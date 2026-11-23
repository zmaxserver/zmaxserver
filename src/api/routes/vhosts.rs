use super::super::*;

pub(super) async fn vhosts_all<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let clean_path = req_path.split('?').next().unwrap_or(req_path).trim_end_matches('/');
    if clean_path.contains("/context") || clean_path.contains("/contexts") {
        return Ok(false);
    }

    if clean_path == "/api/v1/vhosts" || clean_path == "/api/vhosts" {
        if req.method == "GET" || req.method == "HEAD" {
            let rt = state.runtime.read().await;
            let items: Vec<String> = rt.vhosts.iter().map(format_vhost_json).collect();
            let json = format!(
                r#"{{"ok":true,"count":{},"vhosts":[{}]}}"#,
                items.len(),
                items.join(",")
            );
            send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            return Ok(true);
        } else if req.method != "POST" {
            let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
            send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
            return Ok(true);
        }
    }

    // 11. Yeni Sanal Konak Oluşturma / Güncelleme (POST /api/v1/vhosts veya PUT /api/v1/vhosts/<domain>)
    if (clean_path == "/api/v1/vhosts" && req.method == "POST")
        || (clean_path.starts_with("/api/v1/vhosts/")
            && !clean_path.contains("/context")
            && (req.method == "PUT" || req.method == "POST"))
        || (clean_path.starts_with("/api/vhosts/")
            && !clean_path.contains("/context")
            && (req.method == "PUT" || req.method == "POST"))
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let raw_domain = clean_path
            .strip_prefix("/api/v1/vhosts/")
            .or_else(|| clean_path.strip_prefix("/api/vhosts/"))
            .map(|s| s.trim_matches('/').to_string())
            .or_else(|| extract_json_string(&body_str, "domain"))
            .or_else(|| extract_json_string(&body_str, "name"))
            .unwrap_or_default();

        let domain = match validate_domain(&raw_domain) {
            Ok(d) => d,
            Err(msg) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        let (existing_opt, vhosts_dir) = {
            let rt = state.runtime.read().await;
            (
                rt.vhosts
                    .iter()
                    .find(|v| v.entry.name.eq_ignore_ascii_case(&domain))
                    .map(|v| v.entry.clone()),
                rt.vhosts_dir.clone(),
            )
        };

        let mut base_entry = existing_opt.unwrap_or_else(|| VHostEntry {
            name: domain.clone(),
            document_root: format!("www/{}", domain),
            ..VHostEntry::default()
        });

        if let Some(doc_root) = extract_json_string(&body_str, "document_root") {
            if doc_root.contains("..") || doc_root.contains('\0') || doc_root.trim().is_empty() {
                let err = r#"{"ok":false,"error":"Gecersiz document_root yolu"}"#;
                send_json_response(socket, 400, "Bad Request", &cors_origin, err).await?;
                return Ok(true);
            }
            base_entry.document_root = doc_root;
        }

        let entry = match merge_vhost_json_patch(&base_entry, &domain, &req.body) {
            Ok(e) => e,
            Err(e) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        match write_vhost_atomic_with_rollback(&vhosts_dir, &domain, &entry, state).await {
            Ok(count) => {
                super::super::audit::kayit(state, "api", "vhost-kaydet", &domain, true).await;
                let json = format!(
                    r#"{{"ok":true,"status":"saved","domain":"{}","vhosts_loaded":{}}}"#,
                    json_escape(&domain),
                    count
                );
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            }
            Err(e) => {
                super::super::audit::kayit(state, "api", "vhost-kaydet", &domain, false).await;
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
            }
        }
        return Ok(true);
    }

    // 12. Tekil Sanal Konak Okuma veya Silme (GET / DELETE /api/v1/vhosts/<domain>)
    if let Some(raw_domain) = clean_path.strip_prefix("/api/v1/vhosts/").or_else(|| clean_path.strip_prefix("/api/vhosts/")) {
        let raw_domain = raw_domain.trim_matches('/');
        if raw_domain.contains('/') {
            return Ok(false);
        }
        let domain = match validate_domain(raw_domain) {
            Ok(d) => d,
            Err(msg) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                return Ok(true);
            }
        };

        if req.method == "GET" {
            let rt = state.runtime.read().await;
            if let Some(found) = rt
                .vhosts
                .iter()
                .find(|v| v.entry.name.eq_ignore_ascii_case(&domain))
            {
                let json = format!(r#"{{"ok":true,"vhost":{}}}"#, format_vhost_json(found));
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            } else {
                let err = r#"{"ok":false,"error":"Sanal konak bulunamadi"}"#;
                send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
            }
            return Ok(true);
        }

        if req.method == "DELETE" {
            let vhosts_dir = state.runtime.read().await.vhosts_dir.clone();
            let target = vhosts_dir.join(format!("{}.toml", domain));
            if !target.exists() {
                let err = r#"{"ok":false,"error":"Silinecek sanal konak dosyasi bulunamadi"}"#;
                send_json_response(socket, 404, "Not Found", &cors_origin, err).await?;
                return Ok(true);
            }
            if let Err(e) = tokio::fs::remove_file(&target).await {
                super::super::audit::kayit(state, "api", "vhost-sil", &domain, false).await;
                let err = format!(
                    r#"{{"ok":false,"error":"Dosya silinemedi: {}"}}"#,
                    json_escape(&e.to_string())
                );
                send_json_response(socket, 500, "Internal Server Error", &cors_origin, &err)
                    .await?;
                return Ok(true);
            }
            super::super::audit::kayit(state, "api", "vhost-sil", &domain, true).await;
            let count = reload_runtime_state(state).await.unwrap_or(0);
            let json = format!(
                r#"{{"ok":true,"status":"deleted","domain":"{}","vhosts_loaded":{}}}"#,
                json_escape(&domain),
                count
            );
            send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            return Ok(true);
        }
    }

    Ok(false)
}

pub(crate) async fn handle<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if vhost_context_endpoint(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if vhosts_all(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    Ok(false)
}

pub(super) async fn vhost_context_endpoint<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let clean_path = req_path.split('?').next().unwrap_or(req_path).trim_end_matches('/');
    let Some(after_vhosts) = clean_path.strip_prefix("/api/v1/vhosts/")
        .or_else(|| clean_path.strip_prefix("/api/vhosts/")) else {
        return Ok(false);
    };

    let parts: Vec<&str> = after_vhosts.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() < 2 || (parts[1] != "context" && parts[1] != "contexts") {
        return Ok(false);
    }

    if !matches!(req.method.as_str(), "GET" | "POST" | "HEAD" | "PUT" | "DELETE") {
        let err = r#"{"ok":false,"error":"Yonteme izin verilmiyor (Method Not Allowed)"}"#;
        send_json_response(socket, 405, "Method Not Allowed", cors_origin, err).await?;
        return Ok(true);
    }

    let raw_domain = parts[0];
    let sub_uri = if parts.len() > 2 {
        format!("/{}", parts[2..].join("/"))
    } else {
        String::new()
    };

    let domain = match validate_domain(raw_domain) {
        Ok(d) => d,
        Err(msg) => {
            let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(msg));
            send_json_response(socket, 400, "Bad Request", cors_origin, &err).await?;
            return Ok(true);
        }
    };

    let (existing_opt, vhosts_dir) = {
        let rt = state.runtime.read().await;
        (
            rt.vhosts
                .iter()
                .find(|v| v.entry.name.eq_ignore_ascii_case(&domain))
                .map(|v| v.entry.clone()),
            rt.vhosts_dir.clone(),
        )
    };

    let mut entry = if let Some(e) = existing_opt {
        e
    } else {
        let target_file = vhosts_dir.join(format!("{}.toml", domain));
        if target_file.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&target_file).await {
                if let Ok(doc) = toml::from_str::<zmax_config::VHostFileDocument>(&content) {
                    doc.vhost
                } else {
                    let mut b = VHostEntry::default();
                    b.name = domain.clone();
                    b.document_root = format!("www/{}", domain);
                    b
                }
            } else {
                let mut b = VHostEntry::default();
                b.name = domain.clone();
                b.document_root = format!("www/{}", domain);
                b
            }
        } else if req.method == "POST" || req.method == "PUT" {
            let mut b = VHostEntry::default();
            b.name = domain.clone();
            b.document_root = format!("www/{}", domain);
            b
        } else {
            let err = r#"{"ok":false,"error":"Sanal konak bulunamadi"}"#;
            send_json_response(socket, 404, "Not Found", cors_origin, err).await?;
            return Ok(true);
        }
    };

    if req.method == "GET" || req.method == "HEAD" {
        let contexts_json: Vec<String> = entry.contexts.iter().map(|c| {
            let headers_str = serde_json::to_string(&c.headers).unwrap_or_else(|_| "{}".to_string());
            let allow_str = serde_json::to_string(&c.access_allowed).unwrap_or_else(|_| "[]".to_string());
            let deny_str = serde_json::to_string(&c.access_denied).unwrap_or_else(|_| "[]".to_string());
            let rewrite_str = serde_json::to_string(&c.rewrite_rules).unwrap_or_else(|_| "[]".to_string());
            format!(
                r#"{{"uri":"{}","type":"{}","context_type":"{}","location":"{}","target":"{}","handler":"{}","headers":{},"access_allowed":{},"access_denied":{},"rewrite_rules":{},"enabled":{}}}"#,
                json_escape(&c.uri),
                json_escape(&c.context_type),
                json_escape(&c.context_type),
                json_escape(&c.location),
                json_escape(&c.location),
                json_escape(&c.handler),
                headers_str,
                allow_str,
                deny_str,
                rewrite_str,
                c.enabled
            )
        }).collect();
        let json = format!(
            r#"{{"ok":true,"domain":"{}","count":{},"contexts":[{}]}}"#,
            json_escape(&domain),
            contexts_json.len(),
            contexts_json.join(",")
        );
        send_json_response(socket, 200, "OK", cors_origin, &json).await?;
        return Ok(true);
    }

    if req.method == "POST" || req.method == "PUT" {
        let body_val: serde_json::Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => {
                let err = format!(r#"{{"ok":false,"error":"Gecersiz JSON verisi: {}"}}"#, json_escape(&e.to_string()));
                send_json_response(socket, 400, "Bad Request", cors_origin, &err).await?;
                return Ok(true);
            }
        };

        let items: Vec<&serde_json::Value> = if let Some(arr) = body_val.as_array() {
            arr.iter().collect()
        } else if let Some(arr) = body_val.get("contexts").and_then(|v| v.as_array()) {
            arr.iter().collect()
        } else if let Some(c_obj) = body_val.get("context") {
            if let Some(arr) = c_obj.as_array() {
                arr.iter().collect()
            } else {
                vec![c_obj]
            }
        } else if body_val.is_object() {
            vec![&body_val]
        } else {
            let err = r#"{"ok":false,"error":"Gecersiz context formati"}"#;
            send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
            return Ok(true);
        };

        for item in items {
            let raw_cand = item.get("uri")
                .or_else(|| item.get("location_match"))
                .or_else(|| item.get("path"))
                .and_then(|v| v.as_str())
                .unwrap_or(if !sub_uri.is_empty() { &sub_uri } else { "/" })
                .trim();
            if raw_cand.is_empty() {
                let err = r#"{"ok":false,"error":"Context icin 'uri' alani zorunludur"}"#;
                send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
                return Ok(true);
            }
            let uri_cand = if raw_cand.starts_with('/') {
                raw_cand.to_string()
            } else {
                format!("/{}", raw_cand)
            };

            let c_type = item.get("type")
                .or_else(|| item.get("context_type"))
                .and_then(|v| v.as_str())
                .unwrap_or("Proxy");

            let location = item.get("location")
                .or_else(|| item.get("target"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let handler = item.get("handler")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let enabled = item.get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);

            let mut headers = std::collections::HashMap::new();
            if let Some(h_obj) = item.get("headers").and_then(|v| v.as_object()) {
                for (k, v) in h_obj {
                    if let Some(s) = v.as_str() {
                        headers.insert(k.clone(), s.to_string());
                    }
                }
            }

            let access_allowed: Vec<String> = item.get("access_allowed")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            let access_denied: Vec<String> = item.get("access_denied")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            let rewrite_rules: Vec<String> = item.get("rewrite_rules")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            let target_str = item.get("target")
                .or_else(|| item.get("location"))
                .and_then(|v| v.as_str())
                .unwrap_or(location);
            let redirect_status = item.get("redirect_status")
                .and_then(|v| v.as_u64())
                .unwrap_or(302) as u16;

            let ctx = zmax_config::ContextConfig {
                uri: uri_cand.clone(),
                context_type: c_type.to_string(),
                target: target_str.to_string(),
                location: location.to_string(),
                handler: handler.to_string(),
                headers,
                access_allowed,
                access_denied,
                rewrite_rules,
                redirect_status,
                enabled,
                ..Default::default()
            };

            if let Some(idx) = entry.contexts.iter().position(|c| c.uri == uri_cand) {
                entry.contexts[idx] = ctx;
            } else {
                entry.contexts.push(ctx);
            }
        }

        match write_vhost_atomic_with_rollback(&vhosts_dir, &domain, &entry, state).await {
            Ok(count) => {
                super::super::audit::kayit(state, "api", "vhost-context-kaydet", &domain, true).await;
                let json = format!(
                    r#"{{"ok":true,"status":"saved","domain":"{}","count":{},"vhosts_loaded":{},"message":"Context basariyla kaydedildi."}}"#,
                    json_escape(&domain),
                    entry.contexts.len(),
                    count
                );
                send_json_response(socket, 200, "OK", cors_origin, &json).await?;
            }
            Err(e) => {
                super::super::audit::kayit(state, "api", "vhost-context-kaydet", &domain, false).await;
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 400, "Bad Request", cors_origin, &err).await?;
            }
        }
        return Ok(true);
    }

    if req.method == "DELETE" {
        let raw_target = if !sub_uri.is_empty() {
            sub_uri
        } else {
            let body_str = String::from_utf8_lossy(&req.body);
            extract_json_string(&body_str, "uri").unwrap_or_default()
        };

        if raw_target.is_empty() {
            let err = r#"{"ok":false,"error":"Silinecek context 'uri' alani belirtilmedi"}"#;
            send_json_response(socket, 400, "Bad Request", cors_origin, err).await?;
            return Ok(true);
        }

        let target_uri = if raw_target.starts_with('/') {
            raw_target
        } else {
            format!("/{}", raw_target)
        };

        let initial_len = entry.contexts.len();
        entry.contexts.retain(|c| c.uri != target_uri);
        if entry.contexts.len() == initial_len {
            let err = r#"{"ok":false,"error":"Belirtilen URI ile eslesen context bulunamadi"}"#;
            send_json_response(socket, 404, "Not Found", cors_origin, err).await?;
            return Ok(true);
        }

        match write_vhost_atomic_with_rollback(&vhosts_dir, &domain, &entry, state).await {
            Ok(count) => {
                super::super::audit::kayit(state, "api", "vhost-context-sil", &domain, true).await;
                let json = format!(
                    r#"{{"ok":true,"status":"deleted","domain":"{}","count":{},"vhosts_loaded":{},"message":"Context basariyla silindi."}}"#,
                    json_escape(&domain),
                    entry.contexts.len(),
                    count
                );
                send_json_response(socket, 200, "OK", cors_origin, &json).await?;
            }
            Err(e) => {
                super::super::audit::kayit(state, "api", "vhost-context-sil", &domain, false).await;
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 500, "Internal Server Error", cors_origin, &err).await?;
            }
        }
        return Ok(true);
    }

    Ok(false)
}

