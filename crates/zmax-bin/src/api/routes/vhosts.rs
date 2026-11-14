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
    if req_path == "/api/v1/vhosts" && req.method == "GET" {
        let rt = state.runtime.read().await;
        let items: Vec<String> = rt.vhosts.iter().map(format_vhost_json).collect();
        let json = format!(
            r#"{{"ok":true,"count":{},"vhosts":[{}]}}"#,
            items.len(),
            items.join(",")
        );
        send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
        return Ok(true);
    }

    // 11. Yeni Sanal Konak Oluşturma / Güncelleme (POST /api/v1/vhosts veya PUT /api/v1/vhosts/<domain>)
    if (req_path == "/api/v1/vhosts" && req.method == "POST")
        || (req_path.starts_with("/api/v1/vhosts/")
            && (req.method == "PUT" || req.method == "POST"))
    {
        let body_str = String::from_utf8_lossy(&req.body);
        let raw_domain = req_path
            .strip_prefix("/api/v1/vhosts/")
            .map(|s| s.to_string())
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
                let json = format!(
                    r#"{{"ok":true,"status":"saved","domain":"{}","vhosts_loaded":{}}}"#,
                    json_escape(&domain),
                    count
                );
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
            }
            Err(e) => {
                let err = format!(r#"{{"ok":false,"error":"{}"}}"#, json_escape(&e));
                send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
            }
        }
        return Ok(true);
    }

    // 12. Tekil Sanal Konak Okuma veya Silme (GET / DELETE /api/v1/vhosts/<domain>)
    if let Some(raw_domain) = req_path.strip_prefix("/api/v1/vhosts/") {
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
                let err = format!(
                    r#"{{"ok":false,"error":"Dosya silinemedi: {}"}}"#,
                    json_escape(&e.to_string())
                );
                send_json_response(socket, 500, "Internal Server Error", &cors_origin, &err)
                    .await?;
                return Ok(true);
            }
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
    if vhosts_all(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    Ok(false)
}

