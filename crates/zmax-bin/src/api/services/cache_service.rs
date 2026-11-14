use super::super::*;

pub(crate) async fn purge<S>(
    socket: &mut S,
    req: &ParsedHttpRequest,
    state: &Arc<ServerState>,
    req_path: &str,
    cors_origin: &String,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    if (req_path == "/api/purge" || req_path == "/api/v1/cache/purge") && req.method == "POST" {
        let payload: serde_json::Value = if req.body.iter().all(|b| b.is_ascii_whitespace()) {
            serde_json::json!({})
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(v) => v,
                Err(e) => {
                    let err = serde_json::json!({
                        "ok": false,
                        "error": format!("Gecersiz JSON govdesi: {}", e)
                    })
                    .to_string();
                    send_json_response(socket, 400, "Bad Request", &cors_origin, &err).await?;
                    return Ok(true);
                }
            }
        };

        let domain_opt = payload
            .get("domain")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty());
        let tag_opt = payload
            .get("tag")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let tags_opt = payload
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<String>>()
            })
            .filter(|v| !v.is_empty());
        let uri_opt = payload
            .get("uri")
            .or_else(|| payload.get("key"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let redis_opt = state.runtime.read().await.redis_client.clone();

        let hedef = match (&domain_opt, &tag_opt, &tags_opt, &uri_opt) {
            (Some(d), _, _, _) => d.clone(),
            (None, Some(t), _, _) => format!("tag:{t}"),
            (None, None, Some(_), _) => "tags".to_string(),
            (None, None, None, Some(u)) => format!("uri:{u}"),
            _ => "tum-onbellek".to_string(),
        };
        super::super::audit::kayit(state, "api", "cache-purge", &hedef, true).await;

        match (domain_opt, tag_opt, tags_opt, uri_opt) {
            (Some(domain), Some(tag), _, _) => {
                let purged = state.cache.purge_by_domain_tag(&domain, &tag).await;
                crate::redis::publish_purge_tag(redis_opt.as_ref(), &domain, &tag);
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain_tag",
                    "domain": domain,
                    "tag": tag,
                    "purged": purged,
                    "message": "Secili alan adi ve etiket onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (Some(domain), None, Some(tags), _) => {
                let purged = state.cache.purge_by_tags(&domain, &tags).await;
                crate::redis::publish_purge_tags(redis_opt.as_ref(), &domain, &tags);
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain_tags",
                    "domain": domain,
                    "tags": tags,
                    "purged": purged,
                    "message": "Secili alan adi etiketleri temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, Some(tag), _, _) => {
                let purged = state.cache.purge_by_tag(&tag).await;
                crate::redis::publish_purge_raw_tag(redis_opt.as_ref(), &tag);
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "tag",
                    "tag": tag,
                    "purged": purged,
                    "message": "Secili etiket onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, None, Some(tags), None) => {
                let mut purged = 0;
                for t in &tags {
                    purged += state.cache.purge_by_tag(t).await;
                }
                crate::redis::publish_purge_raw_tags(redis_opt.as_ref(), &tags);
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "tags",
                    "tags": tags,
                    "purged": purged,
                    "message": "Secili etiketler onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (Some(domain), None, None, None) => {
                let purged = state.cache.purge_by_domain(&domain).await;
                crate::redis::publish_purge_domain(redis_opt.as_ref(), &domain);
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain",
                    "domain": domain,
                    "purged": purged,
                    "message": "Secili alan adi onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (Some(domain), None, None, Some(target_uri)) => {
                let purged = state.cache.purge_by_domain_uri(&domain, &target_uri).await;
                crate::redis::publish_purge_domain_uri(redis_opt.as_ref(), &domain, &target_uri);
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "domain_uri",
                    "domain": domain,
                    "uri": target_uri,
                    "purged": purged,
                    "message": "Secili alan adi ve URI onbellegi temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (_, _, _, Some(target_uri)) => {
                let purged = state.cache.purge_by_uri(&target_uri).await;
                crate::redis::publish_purge_uri(redis_opt.as_ref(), &target_uri);
                let json = serde_json::json!({
                    "ok": true,
                    "status": "success",
                    "scope": "uri",
                    "uri": target_uri,
                    "key": target_uri,
                    "purged": purged,
                    "message": "Secili onbellek anahtari veya URI temizlendi."
                })
                .to_string();
                send_json_response(socket, 200, "OK", &cors_origin, &json).await?;
                return Ok(true);
            }
            (None, None, None, None) => {
                state.cache.purge_all().await;
                crate::redis::publish_purge_all(redis_opt.as_ref());
                let json = r#"{"ok":true,"status":"success","scope":"all","message":"L1 & L2 Onbellegi tamamen temizlendi!"}"#;
                send_json_response(socket, 200, "OK", &cors_origin, json).await?;
                return Ok(true);
            }
        }
    }
    Ok(false)
}

