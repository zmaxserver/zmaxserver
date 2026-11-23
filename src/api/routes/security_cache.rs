use super::super::*;

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
    if super::super::services::security_service::bans(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if super::super::services::security_service::unban(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    if super::super::services::cache_service::purge(socket, req, state, req_path, cors_origin).await? {
        return Ok(true);
    }
    Ok(false)
}

