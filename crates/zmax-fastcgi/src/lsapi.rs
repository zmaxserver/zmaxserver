//! LSAPI (LiteSpeed SAPI) istemcisi: `lsphp -b <adres>` sürecine FastCGI yerine LSAPI konuşur.
//! Şartname: php-src `sapi/litespeed/lsapidef.h` + `lsapilib.c`. Yanıt, mevcut işleyicinin
//! beklediği CGI biçimine (`Status: N\r\nBaşlık: değer\r\n\r\ngövde`) çevrilir.

use crate::{FastCgiError, FastCgiRequest, FastCgiResponse};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const PKT_BEGIN_REQUEST: u8 = 1;
const PKT_RESP_HEADER: u8 = 3;
const PKT_RESP_STREAM: u8 = 4;
const PKT_RESP_END: u8 = 5;
const PKT_STDERR_STREAM: u8 = 6;
const PKT_CONN_CLOSE: u8 = 8;
const PKT_INTERNAL_ERROR: u8 = 9;
const PKT_HEADER_LEN: usize = 8;
const MAX_RESP_PACKET: usize = 64 * 1024 * 1024;
const MAX_RESP_TOTAL: usize = 512 * 1024 * 1024;
const REQ_HEADER_LEN: usize = PKT_HEADER_LEN + 9 * 4;
const HEADER_INDEX_COUNT: usize = 25;
/// `H_TRANSFER_ENCODING` dizinde son eleman olduğundan sunucu tarafında bilinmeyen başlık sayılır.
const KNOWN_HEADERS: [&str; 24] = [
    "accept", "accept-charset", "accept-encoding", "accept-language", "authorization", "connection",
    "content-type", "content-length", "cookie", "cookie2", "host", "pragma", "referer", "user-agent",
    "cache-control", "if-modified-since", "if-match", "if-none-match", "if-range",
    "if-unmodified-since", "keep-alive", "range", "x-forwarded-for", "via",
];

fn pkt_header(kind: u8, total_len: usize) -> [u8; PKT_HEADER_LEN] {
    let mut h = [0u8; PKT_HEADER_LEN];
    h[0] = b'L';
    h[1] = b'S';
    h[2] = kind;
    h[3] = 0; // LSAPI_ENDIAN_LITTLE
    h[4..8].copy_from_slice(&(total_len as i32).to_le_bytes());
    h
}

fn push_env(buf: &mut Vec<u8>, key: &str, val: &str) -> usize {
    let k = key.as_bytes();
    let v = val.as_bytes();
    let klen = (k.len() + 1).min(u16::MAX as usize);
    let vlen = (v.len() + 1).min(u16::MAX as usize);
    buf.extend_from_slice(&(klen as u16).to_be_bytes());
    buf.extend_from_slice(&(vlen as u16).to_be_bytes());
    buf.extend_from_slice(&k[..klen - 1]);
    buf.push(0);
    let val_off = buf.len();
    buf.extend_from_slice(&v[..vlen - 1]);
    buf.push(0);
    val_off
}

/// BEGIN_REQUEST paketini (istek başlığı + env + başlık dizini + HTTP başlıkları) ve ardından gövdeyi üretir.
pub fn build_request(req: &FastCgiRequest) -> Vec<u8> {
    let params = req.build_params();
    let mut buf: Vec<u8> = vec![0u8; REQ_HEADER_LEN];
    // Özel env listesi boş: yalnız sonlandırıcı.
    buf.extend_from_slice(&[0, 0, 0, 0]);

    let mut keys: Vec<&String> = params.keys().filter(|k| !k.starts_with("HTTP_")).collect();
    keys.sort();
    let (mut script_file, mut script_name, mut query, mut method) = (0usize, 0usize, 0usize, 0usize);
    let cnt_env = keys.len();
    for k in keys {
        let off = push_env(&mut buf, k, &params[k]);
        match k.as_str() {
            "SCRIPT_FILENAME" => script_file = off,
            "SCRIPT_NAME" => script_name = off,
            "QUERY_STRING" => query = off,
            "REQUEST_METHOD" => method = off,
            _ => {}
        }
    }
    buf.extend_from_slice(&[0, 0, 0, 0]);
    while buf.len() % 8 != 0 {
        buf.push(0);
    }

    // HTTP başlık bloğu: ofset 0 "yok" demektir, bu yüzden bir doldurma baytıyla başlar.
    let mut http: Vec<u8> = vec![0u8];
    let mut idx_len = [0u16; HEADER_INDEX_COUNT];
    let mut idx_off = [0i32; HEADER_INDEX_COUNT];
    let mut unknown: Vec<(i32, i32, i32, i32)> = Vec::new();
    for (name, value) in &req.headers {
        let lname = name.to_ascii_lowercase();
        let v = value.as_bytes();
        let known = KNOWN_HEADERS.iter().position(|h| *h == lname);
        match known {
            Some(i) if idx_off[i] == 0 && v.len() <= u16::MAX as usize => {
                idx_off[i] = http.len() as i32;
                idx_len[i] = v.len() as u16;
                http.extend_from_slice(v);
                http.push(0);
            }
            _ => {
                let n_off = http.len() as i32;
                http.extend_from_slice(name.as_bytes());
                http.push(0);
                let v_off = http.len() as i32;
                http.extend_from_slice(v);
                http.push(0);
                unknown.push((n_off, name.len() as i32, v_off, v.len() as i32));
            }
        }
    }
    for l in idx_len {
        buf.extend_from_slice(&l.to_le_bytes());
    }
    // `uint16[25]` (50 bayt) sonrasında `int32` hizası için 2 bayt doldurma.
    buf.extend_from_slice(&[0, 0]);
    for o in idx_off {
        buf.extend_from_slice(&o.to_le_bytes());
    }
    for (a, b, c, d) in &unknown {
        for x in [a, b, c, d] {
            buf.extend_from_slice(&x.to_le_bytes());
        }
    }
    buf.extend_from_slice(&http);

    let total = buf.len();
    buf[..PKT_HEADER_LEN].copy_from_slice(&pkt_header(PKT_BEGIN_REQUEST, total));
    let mut w = |pos: usize, v: i32| buf[pos..pos + 4].copy_from_slice(&v.to_le_bytes());
    w(8, http.len() as i32); // m_httpHeaderLen
    w(12, req.body.len() as i32); // m_reqBodyLen
    w(16, script_file as i32);
    w(20, script_name as i32);
    w(24, query as i32);
    w(28, method as i32);
    w(32, unknown.len() as i32);
    w(36, cnt_env as i32);
    w(40, 0); // m_cntSpecialEnv
    buf.extend_from_slice(&req.body);
    buf
}

/// Yanıt akışını CGI biçimine çevirir; `(raw_stdout, stderr)` döner.
pub async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<FastCgiResponse, FastCgiError> {
    let mut head: Vec<(String, String)> = Vec::new();
    let mut status: u16 = 200;
    let mut body: Vec<u8> = Vec::new();
    let mut stderr: Vec<u8> = Vec::new();
    let mut got_header = false;
    loop {
        let mut h = [0u8; PKT_HEADER_LEN];
        match stream.read_exact(&mut h).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && got_header => break,
            Err(e) => return Err(FastCgiError::Io(e)),
        }
        if h[0] != b'L' || h[1] != b'S' {
            return Err(FastCgiError::Protocol("LSAPI paket imzasi gecersiz".into()));
        }
        let big = h[3] & 1 == 1;
        let raw = [h[4], h[5], h[6], h[7]];
        let total = if big { i32::from_be_bytes(raw) } else { i32::from_le_bytes(raw) };
        if total < PKT_HEADER_LEN as i32 || total as usize > MAX_RESP_PACKET {
            return Err(FastCgiError::Protocol(format!("LSAPI paket uzunlugu gecersiz: {total}")));
        }
        let mut payload = vec![0u8; total as usize - PKT_HEADER_LEN];
        stream.read_exact(&mut payload).await?;
        match h[2] {
            PKT_RESP_HEADER => {
                if payload.len() < 8 {
                    return Err(FastCgiError::Protocol("LSAPI yanit basligi kisa".into()));
                }
                let cnt = i32::from_le_bytes(payload[0..4].try_into().unwrap()).max(0) as usize;
                status = i32::from_le_bytes(payload[4..8].try_into().unwrap()).clamp(100, 999) as u16;
                let lens_end = 8 + cnt * 2;
                if lens_end > payload.len() {
                    return Err(FastCgiError::Protocol("LSAPI yanit baslik uzunluklari tasti".into()));
                }
                let mut pos = lens_end;
                for i in 0..cnt {
                    let l = i16::from_le_bytes([payload[8 + i * 2], payload[9 + i * 2]]).max(0) as usize;
                    if pos + l > payload.len() {
                        return Err(FastCgiError::Protocol("LSAPI yanit basligi tasti".into()));
                    }
                    let line = &payload[pos..pos + l];
                    pos += l;
                    let line = line.strip_suffix(&[0u8]).unwrap_or(line);
                    if let Some(c) = line.iter().position(|b| *b == b':') {
                        head.push((
                            String::from_utf8_lossy(&line[..c]).trim().to_string(),
                            String::from_utf8_lossy(&line[c + 1..]).trim().to_string(),
                        ));
                    }
                }
                got_header = true;
            }
            PKT_RESP_STREAM => {
                if body.len() + payload.len() > MAX_RESP_TOTAL {
                    return Err(FastCgiError::Protocol("LSAPI yanit govdesi sinirda".into()));
                }
                body.extend_from_slice(&payload);
            }
            PKT_STDERR_STREAM => stderr.extend_from_slice(&payload),
            PKT_RESP_END | PKT_CONN_CLOSE => break,
            PKT_INTERNAL_ERROR => return Err(FastCgiError::Protocol("LSAPI dahili hata".into())),
            _ => {} // REQ_RECEIVED vb.
        }
    }
    if !got_header {
        return Err(FastCgiError::Protocol("LSAPI yanit basligi gelmedi".into()));
    }
    let mut out = format!("Status: {status}\r\n").into_bytes();
    for (k, v) in &head {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&body);
    Ok(FastCgiResponse { raw_stdout: out, stderr })
}

/// Akış üzerinde tek isteği çalıştırır.
pub async fn execute_on_stream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    req: &FastCgiRequest,
) -> Result<FastCgiResponse, FastCgiError> {
    stream.write_all(&build_request(req)).await?;
    stream.flush().await?;
    read_response(&mut stream).await
}

/// `upstream`: `host:port` ya da `unix:/yol.sock` (veya `/yol.sock`). Her istek yeni bağlantıdır.
pub async fn execute_lsapi(
    upstream: &str,
    req: &FastCgiRequest,
    dial_timeout: Duration,
    io_timeout: Duration,
) -> Result<FastCgiResponse, FastCgiError> {
    let trimmed = upstream.trim();
    let fut = async {
        if let Some(path) = trimmed
            .strip_prefix("unix:")
            .or_else(|| if trimmed.starts_with('/') { Some(trimmed) } else { None })
        {
            #[cfg(unix)]
            {
                let s = tokio::time::timeout(dial_timeout, tokio::net::UnixStream::connect(path))
                    .await
                    .map_err(|_| FastCgiError::Timeout("LSAPI baglanti".into()))??;
                return execute_on_stream(s, req).await;
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(FastCgiError::Protocol("LSAPI unix soketi yalniz Unix'te desteklenir".into()));
            }
        }
        let s = tokio::time::timeout(dial_timeout, tokio::net::TcpStream::connect(trimmed))
            .await
            .map_err(|_| FastCgiError::Timeout("LSAPI baglanti".into()))??;
        execute_on_stream(s, req).await
    };
    tokio::time::timeout(io_timeout, fut)
        .await
        .map_err(|_| FastCgiError::Timeout("LSAPI yanit".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn le32(b: &[u8], p: usize) -> i32 {
        i32::from_le_bytes(b[p..p + 4].try_into().unwrap())
    }

    #[test]
    fn istek_paketi_yapisi() {
        let req = FastCgiRequest::new("POST", "/a.php?x=1", "/a.php", "/srv/a.php", "/srv")
            .query_string("x=1")
            .host("ornek.test")
            .header("Cookie", "a=b")
            .header("X-Ozel", "deger")
            .body(b"abc".to_vec());
        let b = build_request(&req);
        assert_eq!(&b[0..2], b"LS");
        assert_eq!(b[2], PKT_BEGIN_REQUEST);
        let body_len = le32(&b, 12);
        assert_eq!(body_len, 3);
        let pkt_total = le32(&b, 4) as usize;
        assert_eq!(&b[pkt_total..], b"abc");
        let off = le32(&b, 16) as usize;
        assert_eq!(&b[off..off + 10], b"/srv/a.php");
        assert_eq!(b[off + 10], 0);
        let moff = le32(&b, 28) as usize;
        assert_eq!(&b[moff..moff + 4], b"POST");
        assert_eq!(le32(&b, 32), 1); // bilinmeyen başlık: X-Ozel
    }

    #[tokio::test]
    async fn yanit_cgi_bicimine_cevrilir() {
        let mut pkts: Vec<u8> = Vec::new();
        let hdr = b"Content-Type:text/plain\0";
        let mut p = Vec::new();
        p.extend_from_slice(&1i32.to_le_bytes());
        p.extend_from_slice(&201i32.to_le_bytes());
        p.extend_from_slice(&(hdr.len() as i16).to_le_bytes());
        p.extend_from_slice(hdr);
        pkts.extend_from_slice(&pkt_header(PKT_RESP_HEADER, 8 + p.len()));
        pkts.extend_from_slice(&p);
        pkts.extend_from_slice(&pkt_header(PKT_RESP_STREAM, 8 + 5));
        pkts.extend_from_slice(b"merha");
        pkts.extend_from_slice(&pkt_header(PKT_RESP_END, 8));
        let mut cur = std::io::Cursor::new(pkts);
        let r = read_response(&mut cur).await.unwrap();
        let s = String::from_utf8(r.raw_stdout).unwrap();
        assert_eq!(s, "Status: 201\r\nContent-Type: text/plain\r\n\r\nmerha");
    }
}
