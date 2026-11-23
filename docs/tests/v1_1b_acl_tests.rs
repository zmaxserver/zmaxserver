use bytes::Bytes;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio_rustls::TlsConnector;

const HTTP_PORT: u16 = 21050;
const HTTPS_PORT: u16 = 21051;
const API_PORT: u16 = 21052;
const ADMIN_PORT: u16 = 21053;

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

struct ZmaxTestEnv {
    base_dir: PathBuf,
    child: Option<Child>,
}

impl ZmaxTestEnv {
    async fn start() -> Self {
        let unique = format!(
            "zmax_v1_1b_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let base_dir = std::env::temp_dir().join(unique);
        let _ = std::fs::remove_dir_all(&base_dir);

        let conf_dir = base_dir.join("conf");
        let vhosts_dir = conf_dir.join("vhosts");
        let ssl_dir = conf_dir.join("ssl");
        let modules_dir = base_dir.join("modules");
        let admin_dir = base_dir.join("admin");
        let logs_dir = base_dir.join("logs");

        std::fs::create_dir_all(&vhosts_dir).unwrap();
        std::fs::create_dir_all(&ssl_dir).unwrap();
        std::fs::create_dir_all(&modules_dir).unwrap();
        std::fs::create_dir_all(&admin_dir).unwrap();
        std::fs::create_dir_all(&logs_dir).unwrap();
        std::fs::create_dir_all(base_dir.join("www").join("html")).unwrap();
        std::fs::write(admin_dir.join("index.html"), "ADMIN_OK").unwrap();

        let domains = [
            "acl-deny.test",
            "acl-deny-cidr.test",
            "acl-allow.test",
            "acl-strict.test",
            "acl-merged-deny.test",
            "acl-merged-reverse.test",
            "parity-sec.test",
            "*.parity-sec.test",
        ];
        let ck = rcgen::generate_simple_self_signed(
            domains.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        std::fs::write(ssl_dir.join("test.pem"), ck.cert.pem()).unwrap();
        std::fs::write(ssl_dir.join("test.key"), ck.signing_key.serialize_pem()).unwrap();

        let zmax_toml = format!(
            r#"
[listeners.http]
enabled = true
address = "127.0.0.1"
port = {HTTP_PORT}

[listeners.https]
enabled = true
address = "127.0.0.1"
port = {HTTPS_PORT}
ssl = true

[listeners.api]
enabled = true
address = "127.0.0.1"
port = {API_PORT}

[listeners.admin]
enabled = true
address = "127.0.0.1"
port = {ADMIN_PORT}
document_root = "admin"

[cache]
enabled = false

[security]
rate_limit_enabled = false
"#
        );
        std::fs::write(conf_dir.join("zmax.toml"), zmax_toml).unwrap();

        std::fs::write(
            modules_dir.join("mod_security.toml"),
            "[module]\nname = \"mod_security\"\nenabled = true\n\n[settings]\nsql_injection_inspection = true\npath_traversal_shield = true\n",
        )
        .unwrap();
        std::fs::write(
            modules_dir.join("mod_coreruleset.toml"),
            "[module]\nname = \"mod_coreruleset\"\nenabled = true\n\n[settings]\nblock_sql_injection = true\n",
        )
        .unwrap();

        write_vhost(
            &base_dir,
            &vhosts_dir,
            "01-acl-deny",
            "acl-deny.test",
            &[],
            "www/acl-deny",
            "ACL_DENY_BODY",
            r#"
[vhost.acl]
deny_ips = ["127.0.0.1"]
"#,
        );

        write_vhost(
            &base_dir,
            &vhosts_dir,
            "02-acl-deny-cidr",
            "acl-deny-cidr.test",
            &[],
            "www/acl-deny-cidr",
            "ACL_DENY_CIDR_BODY",
            r#"
[vhost.acl]
deny_ips = ["127.0.0.0/8"]
"#,
        );

        write_vhost(
            &base_dir,
            &vhosts_dir,
            "03-acl-allow",
            "acl-allow.test",
            &[],
            "www/acl-allow",
            "ACL_ALLOW_OK",
            r#"
[vhost.acl]
allow_ips = ["127.0.0.1"]
deny_ips = ["127.0.0.0/8"]
"#,
        );

        write_vhost(
            &base_dir,
            &vhosts_dir,
            "04-acl-strict",
            "acl-strict.test",
            &[],
            "www/acl-strict",
            "ACL_STRICT_BODY",
            r#"
[vhost.acl]
allow_ips = ["10.99.99.99"]
"#,
        );

        write_vhost(
            &base_dir,
            &vhosts_dir,
            "05-acl-merged-deny",
            "acl-merged-deny.test",
            &[],
            "www/acl-merged-deny",
            "ACL_MERGED_DENY_BODY",
            r#"
[vhost.security]
deny_ips = ["127.0.0.1"]

[vhost.acl]
deny_ips = ["10.10.0.0/16"]
"#,
        );

        write_vhost(
            &base_dir,
            &vhosts_dir,
            "06-acl-merged-reverse",
            "acl-merged-reverse.test",
            &[],
            "www/acl-merged-reverse",
            "ACL_MERGED_REVERSE_OK",
            r#"
[vhost.security]
allow_ips = ["127.0.0.1"]

[vhost.acl]
deny_ips = ["127.0.0.0/8"]
"#,
        );

        write_vhost(
            &base_dir,
            &vhosts_dir,
            "07-parity-sec",
            "parity-sec.test",
            &["sub.parity-sec.test"],
            "www/parity-sec",
            "PARITY_HTML_OK",
            r#"
[vhost.security]
force_https = true
waf_enabled = true

[vhost.acl]
allow_ips = ["127.0.0.1", "10.0.0.0/8"]
deny_ips = ["172.16.0.0/16"]

[vhost.hotlink]
enabled = true
allowed_referers = ["parity-sec.test", "*.parity-sec.test"]
extensions = ["png", "jpg"]
"#,
        );
        let parity_root = base_dir.join("www").join("parity-sec");
        std::fs::write(parity_root.join("sayfa.html"), "PARITY_HTML_OK").unwrap();
        std::fs::write(parity_root.join("resim.png"), "PARITY_PNG_OK").unwrap();

        let bin = env!("CARGO_BIN_EXE_zmax");
        let mut child = Command::new(bin)
            .env("ZMAX_HOME", &base_dir)
            .env("ZMAX_HTTP_PORT", HTTP_PORT.to_string())
            .env("ZMAX_HTTPS_PORT", HTTPS_PORT.to_string())
            .env("ZMAX_API_PORT", API_PORT.to_string())
            .env("ZMAX_ADMIN_PORT", ADMIN_PORT.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("zmax ikilisi baslatilamadi");

        let stdout = child.stdout.take().expect("stdout pipe alinmadi");
        let stderr = child.stderr.take().expect("stderr pipe alinmadi");

        let stderr_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut buf = String::new();
            let _ = reader.read_to_string(&mut buf).await;
            buf
        });

        let mut lines = BufReader::new(stdout).lines();
        let ready = tokio::time::timeout(Duration::from_secs(15), async {
            let mut captured = Vec::new();
            while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
                let is_ready = line.contains("hazir!");
                captured.push(line);
                if is_ready {
                    return Ok::<(), String>(());
                }
            }
            Err(format!(
                "zmax hazir olmadan sonlandi:\n{}",
                captured.join("\n")
            ))
        })
        .await;

        match ready {
            Ok(Ok(())) => {
                tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
            }
            Ok(Err(msg)) => {
                let err_out = stderr_task.await.unwrap_or_default();
                let _ = child.kill().await;
                let _ = std::fs::remove_dir_all(&base_dir);
                panic!("{msg}\nstderr:\n{err_out}");
            }
            Err(_) => {
                let _ = child.kill().await;
                let err_out = stderr_task.await.unwrap_or_default();
                let _ = std::fs::remove_dir_all(&base_dir);
                panic!("zmax 15sn icinde hazir olmadi\nstderr:\n{err_out}");
            }
        }

        Self {
            base_dir,
            child: Some(child),
        }
    }

    async fn shutdown(mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        let _ = std::fs::remove_dir_all(&self.base_dir);
    }
}

impl Drop for ZmaxTestEnv {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
        let _ = std::fs::remove_dir_all(&self.base_dir);
    }
}

fn write_vhost(
    base_dir: &Path,
    vhosts_dir: &Path,
    file_stem: &str,
    domain: &str,
    aliases: &[&str],
    doc_root_rel: &str,
    index_body: &str,
    extra_toml: &str,
) {
    let doc_root = base_dir.join(doc_root_rel);
    std::fs::create_dir_all(&doc_root).unwrap();
    std::fs::write(doc_root.join("index.html"), index_body).unwrap();

    let aliases_line = if aliases.is_empty() {
        String::new()
    } else {
        let items: Vec<String> = aliases.iter().map(|a| format!("\"{a}\"")).collect();
        format!("aliases = [{}]\n", items.join(", "))
    };

    let content = format!(
        r#"[vhost]
name = "{domain}"
{aliases_line}document_root = "{doc_root_rel}"

[vhost.php]
enabled = false

[vhost.ssl]
certificate = "conf/ssl/test.pem"
key = "conf/ssl/test.key"

{extra_toml}
"#
    );
    std::fs::write(vhosts_dir.join(format!("{file_stem}.toml")), content).unwrap();
}

struct HttpResp {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

fn parse_http1_raw(raw: &[u8]) -> HttpResp {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("HTTP yanitinda baslik sonu bulunamadi");
    let head = String::from_utf8_lossy(&raw[..sep]);
    let body = String::from_utf8_lossy(&raw[sep + 4..]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("HTTP durum satiri eksik");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("HTTP durum kodu eksik")
        .parse()
        .expect("HTTP durum kodu sayi degil");
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    HttpResp {
        status,
        headers,
        body,
    }
}

async fn send_http1_plain(
    host: &str,
    path_and_query: &str,
    extra_headers: &[(&str, &str)],
) -> HttpResp {
    let fut = async {
        let mut stream = TcpStream::connect(("127.0.0.1", HTTP_PORT))
            .await
            .expect("HTTP baglantisi kurulamadi");
        let mut req = format!("GET {path_and_query} HTTP/1.1\r\nHost: {host}\r\n");
        for (k, v) in extra_headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = Vec::new();
        match stream.read_to_end(&mut buf).await {
            Ok(_) => {}
            Err(e) if !buf.is_empty() => {
                panic!("HTTP/1.1 okuma hatasi (alinan {} bayt): {e}", buf.len());
            }
            Err(e) => panic!("HTTP/1.1 okuma hatasi: {e}"),
        }
        parse_http1_raw(&buf)
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .unwrap_or_else(|_| panic!("HTTP/1.1 zaman asimi: host={host} path={path_and_query}"))
}

fn build_tls_connector(alpn: Vec<Vec<u8>>) -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn;
    TlsConnector::from(Arc::new(cfg))
}

async fn send_https_http1(
    host: &str,
    path_and_query: &str,
    extra_headers: &[(&str, &str)],
) -> HttpResp {
    let fut = async {
        let tcp = TcpStream::connect(("127.0.0.1", HTTPS_PORT))
            .await
            .expect("HTTPS HTTP/1.1 baglantisi kurulamadi");
        let connector = build_tls_connector(vec![b"http/1.1".to_vec()]);
        let sni = ServerName::try_from(host.to_string()).unwrap();
        let mut tls = connector
            .connect(sni, tcp)
            .await
            .expect("TLS el sikisma hatasi");
        assert_eq!(
            tls.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_slice())
        );

        let mut req = format!("GET {path_and_query} HTTP/1.1\r\nHost: {host}\r\n");
        for (k, v) in extra_headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Connection: close\r\n\r\n");
        tls.write_all(req.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = Vec::new();
        match tls.read_to_end(&mut buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => {}
            Err(e) => panic!("HTTPS HTTP/1.1 okuma hatasi: {e}"),
        }
        parse_http1_raw(&buf)
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .unwrap_or_else(|_| panic!("HTTPS HTTP/1.1 zaman asimi: host={host} path={path_and_query}"))
}

async fn send_https_h2(
    host: &str,
    path_and_query: &str,
    extra_headers: &[(&str, &str)],
) -> HttpResp {
    let fut = async {
        let tcp = TcpStream::connect(("127.0.0.1", HTTPS_PORT))
            .await
            .expect("HTTPS HTTP/2 baglantisi kurulamadi");
        let connector = build_tls_connector(vec![b"h2".to_vec()]);
        let sni = ServerName::try_from(host.to_string()).unwrap();
        let tls = connector
            .connect(sni, tcp)
            .await
            .expect("TLS H2 el sikisma hatasi");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

        let (mut client, conn) = h2::client::handshake(tls)
            .await
            .expect("H2 handshake hatasi");
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        let uri = format!("https://{host}{path_and_query}");
        let mut builder = http::Request::builder().method("GET").uri(uri);
        for (k, v) in extra_headers {
            builder = builder.header(*k, *v);
        }
        let req = builder.body(()).unwrap();
        let (resp_fut, _) = client.send_request(req, true).unwrap();
        let resp = resp_fut.await.unwrap();
        let status = resp.status().as_u16();
        let mut headers = HashMap::new();
        for (k, v) in resp.headers() {
            headers.insert(
                k.as_str().to_ascii_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            );
        }
        let mut body_stream = resp.into_body();
        let mut body_bytes = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            let b: Bytes = chunk.unwrap();
            body_bytes.extend_from_slice(&b);
            let _ = body_stream.flow_control().release_capacity(b.len());
        }
        drop(client);
        conn_task.abort();

        HttpResp {
            status,
            headers,
            body: String::from_utf8_lossy(&body_bytes).into_owned(),
        }
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .unwrap_or_else(|_| panic!("HTTPS HTTP/2 zaman asimi: host={host} path={path_and_query}"))
}

#[tokio::test]
async fn v1_1b_http1_acl_and_security_pipeline_parity() {
    let env = ZmaxTestEnv::start().await;

    // 1. [vhost.acl] HTTP/1.1 tekil IP deny -> 403, HTTP/2 -> 403
    let r_h1_deny = send_http1_plain("acl-deny.test", "/", &[]).await;
    assert_eq!(
        r_h1_deny.status, 403,
        "HTTP/1.1 [acl] deny 403 olmali: {}",
        r_h1_deny.body
    );
    assert!(
        r_h1_deny.body.contains("IP Access Denied"),
        "{}",
        r_h1_deny.body
    );

    let r_tls_h1_deny = send_https_http1("acl-deny.test", "/", &[]).await;
    assert_eq!(
        r_tls_h1_deny.status, 403,
        "HTTPS HTTP/1.1 [acl] deny 403 olmali"
    );
    assert!(r_tls_h1_deny.body.contains("IP Access Denied"));

    let r_h2_deny = send_https_h2("acl-deny.test", "/", &[]).await;
    assert_eq!(r_h2_deny.status, 403, "HTTP/2 [acl] deny 403 olmali");
    assert!(r_h2_deny.body.contains("IP Access Denied"));

    // 2. [vhost.acl] HTTP/1.1 CIDR deny (127.0.0.0/8) -> 403, HTTP/2 -> 403
    let r_h1_cidr = send_http1_plain("acl-deny-cidr.test", "/", &[]).await;
    assert_eq!(r_h1_cidr.status, 403);
    assert!(r_h1_cidr.body.contains("IP Access Denied"));

    let r_h2_cidr = send_https_h2("acl-deny-cidr.test", "/", &[]).await;
    assert_eq!(r_h2_cidr.status, 403);
    assert!(r_h2_cidr.body.contains("IP Access Denied"));

    // 3. [vhost.acl] HTTP/1.1 allow (127.0.0.1) deny CIDR'i (127.0.0.0/8) ezer -> 200, HTTP/2 -> 200
    let r_h1_allow = send_http1_plain("acl-allow.test", "/", &[]).await;
    assert_eq!(
        r_h1_allow.status, 200,
        "HTTP/1.1 [acl] allow 200 olmali: {}",
        r_h1_allow.body
    );
    assert_eq!(r_h1_allow.body, "ACL_ALLOW_OK");

    let r_tls_h1_allow = send_https_http1("acl-allow.test", "/", &[]).await;
    assert_eq!(r_tls_h1_allow.status, 200);
    assert_eq!(r_tls_h1_allow.body, "ACL_ALLOW_OK");

    let r_h2_allow = send_https_h2("acl-allow.test", "/", &[]).await;
    assert_eq!(r_h2_allow.status, 200);
    assert_eq!(r_h2_allow.body, "ACL_ALLOW_OK");

    // 4. [vhost.acl] Siki beyaz liste: yalnizca baska IP izinli -> 127.0.0.1 HTTP/1.1 ve HTTP/2 403
    let r_h1_strict = send_http1_plain("acl-strict.test", "/", &[]).await;
    assert_eq!(r_h1_strict.status, 403);
    assert!(r_h1_strict.body.contains("IP Access Denied"));

    let r_h2_strict = send_https_h2("acl-strict.test", "/", &[]).await;
    assert_eq!(r_h2_strict.status, 403);
    assert!(r_h2_strict.body.contains("IP Access Denied"));

    // 5. [vhost.security] + [vhost.acl] birlestirme (security.deny=127.0.0.1, acl.deny=10.10.0.0/16) -> 403
    let r_h1_merged_deny = send_http1_plain("acl-merged-deny.test", "/", &[]).await;
    assert_eq!(
        r_h1_merged_deny.status, 403,
        "Birlestirilen security.deny HTTP/1.1'de engellenmeli"
    );
    assert!(r_h1_merged_deny.body.contains("IP Access Denied"));

    let r_h2_merged_deny = send_https_h2("acl-merged-deny.test", "/", &[]).await;
    assert_eq!(
        r_h2_merged_deny.status, 403,
        "Birlestirilen security.deny HTTP/2'de engellenmeli"
    );
    assert!(r_h2_merged_deny.body.contains("IP Access Denied"));

    // 6. [vhost.security] allow_ips (127.0.0.1) + [vhost.acl] deny_ips (127.0.0.0/8) -> 200 (ters yonlu birlestirme)
    let r_h1_merged_rev = send_http1_plain("acl-merged-reverse.test", "/", &[]).await;
    assert_eq!(
        r_h1_merged_rev.status, 200,
        "security.allow acl.deny CIDR'ini ezmeli: {}",
        r_h1_merged_rev.body
    );
    assert_eq!(r_h1_merged_rev.body, "ACL_MERGED_REVERSE_OK");

    let r_h2_merged_rev = send_https_h2("acl-merged-reverse.test", "/", &[]).await;
    assert_eq!(r_h2_merged_rev.status, 200);
    assert_eq!(r_h2_merged_rev.body, "ACL_MERGED_REVERSE_OK");

    // 7. HTTP/1.1 + HTTP/2 tam guvenlik denkligi (force_https, Hotlink, WAF SQLi, Normal 200)
    let r_h1_redirect = send_http1_plain("parity-sec.test", "/sayfa.html", &[]).await;
    assert_eq!(r_h1_redirect.status, 301, "HTTP force_https 301 olmali");
    assert_eq!(
        r_h1_redirect.headers.get("location").map(String::as_str),
        Some("https://parity-sec.test:21051/sayfa.html")
    );

    // Normal istek: HTTPS HTTP/1.1 == HTTP/2 -> 200
    let p_h1_ok = send_https_http1("parity-sec.test", "/sayfa.html", &[]).await;
    let p_h2_ok = send_https_h2("parity-sec.test", "/sayfa.html", &[]).await;
    assert_eq!(p_h1_ok.status, 200);
    assert_eq!(p_h2_ok.status, 200);
    assert_eq!(p_h1_ok.body, "PARITY_HTML_OK");
    assert_eq!(p_h2_ok.body, "PARITY_HTML_OK");

    // Hotlink yabanci referer -> her ikisinde 403
    let hl_h1_block = send_https_http1(
        "parity-sec.test",
        "/resim.png",
        &[("Referer", "http://saldirgan.example/sayfa.html")],
    )
    .await;
    let hl_h2_block = send_https_h2(
        "parity-sec.test",
        "/resim.png",
        &[("referer", "http://saldirgan.example/sayfa.html")],
    )
    .await;
    assert_eq!(hl_h1_block.status, 403);
    assert_eq!(hl_h2_block.status, 403);
    assert!(hl_h1_block.body.contains("Hotlink Protection"));
    assert!(hl_h2_block.body.contains("Hotlink Protection"));

    // Hotlink bos referer & joker izinli referer -> her ikisinde 200
    let hl_h1_empty = send_https_http1("parity-sec.test", "/resim.png", &[]).await;
    let hl_h2_empty = send_https_h2("parity-sec.test", "/resim.png", &[]).await;
    assert_eq!(hl_h1_empty.status, 200);
    assert_eq!(hl_h2_empty.status, 200);

    let hl_h1_wild = send_https_http1(
        "parity-sec.test",
        "/resim.png",
        &[("Referer", "https://cdn.parity-sec.test/galeri")],
    )
    .await;
    let hl_h2_wild = send_https_h2(
        "parity-sec.test",
        "/resim.png",
        &[("referer", "https://cdn.parity-sec.test/galeri")],
    )
    .await;
    assert_eq!(hl_h1_wild.status, 200);
    assert_eq!(hl_h2_wild.status, 200);

    // WAF SQLi engeli -> her ikisinde 403 (WAF Blocked)
    let waf_h1 = send_https_http1("parity-sec.test", "/sayfa.html?q=union+select+1", &[]).await;
    let waf_h2 = send_https_h2("parity-sec.test", "/sayfa.html?q=union+select+1", &[]).await;
    assert_eq!(waf_h1.status, 403);
    assert_eq!(waf_h2.status, 403);
    assert!(waf_h1.body.contains("WAF Blocked"));
    assert!(waf_h2.body.contains("WAF Blocked"));

    env.shutdown().await;
}
