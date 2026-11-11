# ZMAX SERVER
# RUST WEB SERVER – PRODUCTION READINESS & TECHNICAL DEVELOPMENT ROADMAP

**Project:** ZMax Server  
**Component:** Rust Web Server  
**Current Version:** v1.0.01  
**Target Version:** v1.1+  
**Language:** Rust  
**Existing Control Panel:** Go (Implemented, Working and Stable)  
**Primary Objective:** Production-Ready High-Performance Web Server  
**Reference Projects:** Nginx, OpenLiteSpeed, Caddy, Ferron, Cloudflare Pingora

---

# 1. PROJECT SCOPE

This document covers exclusively the Rust-based ZMax Web Server.

The Go-based ZMax hosting control panel is already implemented, operational and stable. It is outside the scope of this development roadmap.

The Rust web server must provide a reliable, secure, resource-efficient and high-performance HTTP delivery infrastructure.

## 1.1 Existing Architecture

The following components are already part of the project:

- `zmax-runtime`
- `zmax-pool`
- `zmax-httpparser`
- `zmax-header`
- `zmax-tls`
- `zmax-static`
- `zmax-fastcgi`
- `zmax-rewrite`
- `zmax-cache`
- `zmax-compress`
- `zmax-security`
- `zmax-proxy`
- `zmax-realip`
- `zmax-timeout`
- `zmax-metrics`
- `zmax-log`
- `zmax-acme`
- `zmax-cli`
- `zmax-redis`
- `zmax-obfuscate`
- `zmax-core`

The development objective is to improve these components, close missing functionality and establish production-grade reliability.

---

# 2. CORE RUNTIME AND WORKER ARCHITECTURE

**Module:** `zmax-runtime`  
**Current Status:** Partial  
**Priority:** P0

The runtime is the foundation of the entire web server.

## 2.1 Existing Functionality

- Tokio asynchronous runtime.
- CPU core detection.
- Worker lifecycle management.
- Graceful shutdown.
- SIGINT / SIGTERM handling.
- SIGHUP configuration reload.
- API-triggered reload.
- Dynamic virtual host configuration.

## 2.2 Missing Functionality

### CPU Affinity

Implement:

- Worker-to-CPU affinity.
- Configurable CPU assignment.
- NUMA-aware worker placement where beneficial.
- CPU affinity monitoring.

Use `core_affinity` where appropriate.

CPU pinning must remain configurable because it does not improve every workload.

### SO_REUSEPORT

Implement optional multi-worker listener architecture.

Requirements:

- Multiple workers accepting connections.
- Shared listening port.
- Worker isolation.
- Fair connection distribution.
- Worker failure recovery.

### Privilege Separation

Implement:

- Privileged startup.
- Socket binding.
- Privilege dropping.
- Dedicated runtime user.
- Restricted filesystem permissions.
- Separation of administrative and request-processing privileges.

### Zero-Downtime Binary Upgrade

Investigate:

- File descriptor inheritance.
- Listener transfer.
- Graceful worker handoff.
- Old worker draining.
- New worker readiness verification.
- Rollback on startup failure.

Target: `SIGUSR2`-style upgrade architecture on supported Unix systems.

Do not terminate the old process until the replacement process is healthy.

---

# 3. CONNECTION AND MEMORY MANAGEMENT

**Module:** `zmax-pool`  
**Current Status:** Partial  
**Priority:** P0

## 3.1 Buffer Pool

Existing functionality:

- BytesMut buffer reuse.
- Large static file buffering.
- Range response streaming.

Additional improvements:

- Configurable buffer sizes.
- Maximum pool capacity.
- Memory pressure handling.
- Buffer allocation metrics.
- Allocation reuse benchmarks.
- Backpressure-aware buffer acquisition.

Avoid unbounded memory pools.

## 3.2 Upstream Connection Pool

Existing reverse proxy upstream socket reuse should be extended.

Implement:

- Maximum idle connections.
- Maximum total connections.
- Per-upstream pool.
- Idle timeout.
- Connection lifetime.
- Connection validation.
- Failed connection eviction.
- Pool exhaustion handling.

## 3.3 FastCGI Connection Pool

Current FastCGI implementation opens a connection per request.

Implement:

- `FCGI_KEEP_CONN`.
- Persistent FastCGI connections.
- Per-upstream connection pools.
- Connection health checks.
- Connection timeout.
- Broken connection recovery.
- Pool limits.
- Request serialization safety.

A FastCGI connection must never be reused while its previous request is still being processed.

---

# 4. HTTP PROTOCOL ENGINE

**Modules:** `zmax-httpparser`, `zmax-http2`, `zmax-quic`  
**Priority:** P0

## 4.1 HTTP/1.1 Hardening

Existing functionality:

- httparse.
- Zero-copy parsing.
- Chunked transfer encoding.
- Keep-Alive.
- Pipelining.
- 413.
- 431.
- 408.

Improve:

- Duplicate header handling.
- Content-Length validation.
- Transfer-Encoding validation.
- Header normalization.
- Invalid request rejection.
- Request body limits.
- Trailer handling.
- Connection state management.
- Parser fuzz testing.

### Request Smuggling Protection

Test and protect against:

- CL.TE.
- TE.CL.
- Duplicate Content-Length.
- Conflicting Transfer-Encoding.
- Invalid chunk framing.
- Obsolete line folding.
- Ambiguous request boundaries.

The parser and reverse proxy must agree on message framing.

## 4.2 HTTP/2

**New Module:** `zmax-http2`  
**Priority:** P0

HTTP/2 is one of the most important missing protocol features.

Implement:

- TLS ALPN negotiation.
- HTTP/2 frames.
- HPACK.
- Multiplexed streams.
- Flow control.
- SETTINGS.
- PING.
- GOAWAY.
- RST_STREAM.
- Concurrent stream limits.
- Header table limits.
- Stream timeout.
- Connection timeout.

Use the mature Rust `h2` ecosystem instead of writing the complete protocol implementation from scratch.

Acceptance criteria:

- HTTP/2 works over TLS.
- Multiple concurrent streams work correctly.
- HTTP/1.1 remains unaffected.
- Flow-control tests pass.
- Browser compatibility is verified.
- ALPN negotiates the correct protocol.

## 4.3 HTTP/3

**New Module:** `zmax-quic`  
**Priority:** P2

Implement:

- QUIC transport.
- HTTP/3.
- QPACK.
- UDP listener.
- Connection migration.
- Stream management.
- QUIC timeout handling.
- Alt-Svc.
- Resource limits.

Suggested ecosystem:

- `quinn`
- `h3`
- `h3-quinn`

HTTP/3 should follow stable HTTP/2 implementation.

---

# 5. TLS ENGINE

**Module:** `zmax-tls`  
**Current Status:** Partial  
**Priority:** P1

Existing functionality:

- Rustls.
- TLS 1.2.
- TLS 1.3.
- Dynamic SNI.
- Certificate reload.
- HTTPS redirection.
- Panel/API TLS listener.

## 5.1 Required Improvements

- ALPN HTTP/2.
- OCSP Stapling.
- Session Resumption.
- Session Ticket Rotation.
- Strict SNI.
- Certificate validation.
- Secure certificate loading.
- TLS handshake timeout.
- Certificate expiration monitoring.
- TLS configuration validation.

## 5.2 TLS Security

Implement:

- Secure cipher configuration.
- TLS version policies.
- Weak cipher rejection.
- Certificate chain validation.
- Private key permission validation.
- Secure ticket key management.

## 5.3 ACME

**Module:** `zmax-acme`  
**Current Status:** Partial  
**Priority:** P1

Implement an integrated ACME client.

Requirements:

- HTTP-01.
- DNS-01.
- TLS-ALPN-01 where supported.
- Automatic renewal.
- Renewal scheduling.
- Renewal retries.
- Certificate deployment.
- Wildcard certificates.
- Multi-domain certificates.
- Certificate expiration notifications.
- Failed renewal recovery.

The existing external Certbot integration should remain supported.

---

# 6. STATIC CONTENT DELIVERY

**Module:** `zmax-static`  
**Current Status:** Partial  
**Priority:** P1

Existing functionality:

- Static file delivery.
- WebP.
- AVIF.
- Accept-based content negotiation.
- Vary: Accept.
- Buffer pooling.
- Range streaming.

## 6.1 Zero-Copy Delivery

Implement Linux:

`sendfile(2)`

Evaluate:

- File descriptor reuse.
- Kernel page cache.
- Efficient file transmission.
- Large file delivery.
- Range request handling.

Compare the implementation against the existing buffered path.

## 6.2 Precompressed Files

Support:

```text
style.css
style.css.br
style.css.gz
style.css.zst
```

Implement:

- Brotli sidecar delivery.
- Gzip sidecar delivery.
- Zstd sidecar delivery.
- Accept-Encoding negotiation.
- Vary: Accept-Encoding.
- Correct Content-Length.
- Correct Content-Encoding.
- Cache variation.

## 6.3 HTTP Cache Headers

Improve:

- ETag.
- Last-Modified.
- If-Modified-Since.
- If-None-Match.
- 304 Not Modified.
- Cache-Control.
- Expires.

## 6.4 Directory Handling

Implement:

- Multiple DirectoryIndex candidates.
- Optional Autoindex.
- Access restrictions.
- Hidden file protection.
- Symlink policies.
- Directory traversal protection.

---

# 7. FASTCGI AND PHP INTEGRATION

**Module:** `zmax-fastcgi`  
**Current Status:** Partial  
**Priority:** P0

Existing functionality:

- Linux Unix Domain Socket.
- TCP FastCGI.
- Windows TCP PHP-CGI.
- PARAMS.
- STDIN.
- Multi-record handling.
- Multiple Set-Cookie.
- PATH_INFO.
- PATH_TRANSLATED.

## 7.1 Persistent Connections

Implement:

- FCGI_KEEP_CONN.
- Persistent socket pool.
- Connection health validation.
- Pool limits.
- Connection recycling.
- Failed connection recovery.

## 7.2 Streaming

Implement:

- Streaming FCGI_STDOUT.
- Response buffering policies.
- Backpressure.
- Client disconnect cancellation.
- Large response handling.

## 7.3 FastCGI Security

Implement:

- HTTPoxy protection.
- Removal of untrusted Proxy environment variables.
- Secure PARAMS generation.
- Environment variable allowlists.
- PATH_INFO validation.
- SCRIPT_FILENAME validation.
- Symlink-aware root resolution.
- Unix socket permission validation.

## 7.4 Internal Redirects

Support:

- X-Accel-Redirect.
- X-Sendfile.
- Internal file delivery.
- Protected internal locations.
- Redirect loop prevention.

These headers must not allow an application to access files outside its authorized document root.

## 7.5 Load Balancing

Implement:

- Multiple FastCGI upstreams.
- Health checks.
- Round Robin.
- Least Connections.
- Connection pooling.
- Timeout policies.

---

# 8. REWRITE AND ROUTING ENGINE

**Module:** `zmax-rewrite`  
**Current Status:** Partial  
**Priority:** P1

Existing functionality:

- Root `.htaccess`.
- RewriteEngine.
- RewriteBase.
- RewriteCond.
- RewriteRule.
- Redirect.
- RedirectMatch.
- DirectoryIndex.
- try_files.
- PHP PATH_INFO integration.

## 8.1 Improvements

- Nested `.htaccess`.
- Subdirectory rewrite rules.
- mtime-based parser cache.
- Rewrite rule execution limits.
- Regex complexity protection.
- Redirect loop detection.
- Internal redirect limits.
- Per-vHost rewrite configuration.

## 8.2 Compatibility

Test with:

- WordPress.
- Laravel.
- OpenCart.
- Drupal.
- Joomla.
- Magento where supported.

Compatibility should be established through real application test suites.

---

# 9. CACHE ENGINE

**Module:** `zmax-cache`  
**Current Status:** Partial  
**Priority:** P1

Existing functionality:

- Moka L1 RAM.
- L2 Disk cache.
- Tag purge.
- Stampede protection.
- Stale-While-Revalidate.

## 9.1 Missing Improvements

- Per-domain cache settings.
- Cache bypass rules.
- Cookie-based bypass.
- Authorization bypass.
- Cache locking.
- Cache size limits.
- Disk cleanup.
- LRU/LFU evaluation.
- Cache metadata validation.
- Cache persistence recovery.
- Cache statistics.

## 9.2 LiteSpeed Cache Compatibility

Implement:

- X-LiteSpeed-Cache-Control.
- X-LiteSpeed-Tag.
- X-LiteSpeed-Purge.
- _lscache_vary.

Test with the LiteSpeed Cache WordPress plugin.

## 9.3 Cache Security

Prevent:

- Cache poisoning.
- Cross-domain cache leakage.
- Private response caching.
- Authentication response caching.
- Cookie leakage.
- Incorrect Vary behavior.

Personalized responses should not be cached unless explicitly and safely configured.

---

# 10. COMPRESSION ENGINE

**Module:** `zmax-compress`  
**Current Status:** Partial  
**Priority:** P1

Existing:

- Gzip.

Missing:

- Brotli.
- Zstd.
- Precompressed response delivery.
- Compression CPU limits.
- Content-type policies.
- Minimum response size.
- Compression metrics.

Suggested defaults:

```toml
[compression]
enabled = true

gzip = true
brotli = true
zstd = true

min_size = 1024

gzip_level = 5
brotli_level = 4
zstd_level = 3
```

The actual algorithm and compression level must be benchmarked.

Avoid compressing already compressed images and media formats unnecessarily.

---

# 11. REVERSE PROXY ENGINE

**Module:** `zmax-proxy`  
**Current Status:** Active / Further Improvements Required  
**Priority:** P1

Existing upstream socket reuse should be extended.

Implement:

- Round Robin.
- Least Connections.
- Weighted Round Robin.
- Active health checks.
- Passive health checks.
- Circuit breaker.
- Retry policies.
- Upstream timeout.
- Request buffering.
- Response buffering.
- Streaming.
- WebSocket.
- Backpressure.
- DNS refresh.
- Upstream connection limits.

## 11.1 Advanced Proxy Features

Evaluate:

- HTTP/2 upstream.
- gRPC proxying.
- TCP proxying.
- Proxy Protocol v1/v2.
- Sticky sessions.
- Upstream TLS verification.
- Custom upstream headers.
- Per-upstream metrics.

Retry requests only when the request semantics and response state make retries safe. Do not automatically replay non-idempotent requests.

---

# 12. DNS RESOLVER

**New Module:** `zmax-dns`  
**Current Status:** Planned  
**Priority:** P1

Implement asynchronous upstream DNS resolution.

Requirements:

- Async DNS.
- Positive caching.
- Negative caching.
- TTL respect.
- Multiple resolvers.
- Timeout handling.
- DNS refresh.
- IPv4.
- IPv6.
- DNS failure recovery.

Suggested ecosystem:

- Hickory DNS.

The resolver must support upstream proxy connections without blocking Tokio workers.

---

# 13. SECURITY ENGINE

**Modules:** `zmax-security`, `zmax-waf`, `zmax-auth`, `zmax-botshield`  
**Current Status:** Partial  
**Priority:** P0

Existing functionality:

- Token Bucket.
- IP rate limiting.
- WordPress auto-ban.
- SQLi detection.
- XSS detection.
- Command injection detection.
- Traversal detection.
- Hotlink protection.
- IP ACL.
- Trusted proxy validation.

## 13.1 WAF Improvements

Implement:

- OWASP CRS compatibility.
- Rule ID management.
- Rule exclusions.
- Anomaly scoring.
- Detection Only.
- Blocking mode.
- Per-vHost rules.
- Audit logging.
- False-positive management.
- Rule update management.

Do not mark OWASP CRS compatibility complete without running the relevant regression suite.

## 13.2 DDoS Protection

Implement:

- Per-IP connection limits.
- Per-domain connection limits.
- Per-IP request limits.
- Burst limits.
- Header timeouts.
- Body timeouts.
- Slowloris protection.
- Suspicious request detection.
- Automatic temporary bans.

For large volumetric attacks, support upstream firewall and network-level mitigation rather than relying exclusively on application-layer controls.

## 13.3 Authentication

**New Module:** `zmax-auth`

Implement:

- HTTP Basic Authentication.
- `.htpasswd` compatibility.
- Argon2id.
- Protected directories.
- Per-vHost authentication.
- Credential rotation.

## 13.4 Bot Protection

**New Module:** `zmax-botshield`

Implement:

- JavaScript challenge.
- Challenge tokens.
- Challenge expiration.
- Suspicious client detection.
- Verified crawler handling.
- CAPTCHA integration where needed.
- Per-domain policies.

---

# 14. RATE LIMITING AND RESOURCE LIMITS

**New Module:** `zmax-limits`  
**Current Status:** Planned  
**Priority:** P0

Current request-based rate limiting should be expanded.

Implement:

- Per-IP connection limits.
- Per-vHost connection limits.
- Per-upstream connection limits.
- Per-request body limits.
- Per-IP bandwidth limits.
- Per-domain bandwidth limits.
- Concurrent request limits.
- Worker memory limits.
- Buffer memory limits.

Example:

```toml
[limits]
max_connections = 10000
max_connections_per_ip = 100
max_connections_per_vhost = 5000

max_request_body = "100M"
max_header_size = "32K"

max_buffer_memory = "512M"
```

All limits must be configurable and safely enforced.

Do not treat bandwidth limits and request-rate limits as equivalent.

---

# 15. LOGGING AND OBSERVABILITY

**Modules:** `zmax-log`, `zmax-metrics`, `zmax-tracing`  
**Current Status:** Partial / Active  
**Priority:** P1

## 15.1 Access Logging

Implement:

- Per-domain access logs.
- Per-domain error logs.
- Custom log formats.
- JSON logging.
- Request ID.
- Configurable log rotation.
- Asynchronous writing.
- Log buffer limits.
- Disk failure handling.

## 15.2 Metrics

Add:

- Requests per second.
- Active connections.
- Requests by status.
- Response time histogram.
- P50.
- P95.
- P99.
- Cache hit ratio.
- Cache miss ratio.
- Upstream latency.
- PHP response latency.
- TLS handshake latency.
- Worker CPU.
- Worker memory.
- Buffer pool utilization.

## 15.3 Distributed Tracing

Implement optional OpenTelemetry integration.

Track:

- Request ID.
- Upstream request.
- FastCGI request.
- Cache operation.
- Response completion.

Never log credentials, session cookies or private authentication headers.

---

# 16. CONFIGURATION MANAGEMENT

**Module:** `zmax-config`  
**Priority:** P0

Configuration reliability is essential.

Implement:

- Configuration schema validation.
- Configuration versioning.
- Atomic file writes.
- Configuration snapshots.
- Last-known-good configuration.
- Safe reload.
- Rollback.
- Syntax validation.
- Dependency validation.
- vHost validation.
- TLS configuration validation.

## 16.1 Safe Reload Procedure

```text
NEW CONFIGURATION
       |
       v
PARSE
       |
       v
VALIDATE
       |
       v
BUILD CONFIG CANDIDATE
       |
       v
CHECK DEPENDENCIES
       |
       v
ATOMIC ACTIVATION
       |
       v
GRACEFUL RELOAD
       |
       v
VERIFY HEALTH
       |
       +---- SUCCESS
       |
       +---- FAILURE -> ROLLBACK
```

A failed reload must never leave the server in an inconsistent state.

---

# 17. ACME AND CERTIFICATE AUTOMATION

**Module:** `zmax-acme`  
**Priority:** P1

Integrate certificate lifecycle management into the Rust server.

Implement:

- Automatic certificate issuance.
- Renewal.
- HTTP-01.
- DNS-01.
- Wildcard certificates.
- Certificate validation.
- Expiration monitoring.
- Certificate reload.
- Renewal failure recovery.

Keep external Certbot compatibility.

---

# 18. CLI AND SERVICE MANAGEMENT

**Module:** `zmax-cli`  
**Current Status:** Partial  
**Priority:** P1

Existing commands:

```bash
zmax -v
zmax -t
zmax -c /path/to/config
```

Add:

```bash
zmax status
zmax reload
zmax stop
zmax start
zmax restart
zmax logs
zmax logs --domain example.com
zmax purge
zmax purge --domain example.com
zmax metrics
zmax config validate
zmax config rollback
zmax upstream status
zmax tls status
```

Requirements:

- Clear exit codes.
- Structured errors.
- Safe administrative permissions.
- Useful diagnostic output.
- Non-interactive operation support.

Linux systemd integration should be fully tested.

---

# 19. WINDOWS SUPPORT

**Priority:** P2

Maintain Windows compatibility where practical.

Implement and test:

- Windows service lifecycle.
- Graceful shutdown.
- TCP FastCGI.
- PHP-CGI.
- Windows Named Pipes.
- File permissions.
- Certificate storage.
- Log rotation.
- Service recovery.

Linux should remain the primary production target until Windows functionality passes its own integration suite.

---

# 20. ADVANCED FEATURES

These features should be considered after the core server is production-ready.

| Module | Feature | Priority |
|---|---|---|
| zmax-quic | HTTP/3 | P2 |
| zmax-pagespeed | HTML/CSS/JS optimization | P2 |
| zmax-appserver | Application runtime supervision | P2 |
| zmax-taskrunner | Background application tasks | P2 |
| zmax-cluster | Multi-process coordination | P2 |
| zmax-observability | OpenTelemetry | P2 |
| zmax-redis | Distributed state synchronization | P2 |
| zmax-proxy | Advanced load balancing | P1 |
| zmax-auth | Basic Auth | P1 |
| zmax-botshield | JavaScript challenge | P2 |

---

# 21. PERFORMANCE BENCHMARKING

**Module:** `zmax-benchmark`  
**Priority:** P0

The server must be compared against established alternatives under identical conditions.

Reference implementations:

- Nginx.
- OpenLiteSpeed.
- Caddy.
- Ferron.
- ZMax Server.

## 21.1 Benchmark Scenarios

| ID | Test |
|---|---|
| B01 | 1 KB static file |
| B02 | 100 KB static file |
| B03 | 1 MB static file |
| B04 | 100 MB static file |
| B05 | Range requests |
| B06 | HTTP/1.1 |
| B07 | HTTP/2 |
| B08 | TLS handshake |
| B09 | PHP-FPM |
| B10 | WordPress |
| B11 | Cache HIT |
| B12 | Cache MISS |
| B13 | Gzip |
| B14 | Brotli |
| B15 | Reverse proxy |
| B16 | WebSocket |
| B17 | High concurrency |
| B18 | Long-duration stability |

## 21.2 Measurements

Collect:

- Requests per second.
- Throughput.
- P50 latency.
- P95 latency.
- P99 latency.
- CPU usage.
- RAM usage.
- Context switches.
- Open file descriptors.
- Error rate.
- Connection failures.

## 21.3 Stress Testing

Run:

- 1-hour stress tests.
- 24-hour soak tests.
- Memory leak tests.
- Worker crash tests.
- Upstream outage tests.
- Configuration reload under load.
- Traffic spike tests.

Use reproducible test environments and preserve raw benchmark results.

---

# 22. SECURITY AND FUZZ TESTING

**Priority:** P0

Required test categories:

## HTTP Parser

- Invalid headers.
- Duplicate headers.
- Malformed requests.
- Chunked encoding.
- Request Smuggling.
- Oversized headers.
- Slowloris.

## FastCGI

- Invalid PARAMS.
- Malformed records.
- HTTPoxy.
- Socket disconnection.
- Upstream timeout.
- Large STDOUT.
- Persistent connection failures.

## TLS

- SNI validation.
- ALPN.
- Expired certificates.
- Invalid certificate chains.
- Session resumption.
- Reload during active traffic.

## Cache

- Cache poisoning.
- Vary handling.
- Concurrent MISS.
- Stampede.
- Cross-domain isolation.
- Cache purge races.

## WAF

- SQLi.
- XSS.
- Command injection.
- Traversal.
- False positives.
- Rule bypasses.

Use:

- Rust unit tests.
- Integration tests.
- cargo-fuzz.
- Property-based testing.
- Regression suites.
- Security scanning.

---

# 23. RECOMMENDED DEVELOPMENT ORDER

This is the proposed order for the Rust web server only.

## v1.0.02 – Runtime and Stability

- Worker lifecycle improvements.
- Buffer pool limits.
- Upstream pool limits.
- FastCGI connection reuse.
- Safe configuration reload.
- Error recovery.
- Resource limits.

## v1.0.03 – HTTP Security

- Request Smuggling hardening.
- Parser fuzzing.
- Header validation.
- FastCGI HTTPoxy protection.
- Secure internal redirects.
- WAF regression tests.

## v1.0.04 – HTTP/2

- HTTP/2 frame processing.
- HPACK.
- ALPN.
- Stream multiplexing.
- Flow control.
- HTTP/2 integration tests.

## v1.0.05 – Static Performance

- Linux sendfile.
- Precompressed files.
- Brotli.
- Zstd.
- ETag improvements.
- Range optimization.

## v1.0.06 – Proxy and FastCGI

- Persistent FastCGI pools.
- Advanced upstream pools.
- Health checks.
- Load balancing.
- Backpressure.
- Streaming.

## v1.0.07 – TLS and ACME

- OCSP Stapling.
- Session Resumption.
- Certificate lifecycle.
- Automatic renewal.
- Strict SNI.

## v1.0.08 – WAF and DDoS

- OWASP CRS compatibility.
- Detection Only mode.
- Blocking mode.
- Per-vHost rules.
- Advanced rate limiting.
- Connection limits.

## v1.0.09 – Observability

- Per-domain logs.
- Request ID.
- Latency histograms.
- Upstream metrics.
- Cache metrics.
- Worker metrics.

## v1.1.00 – Production Release

- Complete regression testing.
- Performance verification.
- Security audit.
- Long-duration stability testing.
- Upgrade testing.
- Rollback testing.
- Production documentation.

## v1.2+ – Advanced Features

- HTTP/3.
- QUIC.
- Pagespeed.
- Application supervisor.
- Multi-process coordination.
- Advanced cluster support.

---

# 24. PRODUCTION READINESS CHECKLIST

A module must have separate implementation, testing and production verification states.

## Runtime

- [ ] Graceful shutdown.
- [ ] Graceful reload.
- [ ] Worker recovery.
- [ ] Memory limits.
- [ ] Connection limits.
- [ ] Long-duration stability.

## HTTP

- [ ] HTTP/1.1.
- [ ] HTTP/2.
- [ ] Request Smuggling protection.
- [ ] Header validation.
- [ ] Range requests.
- [ ] Keep-Alive.

## TLS

- [ ] TLS 1.2.
- [ ] TLS 1.3.
- [ ] SNI.
- [ ] ALPN.
- [ ] OCSP Stapling.
- [ ] Session Resumption.
- [ ] Certificate renewal.

## Static

- [ ] sendfile.
- [ ] WebP.
- [ ] AVIF.
- [ ] Gzip.
- [ ] Brotli.
- [ ] Zstd.
- [ ] Range streaming.
- [ ] Conditional requests.

## FastCGI

- [ ] PHP-FPM.
- [ ] PHP-CGI.
- [ ] Persistent connections.
- [ ] Connection recovery.
- [ ] Streaming.
- [ ] HTTPoxy protection.
- [ ] Internal redirects.

## Proxy

- [ ] Upstream pooling.
- [ ] Health checks.
- [ ] Load balancing.
- [ ] WebSocket.
- [ ] Backpressure.
- [ ] Timeout policies.

## Security

- [ ] WAF.
- [ ] OWASP CRS tests.
- [ ] Rate limiting.
- [ ] IP ACL.
- [ ] Hotlink protection.
- [ ] Basic Auth.
- [ ] Security regression tests.

## Observability

- [ ] Per-domain access logs.
- [ ] Per-domain error logs.
- [ ] Request ID.
- [ ] Prometheus metrics.
- [ ] Latency metrics.
- [ ] Worker metrics.

## Release

- [ ] Clean installation.
- [ ] Upgrade.
- [ ] Rollback.
- [ ] Configuration migration.
- [ ] Systemd.
- [ ] Security audit.
- [ ] Performance benchmark.
- [ ] 24-hour soak test.

---

# 25. FINAL ENGINEERING PRIORITIES

The following order is recommended:

1. Runtime stability and safe configuration reload.
2. Memory and connection pool safety.
3. HTTP parser and request security.
4. FastCGI persistent connections.
5. HTTP/2 and ALPN.
6. Static file delivery optimization.
7. Brotli and Zstd.
8. TLS improvements.
9. Reverse proxy health checks and load balancing.
10. WAF and DDoS improvements.
11. Per-domain logs and metrics.
12. ACME automation.
13. HTTP/3 and QUIC.
14. Advanced application runtime.
15. Cluster and multi-process support.

---

# FINAL OBJECTIVE

The objective of ZMax Server v1.1 is not to maximize the number of modules.

It is to deliver a web server that:

- Handles high concurrency reliably.
- Uses memory efficiently.
- Provides predictable latency.
- Supports modern HTTP protocols.
- Delivers static files efficiently.
- Integrates with PHP-FPM reliably.
- Provides secure reverse proxy functionality.
- Protects against common web attacks.
- Reloads configuration without service interruption.
- Recovers safely from failures.
- Provides detailed metrics and diagnostics.
- Can be operated confidently in production.

**ZMax Server should become a production-grade Rust web server capable of competing with Nginx, OpenLiteSpeed, Caddy and Ferron in measurable performance, reliability, security and compatibility.**

The existing Go hosting control panel remains unchanged in this roadmap.

**Development focus: Rust Web Server only.**