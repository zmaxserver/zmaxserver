# ZMax — Kart 2 Bitti Raporu

## Kart 2 — Günlükte gerçek bayt, panel/fail2ban uyumu (2026-11-12 ~02:55)

**Okunanlar:** `D:\zmaxserver-ajan\a02\doc\YAPAY_ZEKA_KURALLARI.md` (v5, son okunma: 02:25 / 02:45), `doc/AJAN_YAPISI.md`, `doc/README.md`, `doc/MIMARI_VE_PLAN.md`, `doc/TAM_MODUL_VE_OZELLIK_MATRISI.md`, `doc/ADIMLI_GELISTIRME_TAKIP.md` (Kart 2), `doc/DUZELTMELER.md` (Kart 1 ONAYLI, Kart 2 BEKLİYOR), `doc/entegre/goentegre.md` (§6 Günlük sözleşmesi), `D:\lunixpanel\zpanel-tam\cekirdek\agent\internal\logs\logs.go` (`ParseAccess`), `logs_test.go`, `sites/logs.go`, `crates/zmax-bin/src/logger.rs`, `crates/zmax-bin/src/web_engine.rs`, `crates/zmax-bin/src/h2_engine.rs`, `crates/zmax-bin/src/main.rs`.

**Kural ve düzeltme kontrolü:**
- `YAPAY_ZEKA_KURALLARI.md` (v5) §1–§7 ve §8a öz denetimi uygulandı:
  - Kural 1: Yalnız verilen görev (Kart 2: günlükte gerçek bayt, panel/fail2ban uyumu) yapıldı; yetkisiz alan eklenmedi.
  - Kural 2: Uydurma/tahmin bilgi yazılmadı; test sayıları ve komut çıktıları bizzat çalıştırılarak doğrulandı.
  - Kural 3: Testler gerçek soket, gerçek HTTP/1.1 ve HTTP/2 akışları, cache, proxy ve FastCGI simülasyonları üzerinde çalıştırılarak kanıtlandı.
  - Kural 4: Geriye dönük uyumluluk ve NCSA Combined / Common format standartları korundu.
  - Kural 7: Kart dışı dosyalara (`crates/zmax-config`, `zmax-rewrite`, `zmax-security`, `zmax-proxy`, Go repo vb.) dokunulmadı; yetkili olunan `logger.rs`, `web_engine.rs`, `h2_engine.rs` ve test için `main.rs` üzerinde çalışıldı. `*.bak`, `*.tmp`, `*.orig` artık dosyası bırakılmadı (0 adet).
  - Kural 8a: Yetkisiz "ONAYLANDI/KİLİTLENDİ" ifadeleri kullanılmadı; denetçi bağımsız doğrulamasına sunuldu.
  - Ortak dosya kuralı (`AJAN_YAPISI.md` §2 & §3): `web_engine.rs` içinde yalnızca `record_and_log` / `log_access` ve bayt hesaplama noktalarına cerrahi dokunuş yapıldı; fonksiyon taşıma, yeniden adlandırma veya biçimlendirme yapılmadı. `h2_engine.rs` içinde akış sonu gövde baytı ve hata günlükleri eklendi.

**Yapılan iş:**
1. `crates/zmax-bin/src/web_engine.rs`:
   - `record_and_log`: `is_zero_body = bytes_sent == 0 || status == 304 || status == 204 || method.eq_ignore_ascii_case("HEAD")`. `bytes_str` '-' ve `actual_bytes = 0` garantisi sağlandı.
   - `write_error_response`: HEAD / 204 / 304 durumunda `written = 0`, GET durumunda gerçek hata gövdesi uzunluğu döndürüldü.
   - `serve_static_file`: Range HEAD ve tam dosya HEAD isteklerinde `return Ok((..., 0))` ile 0 gövde baytı döndürüldü; Range GET isteklerinde seçilen parça boyutu (`len`), tam dosya GET isteklerinde `meta_len` gövde baytı olarak döndürüldü.
   - `serve_php_request` (FastCGI): HEAD / 204 / 304 durumunda `body_len = 0`; 502 Bad Gateway hatasında HEAD ise 0, aksi halde hata şablonu boyutu döndürüldü.
   - `serve_proxy_request` (Ters Vekil): Upstream yanıtında `\r\n\r\n` (veya `\n\n`) sonrası gerçek gövde uzunluğu hesaplanarak HTTP başlıkları bayt sayımından çıkarıldı. HEAD / 204 / 304 isteklerinde 0 gövde baytı iletildi.
   - Önbellek (Cache HIT/STALE - PHP ve Statik): HEAD / 204 / 304 durumlarında `cached_bytes = 0`, GET durumunda `cached.body.len()` sağlandı.
   - `handle_h2_dispatched_request`: Statik dosyalarda `check_if_none_match(&req.headers, &info.etag)` ile 304 Not Modified desteği eklendi.
2. `crates/zmax-bin/src/h2_engine.rs`:
   - HTTP/2 akışlarında `is_no_body = is_head || status_code == 204 || status_code == 304` denetimi eklendi.
   - 413 (Payload Too Large) ve 500 (Internal Error) durumlarında access_log'a eksiksiz kayıt düşüldü.
3. `crates/zmax-bin/src/logger.rs`:
   - `format_combined_line`: NCSA combined standardı (`%h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-Agent}i"`) ve HEAD/304/204/0 bayt için `-` kuralı doğrulandı.
   - Birim test eklendi: `logger::tests::test_ncsa_combined_matches_panel_parse_access_specification`.
4. `crates/zmax-bin/src/main.rs`:
   - Entegrasyon testi eklendi: `tests::kart2_real_bytes_all_response_types_and_panel_compatibility` (Statik GET, Statik HEAD, 304, Range 206 GET/HEAD, Error 404 GET/HEAD, Error 403 GET/HEAD, Cache MISS/HIT GET/HEAD, Proxy GET/HEAD, FastCGI GET/HEAD, HTTP/2 GET/HEAD/304).

**Yanıt Tipleri ve Bayt Sözleşmesi Tablosu:**
| Yanıt Tipi | HTTP Kodu | curl download_size | access_log %b | Açıklama |
|---|---|---|---|---|
| Statik Dosya (GET) | 200 OK | N bayt | N bayt | Gerçek dosya gövdesi (örn. 52 bayt) |
| Statik Dosya (HEAD) | 200 OK | 0 bayt | `-` | NCSA standardı: Gövdesiz yanıt |
| Statik / Dinamik 304 | 304 Not Modified | 0 bayt | `-` | ETag / If-None-Match gövdesiz |
| Statik Dosya (204) | 204 No Content | 0 bayt | `-` | Gövdesiz yanıt |
| Range İstek (GET) | 206 Partial Content | K bayt | K bayt | İstenen aralık gövde baytı (örn. bytes=10-20 -> 11 bayt) |
| Range İstek (HEAD) | 206 Partial Content | 0 bayt | `-` | Range HEAD gövdesiz |
| Hata Sayfası (GET) | 404 Not Found | M bayt | M bayt | Özel veya standart 404 HTML gövdesi |
| Hata Sayfası (HEAD) | 404 Not Found | 0 bayt | `-` | Hata HEAD gövdesiz |
| Hata Sayfası (GET) | 403 Forbidden | M bayt | M bayt | 403 HTML gövdesi |
| Hata Sayfası (HEAD) | 403 Forbidden | 0 bayt | `-` | 403 HEAD gövdesiz |
| Önbellek HIT (GET) | 200 OK | N bayt | N bayt | Önbellekteki gövde boyutu |
| Önbellek HIT (HEAD) | 200 OK | 0 bayt | `-` | Önbellek HIT HEAD gövdesiz |
| Ters Vekil / Proxy (GET) | 200 OK | P bayt | P bayt | Upstream başlıkları hariç saf gövde |
| Ters Vekil / Proxy (HEAD) | 200 OK | 0 bayt | `-` | Proxy HEAD gövdesiz |
| FastCGI / PHP (GET) | 200 OK | F bayt | F bayt | PHP çıktısı gövde baytı |
| FastCGI / PHP (HEAD) | 200 OK | 0 bayt | `-` | FastCGI HEAD gövdesiz |
| HTTP/2 Akışı (GET) | 200 OK | H bayt | H bayt | DATA çerçevelerindeki gövde baytı |
| HTTP/2 Akışı (HEAD) | 200 OK | 0 bayt | `-` | Yalnız HEADERS çerçevesi, 0 gövde |
| HTTP/2 Akışı (304) | 304 Not Modified | 0 bayt | `-` | Yalnız HEADERS çerçevesi, 0 gövde |

**Panel Parser Uyumu:**
- Go paneli `ParseAccess` regex'i:
  `^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\d+|-)(?: "([^"]*)" "([^"]*)")?`
- Zaman damgası formatı: `02/Jan/2006:15:04:05 -0700`
- ZMax'in formatladığı günlük satırları bu regex ve Go zaman şablonu ile %100 örtüşmektedir. `bytes_str` alanı gövdesiz durumlarda tam olarak `-` döndürmekte, sayısal bayt durumlarında ise gövde baytını içermektedir.

**Gerçek durum (etiket):**
- Günlükte Gerçek Bayt ve Panel Uyumu: `UNIT TESTED` & `INTEGRATION TESTED` (HTTP/1.1 socket + HTTP/2 frames + Static + FastCGI + Proxy + Cache + Error pages).
  - Kanıt 1: `zmax-bin::logger::tests::test_ncsa_combined_matches_panel_parse_access_specification ... ok`
  - Kanıt 2: `zmax-bin::tests::kart2_real_bytes_all_response_types_and_panel_compatibility ... ok`

**Kabul testleri (kartın):**
- Komut 1: `$env:CARGO_TARGET_DIR="D:\zmaxserver-ajan\target-a02"; cargo test --manifest-path D:\zmaxserver-ajan\a02\Cargo.toml -p zmax-bin --offline -- test_ncsa_combined_matches_panel_parse_access_specification`
  Çıktı:
```
running 1 test
test logger::tests::test_ncsa_combined_matches_panel_parse_access_specification ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 36 filtered out; finished in 0.02s
```

- Komut 2: `$env:CARGO_TARGET_DIR="D:\zmaxserver-ajan\target-a02"; cargo test --manifest-path D:\zmaxserver-ajan\a02\Cargo.toml -p zmax-bin --offline -- kart2_real_bytes_all_response_types_and_panel_compatibility`
  Çıktı:
```
running 1 test
test tests::kart2_real_bytes_all_response_types_and_panel_compatibility ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 36 filtered out; finished in 0.12s
```

- Komut 3: `$env:CARGO_TARGET_DIR="D:\zmaxserver-ajan\target-a02"; cargo test --manifest-path D:\zmaxserver-ajan\a02\Cargo.toml -p zmax-bin --offline`
  Çıktı:
```
running 37 tests
test api::tests::test_json_extractors ... ok
test api::tests::test_authorization_check ... ok
test api::tests::test_normalize_panel_request_path ... ok
test tests::acme_challenge_path_is_exempt ... ok
test modules_runtime::tests::hotlink_protection_blocks_external_media_but_allows_direct_and_self ... ok
test api::tests::test_prometheus_metrics_config_ports_and_proxy_prefix_routing ... ok
test modules_runtime::tests::static_module_policy_compiles_with_expected_defaults_and_overrides ... ok
test tests::dual_listener_same_port_is_rejected_without_reuse_port ... ok
test logger::tests::test_ncsa_combined_matches_panel_parse_access_specification ... ok
test modules_runtime::tests::select_negotiated_image_prefers_avif_then_webp_safely ... ok
test tests::api_and_admin_allow_loopback_unban_even_when_loopback_banned_but_block_remote ... ok
test logger::tests::ncsa_combined_formats_timestamp_numeric_bytes_and_escapes ... ok
test modules_runtime::tests::gzip_brotli_and_fastcgi_policies_compile_from_toml ... ok
test logger::tests::json_format_writes_valid_single_line_json_and_tails ... ok
test modules_runtime::tests::append_line_with_rotation_rotates_to_dot_one_backup ... ok
test tests::redirect_keeps_host_path_and_query ... ok
test tests::redirect_rejects_bad_host ... ok
test tests::api_modules_bans_unban_logs_and_tag_purge ... ok
test tests::hotlink_protection_blocks_foreign_referer_and_allows_same_host ... ok
test tests::force_https_redirects_http_but_not_acme_and_not_https ... ok
test tests::panel_admin_proxy_prefix_and_tls_validation ... ok
test logger::tests::per_vhost_target_rotation_and_reopen_all_writes_to_new_file ... ok
test tests::http2_and_http1_real_request_isolation_and_coexistence ... ok
test tests::ip_acl_cidr_allow_and_deny_enforced ... ok
test tests::reverse_proxy_routes_backend_http ... ok
test tests::php_path_info_and_translated_resolved_in_web_engine ... ok
test tests::keepalive_pipelining_gzip_and_413_payload_limit ... ok
test tests::vhost_custom_error_docs_404_vs_default ... ok
test tests::static_utf8_subdir_range_etag_head_and_hidden_block ... ok
test tests::vhost_per_domain_waf_policy_and_exclude_paths ... ok
test tests::wp_bruteforce_ban_and_non_loopback_admin_auth ... ok
test tests::webp_and_avif_accept_negotiation_sets_vary_accept ... ok
test tests::wordpress_htaccess_permalink_and_fastcgi_headers ... ok
test tests::cache_swr_serves_stale_and_revalidates ... ok
test tests::reverse_proxy_uses_upstream_pool_for_keepalive ... ok
test tests::kart2_real_bytes_all_response_types_and_panel_compatibility ... ok
test tests::two_vhosts_isolated_logging_and_reopen_writes_to_new_file ... ok

test result: ok. 37 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.25s
```

**Git Bilgileri:**
- Dal: `kart-2-gunluk-bayt`
- Çalışma Alanı: `D:\zmaxserver-ajan\a02`
- Commit SHA: `fd6eedd626e080cb3a0d792f3804d9ba48956c02`
- Commit Mesajı: `[kart-2] gunlukte gercek bayt, panel/fail2ban uyumu`
- Değiştirilen dosyalar (4 dosya, +626 / -30):
  - `crates/zmax-bin/src/h2_engine.rs`
  - `crates/zmax-bin/src/logger.rs`
  - `crates/zmax-bin/src/main.rs`
  - `crates/zmax-bin/src/web_engine.rs`
