# ZMax Server — Bağımsız Denetim Raporu: Kart 1

**Denetim Tarihi:** 2026-11-12 02:05  
**Denetlenen:** Kart 1 — Faz 0 Doğrulama ve İstek Hattı Entegrasyon Testleri  
**Denetçi:** Bağımsız Denetçi Ajan (Antigravity / `YAPAY_ZEKA_KURALLARI.md` standardı)  
**Nihai Karar:** **ONAYLI (Kabul Edildi & Kilitlendi)**

---

## 1. Yönetici Özeti ve Karar
Geliştirici ajan tarafından `crates/zmax-bin/src/web_engine.rs`, `main.rs`, `logger.rs`, `h2_engine.rs` ve `api.rs` dosyalarında yapılan geliştirmeler, birim/entegrasyon testleri ve harici kabul testleri bağımsız olarak incelenmiş, testler bağımsız oturumda bizzat çalıştırılmış ve doğrulanmıştır.

Kart 1 için belirlenen tüm kabul kriterleri eksiksiz karşılanmış, önceki RED gerekçeleri giderilmiş, assert kontrolleri sertleştirilmiş ve canlı sunucu kabul betiği (`verify_all_acceptance.py`) %100 başarıyla tamamlanmıştır.

---

## 2. Dört Ana Kabul Şartının Bağımsız Doğrulaması

| # | Kabul Şartı | Durum | Doğrulama Kanıtı |
|---|---|---|---|
| **a** | İki vHost izole günlükleme, NCSA Combined `[%d/%b/%Y:%H:%M:%S %z]` tarih formatı, gerçek gönderilen sayısal bayt ve `reopen_all` doğrulandı mı? | **TAM DOĞRULANDI** | `main.rs` içinde `tests::two_vhosts_isolated_logging_and_reopen_writes_to_new_file` testi; `status == 200`, `bytes_sent == 18` (vhost-a ve vhost-b gövde uzunluğu) kesin sayısal assert ile doğrulandı (`-` ve `0` reddedildi). `reopen_all` sonrası yeni satırların yazıldığı ve ayrı dosyalara yazıldığı kanıtlandı. |
| **b** | 404 `error_docs` (özel 404.html vs varsayılan 404) gerçek istek hattından test edildi mi? | **TAM DOĞRULANDI** | `tests::vhost_custom_error_docs_404_vs_default` testi; vhost-a için `CUSTOM_404_PAGE_FOR_VHOST_A` dönerken vhost-b için varsayılan sayfa döndü. `web_engine.rs` içinde `write_error_response` ve `StaticFileHandler::resolve_error_doc_file` çağrısı doğrulandı. |
| **c** | vHost WAF politikası (`waf_enabled=false` -> 200 OK, `waf_enabled=true` -> 403 Forbidden, `waf_exclude_paths` -> 200/404 muaf) test edildi mi? | **TAM DOĞRULANDI** | `tests::vhost_per_domain_waf_policy_and_exclude_paths` testi ve `verify_all_acceptance.py` TEST 3; vhost-a SQLi saldırısını 403 ile bloklarken muaf yolda engellemedi, vhost-b'de WAF kapalı olduğu için SQLi isteği 200 OK ile geçti. |
| **d** | HTTP/2 (`h2::client`) gerçek 200 OK yanıtı ve HTTP/1.1 eşzamanlı istek testi çalışıyor mu? | **TAM DOĞRULANDI** | `tests::http2_and_http1_real_request_isolation_and_coexistence` testi; `h2::client::handshake` ile gerçek h2 el sıkışması yapıldı, `GET http://vhost-a.test/` isteği ile HTTP/2 200 OK ve `VHOST_A_BODY_12345` alındı; eşzamanlı HTTP/1.1 isteği etkilenmeden 200 OK ile döndü. |

---

## 3. Bağımsız Test Çalıştırma Sonuçları (Literal Çıktılar)

### Komut 1: `cargo test --manifest-path D:\zmaxserver\Cargo.toml -p zmax-bin --offline`
```
running 35 tests
test api::tests::test_json_extractors ... ok
test api::tests::test_normalize_panel_request_path ... ok
test api::tests::test_authorization_check ... ok
test tests::acme_challenge_path_is_exempt ... ok
test modules_runtime::tests::hotlink_protection_blocks_external_media_but_allows_direct_and_self ... ok
test api::tests::test_prometheus_metrics_config_ports_and_proxy_prefix_routing ... ok
test tests::dual_listener_same_port_is_rejected_without_reuse_port ... ok
test logger::tests::json_format_writes_valid_single_line_json_and_tails ... ok
test modules_runtime::tests::static_module_policy_compiles_with_expected_defaults_and_overrides ... ok
test modules_runtime::tests::gzip_brotli_and_fastcgi_policies_compile_from_toml ... ok
test modules_runtime::tests::select_negotiated_image_prefers_avif_then_webp_safely ... ok
test tests::api_and_admin_allow_loopback_unban_even_when_loopback_banned_but_block_remote ... ok
test logger::tests::ncsa_combined_formats_timestamp_numeric_bytes_and_escapes ... ok
test tests::redirect_keeps_host_path_and_query ... ok
test tests::hotlink_protection_blocks_foreign_referer_and_allows_same_host ... ok
test tests::redirect_rejects_bad_host ... ok
test logger::tests::per_vhost_target_rotation_and_reopen_all_writes_to_new_file ... ok
test tests::panel_admin_proxy_prefix_and_tls_validation ... ok
test tests::force_https_redirects_http_but_not_acme_and_not_https ... ok
test modules_runtime::tests::append_line_with_rotation_rotates_to_dot_one_backup ... ok
test tests::api_modules_bans_unban_logs_and_tag_purge ... ok
test tests::http2_and_http1_real_request_isolation_and_coexistence ... ok
test tests::ip_acl_cidr_allow_and_deny_enforced ... ok
test tests::keepalive_pipelining_gzip_and_413_payload_limit ... ok
test tests::php_path_info_and_translated_resolved_in_web_engine ... ok
test tests::reverse_proxy_routes_backend_http ... ok
test tests::vhost_custom_error_docs_404_vs_default ... ok
test tests::wp_bruteforce_ban_and_non_loopback_admin_auth ... ok
test tests::static_utf8_subdir_range_etag_head_and_hidden_block ... ok
test tests::webp_and_avif_accept_negotiation_sets_vary_accept ... ok
test tests::vhost_per_domain_waf_policy_and_exclude_paths ... ok
test tests::wordpress_htaccess_permalink_and_fastcgi_headers ... ok
test tests::reverse_proxy_uses_upstream_pool_for_keepalive ... ok
test tests::cache_swr_serves_stale_and_revalidates ... ok
test tests::two_vhosts_isolated_logging_and_reopen_writes_to_new_file ... ok

test result: ok. 35 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s
```

### Komut 2: `cargo test --manifest-path D:\zmaxserver\Cargo.toml --workspace --offline`
- Workspace genelinde 18 crate'in testleri çalıştırıldı.
- **Sonuç:** Toplam **220 passed; 0 failed; 0 ignored; 0 filtered out**.

### Komut 3: `python D:\zmaxserver\doc\tools\verify_all_acceptance.py`
```
[1/6] Test ortami hazirlaniyor...
[2/6] Sunucu baslatiliyor (2 saniye bekleniyor)...

--- TEST 1: Alan Adina Ozel Erisim Gunlugu (NCSA & Gercek Bayt) ---
  vhost-a log satiri: 127.0.0.1 - - [11/Nov/2026:22:59:17 +0000] "GET / HTTP/1.1" 200 27 "-" "-"
  vhost-b log satiri: 127.0.0.1 - - [11/Nov/2026:22:59:17 +0000] "GET / HTTP/1.1" 200 27 "-" "-"
  [OK] Her iki vhost kendi dosyasina yazdi, NCSA tarihi ve gercek bayti dogrulandi.
  [OK] /api/v1/logs/reopen API ile log dosyalari kesintisiz yeniden acildi.

--- TEST 2: Ozel Hata Sayfalari (vHost error_docs) ---
  [OK] vhost-a icin ozel 404 sayfasi ('CUSTOM_404_PAGE_FOR_VHOST_A') basariyla donduruldu.
  [OK] vhost-b ozel sayfasi olmadigi icin varsayilan 404 sayfasini dondurdu.

--- TEST 3: Alan Adina Ozel WAF (waf_enabled & muafiyet) ---
  [OK] vhost-a (waf_enabled=true) saldiri istegini 403 ile engelledi.
  [OK] vhost-a muaf yol (/muaf-yol) WAF denetiminden muaf tutuldu (Durum: 404).
  [OK] vhost-b (waf_enabled=false) genel WAF'i ezdi ve saldiri gecti (Durum: 200).

--- TEST 4: API vHost CRUD ve Traversal Korunumu ---
  [OK] POST /api/v1/vhosts tum gelismis alanlari TOML'a atomik yazdi.
  [OK] POST /api/v1/vhosts dizin kacis saldirisini 400 Bad Request ile engelledi.

============================================================
✅ TUM 8 MADDE KABUL TESTLERI BASARIYLA TAMAMLANDI VE KANITLANDI!
============================================================

[Temizlik] Sunucu kapatiliyor ve test dosyalari siliniyor...
```

---

## 4. Kurallara Uyum Denetimi
- **Kart dışı değişiklik:** `drop_privileges` ve `execute_php_pooled` çağrıları `main.rs` ve `web_engine.rs` dosyalarından temizlenmiştir (0 çağrı). Kart dışı müdahale yoktur.
- **Artık dosyalar:** Dizin genelinde `*.bak`, `*.tmp`, `*.orig` taraması yapılmış ve 0 artık dosya tespit edilmiştir.
- **Ölçülmemiş performans iddiaları:** Raporda ölçülmemiş herhangi bir performans iddiası bulunmamaktadır ("Ölçülmedi" olarak etiketlenmiştir).

---

## 5. Kilit Durumu ve Sonraki Adım
- **Kart 1 Durumu:** **ONAYLI & KİLİTLİ** (`YAPAY_ZEKA_KURALLARI.md` Kural 11 uyarınca bu karta bir daha dokunulamaz).
- **Sıradaki Kart:** Kart 2 (`ADIMLI_GELISTIRME_TAKIP.md` - Statik Dosya Motoru Geliştirmeleri / Sendfile & Sidecar).
