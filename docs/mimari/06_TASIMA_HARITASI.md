# ZMax Taşıma Haritası — `origin/main` → v3.0 Parçaları

**GÜNCEL TABAN:** `origin/main` `19608a4` (v1.0.08). `web_engine.rs` bu ağaçta zaten `web_engine/` altında 16 dosyadır (pipeline_h1, pipeline_h2, http_write, logging, static_files, static_stream, php, proxy_h1/h2, cached_response, cache_policy, purge, context, request_util, extra_listeners). Aşağıdaki **eski** tablo `calisma-ana` (eski) ağacına aittir; geçerli eşleme ve satırlar için **`08_GOREV_KARTLARI_M0_M12.md`** kullanılır. Şema boşlukları: `extra_listeners.rs`, Basic Auth (`security_pipeline.rs`), h2-kapalı vhost.

---

## ESKİ TABLO (eski ağaç, yalnız tarihçe)

Satır numaraları 2026-11-14 tarihli kaynaktandır (`D:\zmaxserver\crates\zmax-bin\src`). "~" işaretli aralıklar yaklaşıktır, taşıma sırasında kesinleştirilir. Gömülü testler (`#[cfg(test)]`) ilgili parçanın `tests/` dosyasına taşınır.

## 1. `web_engine.rs` (4198 satır)

| Satır | İçerik | Hedef |
|---|---|---|
| 60-68 | `php_balancer_map`, `lscache_vary_map` | L7 `upstream.rs` / L6 |
| 69-86 | `Http1Stream`, `ResponseSink` | `pipeline/mod.rs` (ortak tipler) |
| 87-373 | `ResolvedVHostContext`, `build_vhost_context` | L5 |
| 374-648 | `build_final_response_headers`, `format_http_response_head`, `write_http_*` | L8 |
| 649-833 | `send_unified_response`, `stream_file_to_sink` | L8 |
| 834-970 | `default_dark_error_page`, `write_error_response` | L8 |
| 971-1045 | `log_vhost_error`, `record_access_log_entry` | L8 → K5 köprüsü |
| 1046-1060 | `normalize_host_name` | L5 |
| 1061-1187 | `handle_web_connection(_with_tls)` | L1 + L2 |
| 1188-1309 | `handle_h2_request`, `handle_h2_early_error` | L2 (`h2.rs`) |
| 1310-1390 | istek başlangıcı, Host (1372) | L2 |
| 1391-1438 | HTTP/2 ve Strict SNI | L2 |
| ~1245, ~1347 | `resolve_real_ip` (iki kopya) | L3 (tek fonksiyon) |
| 1439-1525 | yasaklı IP, ACL, rate limit | L4 |
| 1526-1596 | WAF, WP brute-force | L4 |
| 1597-1648 | `force_https`, ACME HTTP-01 | L5 |
| 1649-1669 | ters vekil kararı | L5 (karar) → L7 `proxy.rs` |
| 1670-~1783 | Rewrite / `.htaccess`, hotlink, 410/403 | L5 |
| ~1784-~1930 | cache anahtarı, Fresh/Stale/Miss, stampede | L6 |
| ~1930-2287 | PHP/statik dağıtımı | L7 |
| 2288-2430 | `resolve_predecoded_static_file`, `serve_sidecar_file` | L7 `static_files.rs` |
| 2431-2749 | `serve_static_file` | L7 `static_files.rs` |
| 2750-2775 | `compress_dynamic_content` | L8 |
| 2776-2914 | `write_cached_response`, `revalidate_static_cache` | L6 |
| 2915-3398 | `execute_and_prepare_php`, `fetch_and_cache_php`, `serve_php_request` | L7 `fastcgi.rs` (+L6 doldurma) |
| 3399-3649 | `serve_proxy_request_with_sink` | L7 `proxy.rs` |
| 3650-3736 | bağlantı kapatma, görsel müzakere, `stream_file_range_pooled` | L7 |
| 3737-3776 | `request_has_bypass_cookie_or_auth`, `response_forbids_cache` | L6 |
| 3777-3806 | `default_status_reason` | L8 |
| 3807-3847 | `is_acme_challenge`, `https_redirect_location` | L5 |
| 3848-4198 | testler | `tests/` |

## 2. `api.rs` (3000 satır)

| Satır | İçerik | Hedef |
|---|---|---|
| 27-120 | `AccessLogRecord`, `ServerStats`, `RuntimeState`, `ServerState` | K2 |
| 121-149 | `current_hms_utc`, `refresh_tls_certs` | K6 / K3 |
| 150-176, 303-338, 377-425 | `ParsedHttpRequest`, okuma/yazma yardımcıları | `api/http.rs` |
| 177-302 | elle JSON çıkarıcılar | `api/http.rs` (JSON yardımcısı) |
| 339-376 | `constant_time_eq`, `is_authorized` | A1 |
| 426-569 | TLS ALPN, `reload_runtime_state` | K3 |
| 570-810 | `format_vhost_json` | A8 `vhost_service.rs` |
| 811-825 | `classify_ban_reason_key` | A5 |
| 826-871 | `write_vhost_atomic` | A8 `vhost_service.rs` |
| 872-926 | `percent_decode`, `parse_query_param`, `has_parent_dir_traversal` | A2 |
| 927-1237 | `merge_*`, `val_as_*`, `merge_vhost_json_patch` | A8 `vhost_service.rs` |
| 1238-1258 | `normalize_panel_request_path` | A2 |
| 1259-1308 | `handle_api_route` giriş, CORS, kimlik (1327) | A1 + A2 |
| 1309-1437 | health, metrics, status | A3 |
| 1438-1516 | modules, modules/toggle | A3 |
| 1517-1571 | security/bans, unban | A5 |
| 1572-1738 | logs, logs/reopen | A6 |
| 1739-1777 | ports | A3 |
| 1778-2008 | cache/purge | A5 → A8 `cache_service.rs` |
| 2009-2074 | reload, config | A3 → A8 `config_service.rs` |
| 2075-2224 | vhosts (GET/POST/PUT/DELETE) | A4 → A8 |
| 2225-3000 | testler | `tests/` |

## 3. Diğer dosyalar

| Dosya | Satır | Hedef |
|---|---|---|
| `main.rs` | 1-165 CLI, taban dizin, dinleyici yardımcıları | K1 |
| | 166-285 yükleme | K3 |
| | 286-360 bind adresleri, durum kurulumu | K1 + K2 |
| | 361-376 bakım görevi | K6 |
| | 377-490 HTTP/HTTPS dinleyici | L1 |
| | 492-575 admin/api dinleyicileri | `api/mod.rs` |
| | 576-607 Unix soketi | `api/mod.rs` |
| | 608-655 SIGHUP, SIGUSR1 | K1 `signals.rs` |
| | 656-718 `handle_api_connection` | `api/mod.rs` |
| | 719-851 `handle_admin_connection` | A7 |
| | 852-2142 testler (bütünleşik) | `tests/` |
| `modules_runtime.rs` | 11-361 politikalar, `compile_policies` | K4 |
| | 362-388 `resolve_vhost_security_headers` | L8 |
| | 389-500 token üretimi, `compute_effective_auth` | A1 |
| | 501-534 `module_category_key` | K4 |
| | 535-580 `build_redis_client` | K7 `redis/client.rs` |
| | 581-692 görsel müzakeresi | L7 `static_files.rs` |
| | 693-754 log ekleme ve rotasyon | K5 |
| | 755-924 hotlink koruması | L5 |
| | 925-1437 testler | `tests/` |
| `logger.rs` | tamamı | K5 |
| `h2_engine.rs` | tamamı | L2 `h2.rs` |
| `admin/index.html`, `admin/js/core.js` | 885 / 781 | U1 / U2 + U3 + U4-U7 |

## 4. Taşıma Sırası (güvenli adım adım)
Her adımda: `cargo check -p zmax-bin` + yalnız o adımın testleri; bir adım bitmeden sonrakine geçilmez. Davranış değişikliği yok, yalnız yer değiştirme.

1. **K2 + K5** — durum ve logger (en az bağımlı).
2. **K3 + K4** — config ve modül politikaları.
3. **A1, A2 ve `api/http.rs`** — yardımcılar ve kimlik (davranış aynı).
4. **A3-A6 rotaları ve A8 servisleri** — `handle_api_route` parçalanır.
5. **L8 ve L7** — yanıt ve işleyiciler.
6. **L5, L6, L4, L3** — yönlendirme, önbellek, güvenlik, gerçek IP (iki kopya tek olur).
7. **L2 ve L1** — protokol/TLS ve bağlantı (H2 dahil).
8. **K1 + K6** — `main.rs` ince hale gelir.
9. **U1-U7** — WebAdmin bileşenleri.
10. **Köprü B1-B5** (`07_RUST_GO_KOPRUSU.md`): önce B1 sözleşme + golden dosyaları, sonra B2 uç noktaları (`version`, `config/validate`, `reload` sonucu, `events`), B3 Go istemcisi, B4 dosya kuralı, B5 yaşam döngüsü. A8 servisleri hazır olduktan sonra başlar (adım 4).
11. **K7 Redis** (`05` K7): en sona. `zmax-redis` crate'i yerinde kalır; `build_redis_client` ve Redis çağrıları (`web_engine.rs:1574` ban, `api.rs:1830/1996` purge) `redis/sync.rs` arkasına alınır. Önce taşıma (davranış aynı), sonra `00` §7 madde 8'e göre abone tarafı ve kodu olmayan ayarlar.
12. **Yeni özellikler** (ayrı, sahip onayıyla): A9 denetim, A2'deki API rate limit/ban, rol modeli, SSE akışı.
