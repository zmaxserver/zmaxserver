# ZMax Taşıma Haritası — TAŞIMA TAMAM: eski → yeni dosya eşlemesi

**Durum:** M1–M12 taşıma kartları ve M13–M20 yeni özellik kartları `birlesme2` dalında birleşti; `main` = `birlesme2` = `dff16c6` (tam test 494 geçti, `bitti/BIRLESME2.md`). Bu belge taşımanın **sonucunu** yazar; eski satır aralığı tabloları kaldırıldı (kaynak dosyaların çoğu artık yok). Önceki plan sürümü `eski_v2/onceki_plan_sema/06_TASIMA_HARITASI.md`.
Yöntem: yeni yollar `agaclar/birlesme2/crates/zmax-bin/src` altında dosya listesi + işlev tanımı satırları okunarak doğrulandı; eski yollar kartlardan (`08`) ve eski ağaç belgelerinden alındı. Kök: `crates/zmax-bin/src`.

## 1. Silinen / küçülen kaynak dosyalar
| Eski | Şimdi |
|---|---|
| `api.rs` (~3000) | **silindi** → `api/`, `core/state.rs`, `config/reload.rs` |
| `logger.rs` (1139) | **silindi** → `logger/` |
| `h2_engine.rs` (272) | **silindi** → `pipeline/l2_protocol/h2.rs` |
| `main.rs` (2142→) | 2873 satır: `main()` 45 + **bütünleşik testler 50-2873** (`tests/` klasörüne taşınmadı) |
| `modules_runtime.rs` | 505 satır: **yalnız testler** (`mod tests` 15); işlevler başka yere taşındı |
| `acme_runtime.rs` | 2 satır (yeniden dışa aktarım) → `config/acme.rs` |
| `web_engine/` (16 dosya) | 5 dosya kaldı: `mod.rs`, `pipeline_h1.rs`, `pipeline_h2.rs`, `extra_listeners.rs`, `kart8_tests.rs` |

## 2. `api.rs` → yeni
| Eski içerik | Yeni yer |
|---|---|
| `AccessLogRecord`, `ServerStats`, `RuntimeState`, `ServerState` | `core/state.rs` 17/29/36/51 |
| `ParsedHttpRequest`, JSON çıkarıcılar, okuma/yazma yardımcıları | `api/http.rs` (`extract_json_*` 52-120, `read_http_request_with_limits` 159, `send_json_response` 255) |
| `constant_time_eq`, `is_authorized` | `api/auth.rs` 8, 62 (+ yeni: `authorize_role` 27, `read_role_allowed` 72) |
| `generate_secure_token`, `compute_effective_auth` (`modules_runtime.rs`'ten) | `api/auth.rs` 85, 112 |
| `percent_decode`, `parse_query_param`, `normalize_panel_request_path` | `api/guard.rs` 77, 108, 129 |
| `has_parent_dir_traversal` | `zmax-config/src/vhost_json.rs:152` |
| `refresh_tls_certs`, `reload_runtime_state*` | `config/reload.rs` 11, 66, 171 |
| `format_vhost_json`, `write_vhost_atomic`, `merge_vhost_json_patch` | `api/services/vhost_service.rs` 3, 7, 94 |
| `classify_ban_reason_key`, bans/unban | `api/services/security_service.rs` 3, 16, 61 |
| `cache/purge` | `api/services/cache_service.rs` 3 |
| `reload`, `config` | `api/services/config_service.rs` 3, 45 |
| `handle_api_route` | `api/mod.rs` 54; rotalar `api/routes/{system,vhosts,security_cache,logs}.rs` |
| `handle_admin_connection` (`main.rs`) | `api/admin_static.rs` 7 |
| `handle_api_connection` (`main.rs`) | `api/mod.rs` 163 |

## 3. `main.rs`, `modules_runtime.rs`, `logger.rs`, `h2_engine.rs` → yeni
| Eski | Yeni |
|---|---|
| `main.rs` CLI, taban dizin, dinleyici, TLS izin düzeltme | `core/boot.rs` (`parse_cli_args` 29, `resolve_base_dir` 69, `create_reuse_listener` 111, `run_fix_tls_perms` 182, `parse_bind_addr` 216, `run` 228) |
| `main.rs` SIGHUP/SIGUSR1 | `core/signals.rs` 6 **ve** `core/boot.rs` içinde satır içi kopya (825-866); signals.rs çağrılmıyor |
| `main.rs` bakım görevi | `core/tasks.rs` 6 **ve** `core/boot.rs:425-440` kopya; tasks.rs çağrılmıyor |
| `main.rs` HTTP/HTTPS kabul | `pipeline/l1_connection.rs` 14, 36 |
| `modules_runtime.rs` `compile_policies` + politikalar | `modules/policy.rs` 152 |
| `modules_runtime.rs` `module_category_key` | `modules/registry.rs` 4 |
| `modules_runtime.rs` `build_redis_client` | `redis/client.rs` 5 |
| `modules_runtime.rs` hotlink koruması | `pipeline/l5_router.rs` 132-302 |
| `modules_runtime.rs` görsel müzakeresi | `pipeline/l7_handlers/static_files.rs` 25-145 |
| `modules_runtime.rs` `resolve_vhost_security_headers` | `pipeline/l8_response.rs` 21 |
| `modules_runtime.rs` log ekleme + rotasyon | `logger/rotate.rs` 19-70 |
| `logger.rs` | `logger/{mod,worker,format,rotate,tail,tests}.rs` (273/344/110/72/86/465) |
| `h2_engine.rs` | `pipeline/l2_protocol/h2.rs` 21, 115, 434 |

## 4. `web_engine/` (eski 16 dosya) → yeni
| Eski | Yeni (işlev adından doğrulandı) |
|---|---|
| `http_write.rs`, `logging.rs` | `pipeline/l8_response.rs` (`write_http_response` 163, `write_error_response` 259, `record_and_log` 347); geri uyum modülleri 487-500 |
| `php.rs` | `pipeline/l7_handlers/fastcgi.rs` 32, 241, 282 |
| `static_files.rs`, `static_stream.rs` | `pipeline/l7_handlers/static_files.rs` 169, 224, 314, 685 |
| `proxy_h1.rs`, `proxy_h2.rs` | `pipeline/l7_handlers/proxy.rs` 73, 418 |
| `context.rs`, `request_util.rs` | `pipeline/l5_router.rs` (`ResolvedVHostContext` 25, `https_redirect_location` 93, `is_acme_challenge` 86) |
| `cached_response.rs`, `cache_policy.rs`, `purge.rs` | `pipeline/l6_cache.rs` (52, 93, 123, 160, 217, 248) |
| `security_pipeline.rs` (ortak güvenlik) | `pipeline/l4_security.rs` 48 (+ `security_pipeline.rs` yeniden dışa aktarım ve L4a Basic Auth) |
| `resolve_real_ip` kopyaları | `pipeline/l3_realip.rs` 7 |
| `pipeline_h1.rs`, `pipeline_h2.rs` | **yerinde kaldı** (orkestratör: sıra, `handle_single_web_request` 32; `handle_h2_dispatched_request` 23) |
| `extra_listeners.rs` | **yerinde kaldı** (L1a, `01` §L1a) |

## 5. Yeni dosyalar (taşıma değil, özellik kartları)
`api/audit.rs` (M16, A9), `api/guard.rs` içindeki rate limit/ban (M17, A2), `api/routes/logs.rs` `logs_stream` (M18, A6), `redis/events.rs` + `redis/sync.rs` (M19, K7), `api/bridge.rs` (M20, B2). Go tarafı: `D:\zmaxserver\katmanlizmax\go\` (izlenmiyor).

## 6. Taşıma sırası (yapıldı)
K2+K5 → K3+K4 → A1/A2/http → A3–A6 rotaları + A8 → L8+L7 → L5/L6/L4/L3 → L2/L1 → K1/K6 (kısmen: kopya) → U1–U7 (M10) → B (M11/M20) → K7 (M19) → yeni özellikler (M13–M18).

## 7. Taşımadan kalan işler (sahip kararıyla)
1. `main.rs` içindeki ~2800 satır test → `tests/` klasörü.
2. `core/signals.rs`, `core/tasks.rs` bağlanmalı veya `boot.rs`'teki kopya silinmeli.
3. `Outcome`/`RequestContext` sözleşmesi (`01` §3).
4. `pipeline_h1.rs`/`pipeline_h2.rs` parçalanması.
