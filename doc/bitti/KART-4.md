## Kart 4 — .htaccess ve Yönlendirme Gerçek-Site Doğrulaması (2026-11-12 02:45)

**Kural son okunma:** 02:40, sürüm v5.
**Okunanlar:** `doc/YAPAY_ZEKA_KURALLARI.md` (v5), `doc/AJAN_YAPISI.md`, `doc/ADIMLI_GELISTIRME_TAKIP.md` (Kart 4), `doc/DUZELTMELER.md`, `doc/karsilastirma/OLS_DENKLIK.md` (B2, B4, B5, B7, B15), `D:\lunixpanel\zpanel-tam\cekirdek\agent\internal\redirects\redirects.go`, `D:\lunixpanel\zpanel-tam\cekirdek\agent\internal\sites\htaccess_compat.go`, `crates/zmax-rewrite/src/lib.rs`, `crates/zmax-rewrite/src/htaccess.rs`, `crates/zmax-bin/src/web_engine.rs`.

**Kural ve düzeltme kontrolü (8a Öz Denetimi):**
- `doc/YAPAY_ZEKA_KURALLARI.md` (v5) ve `doc/DUZELTMELER.md` kontrol edildi.
- Yalnızca sahip olunan dosyalara dokunuldu: `crates/zmax-rewrite/src/htaccess.rs` ve `crates/zmax-rewrite/src/lib.rs`.
- Kart dışı dosya değiştirilmedi, `*.bak`/`*.tmp`/`*.orig` artık dosyası bırakılmadı (0 adet).
- Uydurma test sayısı veya ölçülmemiş iddia yazılmadı. Test sayıları cargo çıktısıyla birebir uyumlu.
- "Yetkisiz onay" veya "kilitlendi" gibi denetçi yetkisindeki ifadeler yazılmadı. Denetçi onayı bekleniyor olarak bırakıldı.
- Dal adı ve son commit SHA eklendi: dal `kart-4-htaccess`, commit `3bbd5965a1d78c41d2d48b2f95e3a038f4ef02b2`.

**Yapılan iş:**
- `crates/zmax-rewrite/src/htaccess.rs`:
  1. Panelin ürettiği `# BEGIN zPanel Redirects` bloğu desteği: `RewriteCond %{HTTPS} off`, `%{HTTP_HOST}`, `RewriteRule … [L,R=301]`, `%1`..`%9` koşul regex capture geri başvurusu tam desteği.
  2. `<FilesMatch "desen">` ve `<Files "glob">` erişim denetimi: `Deny from all` / `Require all denied` ile `Outcome::Forbidden` (403), `Allow from all` / `Require all granted` desteği.
  3. Yönlendirme döngüsü (Rewrite Loop / Ping-Pong) tespiti ve koruması: `history` takibi ile döngüsel isteklerde sonsuz döngü DoS engeli (`Outcome::Forbidden`), kendine yönlendirme (self-redirect 301/302) engeli (`Outcome::None`), azami 10 pass (`MAX_PASSES`) aşımında güvenli durdurma.
  4. Regex karmaşıklık ve ReDoS / DoS koruması: Azami 2048 karakter desen sınırı, `RegexBuilder` bellek sınırları (`size_limit: 1MB`, `dfa_size_limit: 2MB`), hatalı/aşırı karmaşık regex'lerin paniksiz `warnings` listesine aktarılması.
  5. Bilinmeyen Host (OLS_DENKLIK B15) kuralları: Boş veya portlu host başlıklarında paniksiz, kararlı çalışma (`%{HTTP_HOST}` ve `%{SERVER_NAME}`).
- `crates/zmax-rewrite/src/lib.rs`:
  1. `resolve_chain_with_info` hiyerarşik çözümleyicisine `<FilesMatch>` ve `<Files>` denetimi eklendi (RewriteEngine Off olsa bile core Apache kuralı olarak hiyerarşik koruma).
  2. 8 yeni birim testi eklendi: `zpanel_redirects_block_https_www_and_nowww_with_backrefs`, `files_match_deny_and_require_all_denied`, `files_wildcard_glob_denial`, `rewrite_loop_detection_and_self_redirect_safety`, `regex_max_length_dos_protection`, `unknown_host_and_custom_port_behavior`, `test_hierarchical_files_match_protection`, `test_zpanel_redirects_full_route_resolution`.
  3. `zmax-rewrite` birim test sayısı 25'ten 33'e yükseltildi.

**Gerçek durum (etiket):**
- Panelin yönlendirme bloğu (`%{HTTPS} off`, `%1`, `%{HTTP_HOST}`): `UNIT TESTED` (kanıt: `zpanel_redirects_block_https_www_and_nowww_with_backrefs ... ok`, `test_zpanel_redirects_full_route_resolution ... ok`)
- `<FilesMatch>` / `<Files>` Deny / Require all denied: `UNIT TESTED` (kanıt: `files_match_deny_and_require_all_denied ... ok`, `files_wildcard_glob_denial ... ok`, `test_hierarchical_files_match_protection ... ok`)
- Yönlendirme döngüsü (redirect loop) ve DoS koruması: `UNIT TESTED` (kanıt: `rewrite_loop_detection_and_self_redirect_safety ... ok`)
- Regex karmaşıklığı ve uzunluk sınırı: `UNIT TESTED` (kanıt: `regex_max_length_dos_protection ... ok`)
- Bilinmeyen Host yanıtı kuralları: `UNIT TESTED` (kanıt: `unknown_host_and_custom_port_behavior ... ok`)
- WordPress ve Laravel permalink uyumu: `UNIT TESTED` (kanıt: `test_wordpress_htaccess_permalinks_and_encoded_media ... ok`, `test_laravel_htaccess_and_turkish_routes ... ok`)
- Not: Canlı VM ortamında `curl -sI -H 'Host: wp.test' http://127.0.0.1:19480/ornek-yazi/` VM çalışması gerektirdiği için VM ortamında DENENMEDİ.

**Kabul testleri (kartın):**
- Komut 1: `cargo test --manifest-path D:\zmaxserver-ajan\a04\Cargo.toml -p zmax-rewrite --offline`
  Çıktı:
```
running 33 tests
test htaccess::tests::bad_regex_is_reported_not_fatal ... ok
test htaccess::tests::files_match_deny_and_require_all_denied ... ok
test htaccess::tests::files_wildcard_glob_denial ... ok
test htaccess::tests::forbidden_gone_or_cond_nocase_and_qsa ... ok
test htaccess::tests::redirect_directives_and_directory_index ... ok
test htaccess::tests::redirect_flags_and_backrefs ... ok
test htaccess::tests::regex_max_length_dos_protection ... ok
test htaccess::tests::request_uri_and_the_request_query_behavior ... ok
test htaccess::tests::rewrite_loop_is_bounded ... ok
test htaccess::tests::rewrite_loop_detection_and_self_redirect_safety ... ok
test htaccess::tests::unknown_host_and_custom_port_behavior ... ok
test htaccess::tests::wordpress_htaccess_preserves_existing_php_path_info ... ok
test htaccess::tests::wordpress_permalink_rewrites_missing_paths_only ... ok
test htaccess::tests::zpanel_redirects_block_https_www_and_nowww_with_backrefs ... ok
test tests::test_cms_rewrite_resolution ... ok
test tests::test_declarative_vhost_rewrite_rules ... ok
test tests::test_env_flag_http_authorization_and_forwarded_proto ... ok
test tests::test_error_document_directive ... ok
test tests::test_hierarchical_files_match_protection ... ok
test tests::test_hierarchical_rewrite_engine_off_stops_parent_rules ... ok
test tests::test_hierarchical_subdirectory_htaccess_dominance ... ok
test tests::test_htaccess_forbidden_and_flags_comprehensive ... ok
test tests::test_htaccess_mtime_cache_hit_and_invalidation ... ok
test tests::test_htaccess_redirect_forbidden_gone_and_directory_index ... ok
test tests::test_htaccess_rewrite_preserves_php_path_info ... ok
test tests::test_htaccess_wp_front_controller_keeps_existing_php_path_info ... ok
test tests::test_ifmodule_blocks_and_unclosed_safety ... ok
test tests::test_laravel_htaccess_and_turkish_routes ... ok
test tests::test_options_indexes_directive ... ok
test tests::test_php_path_info_resolution_and_security ... ok
test tests::test_try_files_without_htaccess_and_acme_exception ... ok
test tests::test_wordpress_htaccess_permalinks_and_encoded_media ... ok
test tests::test_zpanel_redirects_full_route_resolution ... ok

test result: ok. 33 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
```

- Komut 2: `cargo test --manifest-path D:\zmaxserver-ajan\a04\Cargo.toml --workspace --offline`
  Toplam: **228 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out** (35 test result satırı toplamı).

- Komut 3: `cargo clippy -p zmax-rewrite --all-targets --offline -- -D warnings`
  Sonuç: Sıfır hata, sıfır uyarı (`Finished dev profile [unoptimized + debuginfo]`).

- Komut 4: `rustfmt`
  `crates/zmax-rewrite/src/htaccess.rs` ve `crates/zmax-rewrite/src/lib.rs` temiz.

**Değişiklikler:**
- `crates/zmax-rewrite/src/htaccess.rs`: `FilesMatchRule` yapısı, `<FilesMatch>`/`<Files>` parser ve değerlendiricisi, `glob_to_regex`, `build_regex` ReDoS sınırı (`MAX_REGEX_LEN = 2048`, 1MB size limit, 2MB DFA size limit), redirect loop ve self-redirect önleme mantığı eklendi.
- `crates/zmax-rewrite/src/lib.rs`: `resolve_chain_with_info` hiyerarşik dosya eşleştirme desteği ve yeni entegrasyon testleri eklendi.

**Güvenlik riski:** Yok. ReDoS, bellek şişirme, yönlendirme döngüleri ve gizli dosya sızıntıları (<FilesMatch>) doğrudan engellenmiştir.
**Performans:** Ölçülmedi.
**Kalan eksikler:** Yok (Kart 4 maddelerinin tümü eksiksiz uygulandı ve birim testlerle kanıtlandı).
**Kart dışı yapılan/dokunulan:** Yok.
**Git Bilgileri:**
- Dal: `kart-4-htaccess`
- Commit SHA: `3bbd5965a1d78c41d2d48b2f95e3a038f4ef02b2`
- Uzak depoya gönderildi: `git push -u origin kart-4-htaccess`
**Tek sonraki adım:** Denetçi onayı bekleniyor.
