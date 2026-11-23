# VM test talimatları (sahip, 2026-11-14) — durum işaretli
Yapıldı = kodlandı+doğrulandı; AÇIK = yapılmadı/doğrulanmadı.

| # | Talimat | Durum |
|---|---|---|
| 1 | ZMax tek ana sunucu; OpenLiteSpeed (lsws) kapalı kalacak, bu süreçte litespeed sıfır işlem yapacak, ona dokunulmayacak | Yapıldı (lsws inactive; `disable` yapılmadı, onay bekliyor) |
| 2 | ZMax ayağa kalksın; panel (8026/8036/8047/8056) ZMax üzerinden çalışsın | Yapıldı (ek dinleyiciler, 200) |
| 3 | Her şeyi kontrol et: webmail, MySQL, hepsi ZMax üzerinden çalışıyor mu | KISMEN: webmail arka ucu (8045) çalışmıyor, phpMyAdmin yolu 404, php82/84/85 failed |
| 4 | Paneli kullanıcının tarayıcısı (Chrome) üzerinden test et, her şey sağlıklı çalışacak | KISMEN: açılış sayfaları + Servis Planı ekle/düzenle/sil geçti; uzantı "Yükle" çalışmadı |
| 5 | Tüm işlevler/işlemler, menü/buton/sekme atlanmadan: ekleme-silme-düzenleme, uzantı ekle/kaldır, yan menüde göster/kaldır, ince ayrıntısına kadar | AÇIK (müşteri, satıcı, abonelik, alan adı, /tools ~60 sayfa, sekmeler yapılmadı) |
| 6 | Hata/bug olmayacak; panelde sıfır hata (hata çıkarsa sahip çok kızacak) | AÇIK |
| 7 | Tüm hataları .md'ye yaz, sonra düzelt, güncelle, paketle | md: VM-TEST-1.0.08.md yazıldı; ZMax düzeltmeleri commit 06af0db (token logu, ban audit); izin/panel hataları, güncelleme, paket AÇIK |
| 8 | Hatalar çözüldükten SONRA tüm yapılar/toolkitler denenecek: Laravel, WordPress, Node, Composer, Docker ve tüm toolkitler; önce hata, sonra toolkitler; eksiksiz | AÇIK |
| 9 | ZMax yapısı her toolkit ile uyumlu, çalışır durumda olmalı | AÇIK |
| 10 | Parola/anahtar/token hiçbir dosyaya/rapora yazılmaz; yalnız yerel VM, canlıya dokunma yok | Uygulanıyor |
| 11 | Hatalar bitince yeniden test sırası: önce panel, sonra ZMax Go–Rust uyumluluğu, en son güvenlik testleri (Geliştirmenotu.md bölüm 9) | AÇIK |
| 12 | LSPHP: 8.2–8.5, her birinde mbstring, opcache, intl, gd, bcmath, pgsql, redis, imagick, ldap, memcached, imap, soap standart; Node 20/22/24/26; Docker; Composer; pm2 (gereksinim.md); Java eklenmeyecek | VM'de kuruldu; kurulum betiğine işlenmedi |
| 13 | Kalan hatalar bitince yalnız NOT al (yeniden test başlatma; test sırası satır 11, sahip "başla" diyene kadar) | Uygulanıyor |
