// ZMax WebAdmin - Uygulama Kökü (app.js)
// U3 Bileşeni: Vue 3 kökü, ekran yönlendirme, tema ve dil yönetimi, bileşen koordinasyonu

(function (window) {
    'use strict';

    const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

    const MODULE_CATEGORY_MAP = {
        mod_cache: 'perf',
        mod_security: 'sec',
        mod_fastcgi: 'proto',
        mod_rewrite: 'route',
        mod_brotli: 'perf',
        mod_gzip: 'perf',
        mod_ssl: 'sec',
        mod_quic: 'proto',
        mod_proxy: 'net',
        mod_static: 'core',
        mod_headers: 'sec',
        mod_realip: 'net',
        mod_pagespeed: 'perf',
        mod_geoip: 'sec',
        mod_redis: 'perf',
        mod_coreruleset: 'sec',
        mod_autoindex: 'core',
        mod_acme: 'sec'
    };

    const VALID_MODULE_CATEGORIES = new Set(['core', 'perf', 'sec', 'proto', 'net', 'route']);

    const app = createApp({
        setup() {
            // --- Durum ve Yönlendirme ---
            const currentTab = ref('overview');
            const theme = ref(localStorage.getItem('zmax_theme') || 'dark');
            const currentLang = ref(localStorage.getItem('zmax_lang') || 'tr');
            const mobileMenuOpen = ref(false);
            const notification = ref('');
            let noticeTimer = null;
            let pollTimer = null;

            // --- i18n & Dil ---
            const availableLanguages = window.ZMaxI18n
                ? window.ZMaxI18n.languages
                : [
                      { code: 'tr', label: 'Türkçe', flag: '🇹🇷' },
                      { code: 'en', label: 'English', flag: '🇬🇧' },
                      { code: 'de', label: 'Deutsch', flag: '🇩🇪' },
                      { code: 'fr', label: 'Français', flag: '🇫🇷' },
                      { code: 'ru', label: 'Русский', flag: '🇷🇺' }
                  ];

            const t = (key) => {
                if (window.ZMaxI18n) {
                    return window.ZMaxI18n.get(currentLang.value, key);
                }
                return key;
            };

            const hasI18nKey = (key) => {
                if (!key || !window.ZMaxI18n || !window.ZMaxI18n.translations) return false;
                const trans = window.ZMaxI18n.translations;
                const dict = trans[currentLang.value] || trans.tr;
                return Boolean((dict && dict[key]) || (trans.tr && trans.tr[key]));
            };

            const showNotice = (msg) => {
                notification.value = msg;
                if (noticeTimer) clearTimeout(noticeTimer);
                noticeTimer = setTimeout(() => {
                    notification.value = '';
                }, 3500);
            };

            const syncDocumentTitleAndLang = (code) => {
                document.documentElement.setAttribute('lang', code);
                document.title = t('page_title');
            };

            const setLang = (code) => {
                currentLang.value = code;
                localStorage.setItem('zmax_lang', code);
                syncDocumentTitleAndLang(code);
                const langObj = availableLanguages.find((l) => l.code === code);
                showNotice(`${langObj ? langObj.label : code} — ${t('notice_lang_changed')}`);
            };

            const toggleTheme = () => {
                theme.value = theme.value === 'light' ? 'dark' : 'light';
                localStorage.setItem('zmax_theme', theme.value);
                document.documentElement.setAttribute('data-theme', theme.value);
            };

            const selectTab = (tab) => {
                currentTab.value = tab;
                mobileMenuOpen.value = false;
            };

            const toggleMobileMenu = () => {
                mobileMenuOpen.value = !mobileMenuOpen.value;
            };

            const closeMobileMenu = () => {
                mobileMenuOpen.value = false;
            };

            // --- API Token & Oturum Durumu ---
            const isAuthModalOpen = ref(false);
            const authTokenInput = ref('');
            const authShowPassword = ref(false);
            const authLoading = ref(false);
            const authError = ref('');
            const activeToken = ref(window.ZMaxApiClient.getToken());
            const hasActiveToken = computed(() => Boolean(activeToken.value.trim()));

            const openAuthModal = () => {
                authTokenInput.value = window.ZMaxApiClient.getToken();
                authError.value = '';
                authShowPassword.value = false;
                isAuthModalOpen.value = true;
            };

            const closeAuthModal = () => {
                isAuthModalOpen.value = false;
                authError.value = '';
            };

            const loginWithToken = async (customToken) => {
                const tokenToUse = (typeof customToken === 'string' ? customToken : authTokenInput.value).trim();
                if (!tokenToUse) {
                    authError.value = t('auth_token_empty');
                    return;
                }
                authLoading.value = true;
                authError.value = '';
                try {
                    const valid = await window.ZMaxApiClient.validateToken(tokenToUse);
                    if (valid) {
                        window.ZMaxApiClient.setToken(tokenToUse);
                        activeToken.value = tokenToUse;
                        isAuthModalOpen.value = false;
                        authError.value = '';
                        showNotice(t('notice_auth_success'));
                        await fetchStatus();
                    } else {
                        authError.value = t('notice_auth_invalid');
                    }
                } catch (_) {
                    authError.value = t('notice_auth_invalid');
                } finally {
                    authLoading.value = false;
                }
            };

            const logoutToken = () => {
                window.ZMaxApiClient.clearToken();
                activeToken.value = '';
                authTokenInput.value = '';
                authError.value = '';
                isAuthModalOpen.value = false;
                showNotice(t('notice_auth_logout'));
            };

            // 401 Unauthorized dinleyicisi
            window.ZMaxApiClient.setUnauthorizedHandler(() => {
                isAuthModalOpen.value = true;
                authError.value = t('auth_unauthorized');
            });

            // --- Model Verileri ---
            const stats = ref({
                uptime_seconds: 0,
                total_requests: 0,
                cache_hits: 0,
                cache_misses: 0,
                workers: 0,
                ram_mb: 0,
                cpu_usage: 0,
                current_rps: 0,
                ports: {
                    http: 19480,
                    https: 19483,
                    admin: 19485,
                    api: 19486
                },
                listeners: {
                    http: '0.0.0.0:19480',
                    https: '0.0.0.0:19483',
                    admin: '127.0.0.1:19485',
                    api: '127.0.0.1:19486'
                }
            });

            const vhosts = ref([]);
            const modules = ref([]);
            const bannedIps = ref([]);
            const logs = ref([]);
            const globalSearch = ref('');

            const selectedModuleCategory = ref('all');
            const moduleCategories = [
                { key: 'all', labelKey: 'cat_all' },
                { key: 'core', labelKey: 'cat_core' },
                { key: 'perf', labelKey: 'cat_perf' },
                { key: 'sec', labelKey: 'cat_sec' },
                { key: 'proto', labelKey: 'cat_proto' },
                { key: 'net', labelKey: 'cat_net' },
                { key: 'route', labelKey: 'cat_route' }
            ];

            // --- Hesaplanan Alanlar (Computed) ---
            const hitRate = computed(() => {
                const total = stats.value.total_requests;
                if (!total || total === 0) return 0;
                return ((stats.value.cache_hits / total) * 100).toFixed(1);
            });

            const formattedUptime = computed(() => {
                const sec = stats.value.uptime_seconds;
                const h = Math.floor(sec / 3600);
                const m = Math.floor((sec % 3600) / 60);
                const s = sec % 60;
                return `${h}${t('unit_h')} ${m}${t('unit_m')} ${s}${t('unit_s')}`;
            });

            const filteredVhosts = computed(() => {
                if (!globalSearch.value.trim()) return vhosts.value;
                const q = globalSearch.value.toLowerCase();
                return vhosts.value.filter(
                    (v) =>
                        String(v.domain || '').toLowerCase().includes(q) ||
                        String(v.doc_root || '').toLowerCase().includes(q) ||
                        String(v.php_sapi || '').toLowerCase().includes(q)
                );
            });

            const filteredModules = computed(() => {
                let list = modules.value;
                if (selectedModuleCategory.value !== 'all') {
                    list = list.filter((m) => m.categoryKey === selectedModuleCategory.value);
                }
                if (globalSearch.value.trim()) {
                    const q = globalSearch.value.toLowerCase();
                    list = list.filter(
                        (m) =>
                            t(m.name + '_title').toLowerCase().includes(q) ||
                            t(m.name + '_desc').toLowerCase().includes(q) ||
                            String(m.file || '').toLowerCase().includes(q)
                    );
                }
                return list;
            });

            // --- Normalizasyon Yardımcıları ---
            const normalizeIpArray = (val) => {
                if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
                if (typeof val === 'string') return val.split(',').map((x) => x.trim()).filter(Boolean);
                return [];
            };

            const extractArray = (payload, keys) => {
                if (Array.isArray(payload)) return payload;
                if (!payload || typeof payload !== 'object') return null;
                for (const key of keys) {
                    if (Array.isArray(payload[key])) return payload[key];
                }
                return null;
            };

            const normalizeModuleEntry = (m, existingByName) => {
                const rawName = String((m && m.name) || '').trim();
                const rawFile = String((m && (m.file || m.path)) || '').trim();
                const name = rawName || rawFile.replace(/^.*[\\/]/, '').replace(/\.toml$/i, '');
                const prev = existingByName.get(name);
                const rawCat = String((m && (m.categoryKey || m.category_key || m.category)) || '').trim();
                const categoryKey = VALID_MODULE_CATEGORIES.has(rawCat)
                    ? rawCat
                    : (MODULE_CATEGORY_MAP[name] || (prev && prev.categoryKey) || 'core');
                const file = rawFile || (prev && prev.file) || (name ? `modules/${name}.toml` : '');
                const enabled = typeof (m && m.enabled) === 'boolean' ? m.enabled : true;
                return { name, categoryKey, file, enabled };
            };

            const resolveBanReasonKey = (reasonKey, reason) => {
                if (reasonKey && hasI18nKey(reasonKey)) {
                    return reasonKey;
                }
                const tokenCandidate = String(reasonKey || reason || '').trim().toLowerCase();
                if (tokenCandidate && !tokenCandidate.includes(' ')) {
                    if (tokenCandidate.includes('slowloris')) return 'reason_slowloris';
                    if (tokenCandidate.includes('rate') || tokenCandidate.includes('limit')) return 'reason_ratelimit';
                    if (tokenCandidate.includes('brute')) return 'reason_bruteforce';
                    if (tokenCandidate === 'waf' || tokenCandidate === 'reason_waf') return 'reason_waf';
                }
                if (reason) return String(reason);
                return reasonKey ? String(reasonKey) : 'reason_waf';
            };

            const normalizeBanEntry = (b) => {
                const ip = String((b && b.ip) || '').trim();
                const reason = String((b && b.reason) || '').trim();
                const reasonKey = resolveBanReasonKey(b && b.reasonKey, reason);
                const time = String((b && (b.time || b.banned_at)) || '').trim();
                return { ip, reasonKey, reason, time };
            };

            const normalizeLogEntry = (l) => {
                const latency =
                    l && l.latency !== undefined && l.latency !== null
                        ? String(l.latency)
                        : (l && typeof l.latency_ms === 'number' ? `${l.latency_ms.toFixed(2)}ms` : '');
                return {
                    time: String((l && (l.time || l.timestamp)) || ''),
                    ip: String((l && (l.ip || l.client_ip)) || ''),
                    domain: String((l && (l.domain || l.host)) || ''),
                    method: String((l && l.method) || 'GET'),
                    path: String((l && (l.path || l.uri)) || '/'),
                    status: l && l.status !== undefined && l.status !== null ? l.status : 200,
                    latency
                };
            };

            // --- API Veri Çekme ---
            const fetchLogs = async (domain = '') => {
                try {
                    const logData = await window.ZMaxApiClient.getLogs(domain);
                    if (!logData) return;
                    const logList = extractArray(logData, ['logs', 'entries']);
                    if (logList !== null) {
                        logs.value = logList.map(normalizeLogEntry);
                    }
                } catch (_) {}
            };

            const fetchStatus = async () => {
                try {
                    const [statusData, vhData, modData, banData, logData] = await Promise.all([
                        window.ZMaxApiClient.getStatus(),
                        window.ZMaxApiClient.getVhosts(),
                        window.ZMaxApiClient.getModules(),
                        window.ZMaxApiClient.getBans(),
                        window.ZMaxApiClient.getLogs()
                    ]);

                    if (statusData) {
                        if (typeof statusData.uptime_seconds === 'number') stats.value.uptime_seconds = statusData.uptime_seconds;
                        if (typeof statusData.total_requests === 'number') stats.value.total_requests = statusData.total_requests;
                        if (typeof statusData.cache_hits === 'number') stats.value.cache_hits = statusData.cache_hits;
                        if (typeof statusData.cache_misses === 'number') stats.value.cache_misses = statusData.cache_misses;
                        if (typeof statusData.workers === 'number') stats.value.workers = statusData.workers;
                        if (typeof statusData.ram_mb === 'number') stats.value.ram_mb = statusData.ram_mb;
                        if (typeof statusData.cpu_usage === 'number') stats.value.cpu_usage = statusData.cpu_usage;
                        if (typeof statusData.current_rps === 'number') stats.value.current_rps = statusData.current_rps;
                        if (statusData.ports) {
                            stats.value.ports = { ...stats.value.ports, ...statusData.ports };
                        }
                        if (statusData.listeners) {
                            stats.value.listeners = { ...stats.value.listeners, ...statusData.listeners };
                        }
                    }

                    const vhList = extractArray(vhData, ['vhosts']);
                    if (vhList !== null) {
                        const webPort = stats.value.ports.http || 19480;
                        vhosts.value = vhList.map((v, idx) => {
                            const domain = String(v.domain || v.name || '').trim();
                            const phpEnabled = Boolean(v.php_enabled ?? (v.php && v.php.enabled));
                            const phpSapiRaw = String(v.php_sapi || (v.php && v.php.sapi) || 'fastcgi');
                            const phpUpstreamRaw = String(v.php_upstream || (v.php && v.php.upstream) || '127.0.0.1:9000');
                            const sslEnabled = Boolean(v.ssl_enabled ?? (v.ssl && (v.ssl.enabled ?? Boolean(v.ssl.certificate))));
                            const cacheEnabled = Boolean(v.cache_enabled ?? (v.cache && v.cache.enabled));
                            const wafEnabled = Boolean(v.waf_enabled ?? (v.waf && v.waf.enabled));
                            const hotlinkProtection = Boolean(v.hotlink_protection);
                            const allowIps = normalizeIpArray(v.allow_ips);
                            const denyIps = normalizeIpArray(v.deny_ips);
                            const http2Enabled = Boolean(
                                v.tls && typeof v.tls.http2 === 'boolean'
                                    ? v.tls.http2
                                    : (typeof v.http2 === 'boolean' ? v.http2 : (typeof v.tls_http2 === 'boolean' ? v.tls_http2 : false))
                            );
                            const loggingEnabled = Boolean(
                                v.logging && typeof v.logging.enabled === 'boolean'
                                    ? v.logging.enabled
                                    : (typeof v.logging_enabled === 'boolean' ? v.logging_enabled : false)
                            );
                            const accessLog = String((v.logging && v.logging.access_log) || v.access_log || '');

                            return {
                                id: idx + 1,
                                domain,
                                port: webPort,
                                doc_root: v.document_root || '',
                                php_enabled: phpEnabled,
                                php_sapi_raw: phpSapiRaw,
                                php_upstream_raw: phpUpstreamRaw,
                                php_sapi: phpEnabled ? `${phpSapiRaw} (${phpUpstreamRaw})` : 'Static',
                                ssl_enabled: sslEnabled,
                                sslKey: sslEnabled ? null : 'status_none',
                                sslText: sslEnabled ? 'TLS 1.3' : '',
                                cache: cacheEnabled,
                                waf_enabled: wafEnabled,
                                hotlink_protection: hotlinkProtection,
                                allow_ips: allowIps,
                                deny_ips: denyIps,
                                http2: http2Enabled,
                                logging_enabled: loggingEnabled,
                                access_log: accessLog,
                                statusKey: 'status_active'
                            };
                        });
                    }

                    const modList = extractArray(modData, ['modules']);
                    if (modList !== null) {
                        const existingByName = new Map(modules.value.map((m) => [m.name, m]));
                        modules.value = modList
                            .map((m) => normalizeModuleEntry(m, existingByName))
                            .filter((m) => m.name);
                    }

                    const banList = extractArray(banData, ['bans', 'banned_ips']);
                    if (banList !== null) {
                        bannedIps.value = banList.map(normalizeBanEntry).filter((b) => b.ip);
                    }

                    const logList = extractArray(logData, ['logs', 'entries']);
                    if (logList !== null) {
                        logs.value = logList.map(normalizeLogEntry);
                    }
                } catch (_) {}
            };

            const onVhostDeleted = (domain) => {
                vhosts.value = vhosts.value.filter((v) => v.domain !== domain);
                fetchStatus();
            };

            const onUnbanIp = (ip) => {
                bannedIps.value = bannedIps.value.filter((b) => b.ip !== ip);
            };

            onMounted(() => {
                syncDocumentTitleAndLang(currentLang.value);
                document.documentElement.setAttribute('data-theme', theme.value);
                fetchStatus();
                pollTimer = setInterval(fetchStatus, 2000);
            });

            onUnmounted(() => {
                if (pollTimer) clearInterval(pollTimer);
                if (noticeTimer) clearTimeout(noticeTimer);
            });

            return {
                currentTab,
                theme,
                currentLang,
                availableLanguages,
                mobileMenuOpen,
                notification,
                globalSearch,
                stats,
                vhosts,
                filteredVhosts,
                modules,
                filteredModules,
                selectedModuleCategory,
                moduleCategories,
                bannedIps,
                logs,
                hitRate,
                formattedUptime,
                isAuthModalOpen,
                authTokenInput,
                authShowPassword,
                authLoading,
                authError,
                activeToken,
                hasActiveToken,
                selectTab,
                toggleTheme,
                setLang,
                t,
                toggleMobileMenu,
                closeMobileMenu,
                showNotice,
                openAuthModal,
                closeAuthModal,
                loginWithToken,
                logoutToken,
                fetchStatus,
                fetchLogs,
                onVhostDeleted,
                onUnbanIp
            };
        }
    });

    // Görünüm bileşenlerini kaydet
    if (window.ZMaxViewDashboard) app.component('view-dashboard', window.ZMaxViewDashboard);
    if (window.ZMaxViewVhosts) app.component('view-vhosts', window.ZMaxViewVhosts);
    if (window.ZMaxViewCacheWaf) app.component('view-cache-waf', window.ZMaxViewCacheWaf);
    if (window.ZMaxViewLogs) app.component('view-logs', window.ZMaxViewLogs);
    if (window.ZMaxViewModules) app.component('view-modules', window.ZMaxViewModules);
    if (window.ZMaxViewSettings) app.component('view-settings', window.ZMaxViewSettings);

    app.mount('#app');
    window.ZMaxApp = app;
})(window);
