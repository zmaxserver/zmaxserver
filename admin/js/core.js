// ZMax WebAdmin - Çekirdek Uygulama Motoru (core.js)
// Footer içinde yüklenir, Vue 3 + Bootstrap 5 + Çoklu Dil (i18n) Yönetimi

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

createApp({
    setup() {
        const currentTab = ref('overview');
        const currentLang = ref(localStorage.getItem('zmax_lang') || 'tr');
        const mobileMenuOpen = ref(false);

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

        const apiFetch = (url, options = {}) => {
            const token = (localStorage.getItem('zmax_api_token') || '').trim();
            if (!token) {
                return fetch(url, options);
            }
            const headers = new Headers(options.headers || {});
            headers.set('X-ZMax-Token', token);
            return fetch(url, { ...options, headers });
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

        const engineVersion = ref('…');
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

        const globalSearch = ref('');

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

        const bannedIps = ref([]);
        const logs = ref([]);

        const searchLog = ref('');
        const logDomainFilter = ref('');
        const reopeningLogs = ref(false);
        const notification = ref('');
        const purgeUrlInput = ref('');
        const showVhostModal = ref(false);
        const vhostModalMode = ref('create');
        const savingVhost = ref(false);
        let pollTimer = null;
        let noticeTimer = null;

        const createEmptyVhostForm = () => ({
            domain: '',
            document_root: '',
            php_enabled: true,
            php_sapi: 'fastcgi',
            php_upstream: '127.0.0.1:9000',
            cache_enabled: true,
            ssl_enabled: false,
            tls_http2: true,
            waf_enabled: true,
            hotlink_protection: false,
            allow_ips: '',
            deny_ips: '',
            logging_enabled: false,
            logging_access_log: ''
        });
        const vhostForm = ref(createEmptyVhostForm());

        const normalizeIpArray = (val) => {
            if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
            if (typeof val === 'string') return val.split(',').map((x) => x.trim()).filter(Boolean);
            return [];
        };

        const showNotice = (msg) => {
            notification.value = msg;
            if (noticeTimer) clearTimeout(noticeTimer);
            noticeTimer = setTimeout(() => {
                notification.value = '';
            }, 3500);
        };

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

        const filteredLogs = computed(() => {
            let list = logs.value;
            const domainFilter = logDomainFilter.value.trim().toLowerCase();
            if (domainFilter) {
                list = list.filter((l) => !l.domain || l.domain.toLowerCase().includes(domainFilter));
            }
            const q = (searchLog.value || globalSearch.value).trim().toLowerCase();
            if (!q) return list;
            return list.filter(
                (l) =>
                    String(l.path || '').toLowerCase().includes(q) ||
                    String(l.ip || '').toLowerCase().includes(q) ||
                    String(l.domain || '').toLowerCase().includes(q) ||
                    String(l.status ?? '').includes(q)
            );
        });

        const readSettledJson = async (settled) => {
            if (settled.status !== 'fulfilled' || !settled.value.ok) return null;
            try {
                return await settled.value.json();
            } catch (_) {
                return null;
            }
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

        const extractArray = (payload, keys) => {
            if (Array.isArray(payload)) return payload;
            if (!payload || typeof payload !== 'object') return null;
            for (const key of keys) {
                if (Array.isArray(payload[key])) return payload[key];
            }
            return null;
        };

        const buildLogsUrl = (prefix = 'api/v1/logs') => {
            const domain = logDomainFilter.value.trim();
            return domain ? `${prefix}?domain=${encodeURIComponent(domain)}` : prefix;
        };

        const fetchLogsResponse = async () => {
            let res = await apiFetch(buildLogsUrl('api/v1/logs'));
            if (!res.ok && (res.status === 404 || res.status === 405)) {
                res = await apiFetch(buildLogsUrl('api/logs'));
            }
            return res;
        };

        const fetchLogs = async () => {
            try {
                const res = await fetchLogsResponse();
                if (!res.ok) return;
                const logData = await res.json();
                const logList = extractArray(logData, ['logs', 'entries']);
                if (logList !== null) {
                    logs.value = logList.map(normalizeLogEntry);
                }
            } catch (_) {
                // Günlük yenileme hatası sessiz geçilir
            }
        };

        const fetchStatus = async () => {
            try {
                const [statusRes, vhRes, modRes, banRes, logRes] = await Promise.allSettled([
                    apiFetch('api/status'),
                    apiFetch('api/v1/vhosts'),
                    apiFetch('api/v1/modules'),
                    apiFetch('api/v1/security/bans'),
                    fetchLogsResponse()
                ]);

                const [statusData, vhData, modData, banData, logData] = await Promise.all([
                    readSettledJson(statusRes),
                    readSettledJson(vhRes),
                    readSettledJson(modRes),
                    readSettledJson(banRes),
                    readSettledJson(logRes)
                ]);

                if (statusData) {
                    if (typeof statusData.version === 'string' && statusData.version) engineVersion.value = statusData.version;
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
            } catch (e) {
                // Arka plan anket hatası sessiz geçilir
            }
        };

        const openCreateVhostModal = () => {
            vhostModalMode.value = 'create';
            vhostForm.value = createEmptyVhostForm();
            showVhostModal.value = true;
        };

        const openEditVhostModal = (vh) => {
            vhostModalMode.value = 'edit';
            vhostForm.value = {
                domain: vh.domain || '',
                document_root: vh.doc_root || '',
                php_enabled: Boolean(vh.php_enabled),
                php_sapi: vh.php_sapi_raw || 'fastcgi',
                php_upstream: vh.php_upstream_raw || '127.0.0.1:9000',
                cache_enabled: Boolean(vh.cache),
                ssl_enabled: Boolean(vh.ssl_enabled),
                tls_http2: Boolean(vh.http2),
                waf_enabled: Boolean(vh.waf_enabled),
                hotlink_protection: Boolean(vh.hotlink_protection),
                allow_ips: Array.isArray(vh.allow_ips) ? vh.allow_ips.join(', ') : '',
                deny_ips: Array.isArray(vh.deny_ips) ? vh.deny_ips.join(', ') : '',
                logging_enabled: Boolean(vh.logging_enabled),
                logging_access_log: vh.access_log || (vh.domain ? `logs/${vh.domain}.access.log` : '')
            };
            showVhostModal.value = true;
        };

        const closeVhostModal = () => {
            showVhostModal.value = false;
        };

        const saveVhost = async () => {
            const domain = vhostForm.value.domain.trim().toLowerCase();
            if (!domain || savingVhost.value) return;
            savingVhost.value = true;
            const loggingEnabled = Boolean(vhostForm.value.logging_enabled);
            const accessLogInput = vhostForm.value.logging_access_log.trim();
            const payload = {
                domain,
                document_root: vhostForm.value.document_root.trim() || `www/${domain}`,
                php_enabled: Boolean(vhostForm.value.php_enabled),
                php_sapi: vhostForm.value.php_sapi.trim() || 'fastcgi',
                php_upstream: vhostForm.value.php_upstream.trim() || '127.0.0.1:9000',
                cache_enabled: Boolean(vhostForm.value.cache_enabled),
                ssl_enabled: Boolean(vhostForm.value.ssl_enabled),
                waf_enabled: Boolean(vhostForm.value.waf_enabled),
                hotlink_protection: Boolean(vhostForm.value.hotlink_protection),
                allow_ips: normalizeIpArray(vhostForm.value.allow_ips),
                deny_ips: normalizeIpArray(vhostForm.value.deny_ips),
                tls: {
                    http2: Boolean(vhostForm.value.tls_http2)
                },
                logging: {
                    enabled: loggingEnabled,
                    access_log: accessLogInput || (loggingEnabled ? `logs/${domain}.access.log` : '')
                }
            };
            const isEdit = vhostModalMode.value === 'edit';
            const primaryUrl = `api/v1/vhosts/${encodeURIComponent(domain)}`;
            const reqOpts = {
                method: isEdit ? 'PUT' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            };
            try {
                let res = await apiFetch(primaryUrl, reqOpts);
                if (!res.ok && (res.status === 404 || res.status === 405) && !isEdit) {
                    res = await apiFetch('api/v1/vhosts', reqOpts);
                } else if (!res.ok && res.status === 405 && isEdit) {
                    res = await apiFetch(primaryUrl, { ...reqOpts, method: 'POST' });
                }
                if (res.ok) {
                    showVhostModal.value = false;
                    showNotice(`${domain} — ${t(isEdit ? 'notice_vhost_updated' : 'notice_vhost_added')}`);
                    await fetchStatus();
                } else {
                    showNotice(t('notice_vhost_error'));
                }
            } catch (_) {
                showNotice(t('notice_vhost_error'));
            } finally {
                savingVhost.value = false;
            }
        };

        const reopenLogs = async () => {
            if (reopeningLogs.value) return;
            reopeningLogs.value = true;
            try {
                const res = await apiFetch('api/v1/logs/reopen', { method: 'POST' });
                if (res.ok) {
                    showNotice(t('notice_logs_reopened'));
                    await fetchLogs();
                } else {
                    showNotice(t('notice_logs_reopen_error'));
                }
            } catch (_) {
                showNotice(t('notice_logs_reopen_error'));
            } finally {
                reopeningLogs.value = false;
            }
        };

        const clearLogFilters = () => {
            searchLog.value = '';
            logDomainFilter.value = '';
            fetchLogs();
        };

        const purgeAllCache = async () => {
            try {
                const res = await apiFetch('api/purge', { method: 'POST' });
                if (res.ok) {
                    showNotice(t('notice_purged_all'));
                    fetchStatus();
                } else {
                    showNotice(t('notice_purge_error'));
                }
            } catch (e) {
                showNotice(t('notice_purge_error'));
            }
        };

        const purgeSpecificUrl = async () => {
            const key = purgeUrlInput.value.trim();
            if (!key) return;
            try {
                const res = await apiFetch('api/v1/cache/purge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ uri: key })
                });
                if (res.ok) {
                    showNotice(`${key} — ${t('notice_purged_url')}`);
                    purgeUrlInput.value = '';
                } else {
                    showNotice(t('notice_purge_error'));
                }
            } catch (e) {
                showNotice(t('notice_purge_error'));
            }
        };

        const unbanIp = async (ip) => {
            if (!ip) return;
            try {
                const res = await apiFetch('api/v1/security/unban', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip })
                });
                let data = null;
                try {
                    data = await res.json();
                } catch (_) {
                    data = null;
                }
                if (res.ok && (!data || data.ok !== false)) {
                    bannedIps.value = bannedIps.value.filter((b) => b.ip !== ip);
                    showNotice(`${ip} — ${t('notice_unbanned')}`);
                    await fetchStatus();
                } else {
                    showNotice(t('notice_unban_error'));
                }
            } catch (e) {
                showNotice(t('notice_unban_error'));
            }
        };

        onMounted(() => {
            syncDocumentTitleAndLang(currentLang.value);
            fetchStatus();
            pollTimer = setInterval(fetchStatus, 2000);
        });

        onUnmounted(() => {
            if (pollTimer) clearInterval(pollTimer);
            if (noticeTimer) clearTimeout(noticeTimer);
        });

        return {
            currentTab,
            mobileMenuOpen,
            selectTab,
            toggleMobileMenu,
            closeMobileMenu,
            stats,
            engineVersion,
            vhosts,
            filteredVhosts,
            modules,
            selectedModuleCategory,
            moduleCategories,
            filteredModules,
            bannedIps,
            logs,
            searchLog,
            logDomainFilter,
            reopeningLogs,
            globalSearch,
            notification,
            purgeUrlInput,
            showVhostModal,
            vhostModalMode,
            savingVhost,
            vhostForm,
            hitRate,
            formattedUptime,
            filteredLogs,
            fetchStatus,
            fetchLogs,
            openCreateVhostModal,
            openEditVhostModal,
            closeVhostModal,
            saveVhost,
            reopenLogs,
            clearLogFilters,
            showNotice,
            purgeAllCache,
            purgeSpecificUrl,
            unbanIp,
            currentLang,
            availableLanguages,
            t,
            setLang
        };
    }
}).mount('#app');
