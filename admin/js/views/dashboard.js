// ZMax WebAdmin - Genel bakis / hizmet durumu / moduller (U4). core.js'den tasindi, davranis ayni.
(function () {
    window.ZMaxViews = window.ZMaxViews || {};
    window.ZMaxViews.dashboard = function (ctx) {
        const { ref, computed, t, hasI18nKey, currentTab, currentLang, mobileMenuOpen, engineVersion, stats, vhosts, modules, selectedModuleCategory, moduleCategories, globalSearch, bannedIps, logs, searchLog, logDomainFilter, reopeningLogs, notification, purgeUrlInput, showVhostModal, vhostModalMode, savingVhost, showNotice, normalizeBanEntry, filteredLogs, fetchLogsResponse, fetchLogs, reopenLogs, clearLogFilters } = ctx;

            const svcInput = ref({ status: null, vhosts: null, modules: null, hasToken: false });
            const svcView = computed(() => computeServiceStatus(svcInput.value));
            const svcSummaryText = computed(() => {
                const s = svcView.value.summary;
                let txt = t('svc_summary_running').replace('{n}', String(s.running)).replace('{total}', String(s.total));
                if (s.unknown > 0) txt += ' · ' + t('svc_summary_unknown').replace('{n}', String(s.unknown));
                return txt;
            });
            const svcHint = (row) => (row && row.hintKey ? t(row.hintKey) : '');

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

                    // Hizmet durumu girdisi: alınamayan veri null kalır (eski veri "Çalışıyor" göstermesin)
                    svcInput.value = {
                        status: statusData,
                        vhosts: (() => {
                            const vl = extractArray(vhData, ['vhosts']);
                            return vl === null ? null : vl.map((v) => ({
                                waf_enabled: Boolean(v && (v.waf_enabled ?? (v.waf && v.waf.enabled)))
                            }));
                        })(),
                        modules: (() => {
                            const ml = extractArray(modData, ['modules']);
                            return ml === null ? null : ml.map((m) => ({
                                name: String((m && (m.name || '')) || '').trim(),
                                enabled: typeof (m && m.enabled) === 'boolean' ? m.enabled : true
                            }));
                        })(),
                        hasToken: Boolean((localStorage.getItem('zmax_api_token') || '').trim())
                    };

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
                    // Arka plan anket hatası: durum doğrulanamadı, eski veri tutulmaz
                    svcInput.value = { status: null, vhosts: null, modules: null, hasToken: svcInput.value.hasToken };
                }
            };

        const exported = { svcInput, svcView, svcSummaryText, svcHint, hitRate, formattedUptime, filteredModules, fetchStatus };
        Object.assign(ctx, exported);
        return exported;
    };
})();
