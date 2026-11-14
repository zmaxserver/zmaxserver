// ZMax WebAdmin - Sanal sunucular (U5). core.js'den tasindi, davranis ayni.
(function () {
    window.ZMaxViews = window.ZMaxViews || {};
    window.ZMaxViews.vhosts = function (ctx) {
        const { ref, computed, t, hasI18nKey, currentTab, currentLang, mobileMenuOpen, engineVersion, stats, vhosts, modules, selectedModuleCategory, moduleCategories, globalSearch, bannedIps, logs, searchLog, logDomainFilter, reopeningLogs, notification, purgeUrlInput, showVhostModal, vhostModalMode, savingVhost, showNotice, normalizeBanEntry, filteredLogs, fetchLogsResponse, fetchLogs, reopenLogs, clearLogFilters, svcInput, svcView, svcSummaryText, svcHint, hitRate, formattedUptime, filteredModules, fetchStatus } = ctx;

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

        const exported = { filteredVhosts, vhostForm, openCreateVhostModal, openEditVhostModal, closeVhostModal, saveVhost };
        Object.assign(ctx, exported);
        return exported;
    };
})();
