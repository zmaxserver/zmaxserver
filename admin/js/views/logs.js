// ZMax WebAdmin - Gunlukler ekrani (U7). core.js'den tasindi, davranis ayni.
(function () {
    window.ZMaxViews = window.ZMaxViews || {};
    window.ZMaxViews.logs = function (ctx) {
        const { ref, computed, t, hasI18nKey, currentTab, currentLang, mobileMenuOpen, engineVersion, stats, vhosts, modules, selectedModuleCategory, moduleCategories, globalSearch, bannedIps, logs, searchLog, logDomainFilter, reopeningLogs, notification, purgeUrlInput, showVhostModal, vhostModalMode, savingVhost, showNotice, normalizeBanEntry } = ctx;

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

        const exported = { filteredLogs, fetchLogsResponse, fetchLogs, reopenLogs, clearLogFilters };
        Object.assign(ctx, exported);
        return exported;
    };
})();
