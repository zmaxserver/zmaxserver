// ZMax WebAdmin - Onbellek ve WAF/yasak listesi (U6). core.js'den tasindi, davranis ayni.
(function () {
    window.ZMaxViews = window.ZMaxViews || {};
    window.ZMaxViews.cache_waf = function (ctx) {
        const { ref, computed, t, hasI18nKey, currentTab, currentLang, mobileMenuOpen, engineVersion, stats, vhosts, modules, selectedModuleCategory, moduleCategories, globalSearch, bannedIps, logs, searchLog, logDomainFilter, reopeningLogs, notification, purgeUrlInput, showVhostModal, vhostModalMode, savingVhost, showNotice, normalizeBanEntry, filteredLogs, fetchLogsResponse, fetchLogs, reopenLogs, clearLogFilters, svcInput, svcView, svcSummaryText, svcHint, hitRate, formattedUptime, filteredModules, fetchStatus, filteredVhosts, vhostForm, openCreateVhostModal, openEditVhostModal, closeVhostModal, saveVhost } = ctx;

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

        const exported = { purgeAllCache, purgeSpecificUrl, unbanIp };
        Object.assign(ctx, exported);
        return exported;
    };
})();
