// ZMax WebAdmin - Uygulama kabugu (U3): ortak durum, dil, sekmeler, gorunumlerin birlestirilmesi. core.js'den tasindi, davranis ayni.

const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

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
        fetch('api/version')
            .then((r) => (r.ok ? r.json() : null))
            .then((d) => {
                if (d && typeof d.version === 'string' && d.version) engineVersion.value = d.version;
            })
            .catch(() => {});
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

        const showNotice = (msg) => {
            notification.value = msg;
            if (noticeTimer) clearTimeout(noticeTimer);
            noticeTimer = setTimeout(() => {
                notification.value = '';
            }, 3500);
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

        const ctx = { ref, computed, t, hasI18nKey, currentTab, currentLang, mobileMenuOpen, engineVersion, stats, vhosts, modules, selectedModuleCategory, moduleCategories, globalSearch, bannedIps, logs, searchLog, logDomainFilter, reopeningLogs, notification, purgeUrlInput, showVhostModal, vhostModalMode, savingVhost, showNotice, normalizeBanEntry };
        const views = ['logs', 'dashboard', 'vhosts', 'cache_waf'].map((n) => window.ZMaxViews[n](ctx));
        const {filteredLogs, fetchLogsResponse, fetchLogs, reopenLogs, clearLogFilters, svcInput, svcView, svcSummaryText, svcHint, hitRate, formattedUptime, filteredModules, fetchStatus, filteredVhosts, vhostForm, openCreateVhostModal, openEditVhostModal, closeVhostModal, saveVhost, purgeAllCache, purgeSpecificUrl, unbanIp} = ctx;

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
            svcView,
            svcSummaryText,
            svcHint,
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
