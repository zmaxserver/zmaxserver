const { createApp, ref, computed, onMounted, onUnmounted } = Vue;

createApp({
    setup() {
        const theme = ref(localStorage.getItem('zmax_theme') || 'light');
        const currentTab = ref('overview');
        const currentLang = ref(localStorage.getItem('zmax_lang') || 'tr');

        const availableLanguages = window.ZMaxI18n ? window.ZMaxI18n.languages : [
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

        const setLang = (code) => {
            currentLang.value = code;
            localStorage.setItem('zmax_lang', code);
            document.documentElement.setAttribute('lang', code);
            showNotice(`${availableLanguages.find(l => l.code === code)?.label || code} — ${t('notice_lang_changed')}`);
        };

        const stats = ref({
            uptime_seconds: 0,
            total_requests: 2480,
            cache_hits: 2150,
            cache_misses: 330,
            workers: 12,
            ram_mb: 12,
            cpu_usage: 1.2,
            current_rps: 54
        });

        const vhosts = ref([
            { id: 1, domain: 'localhost', port: 19480, doc_root: 'www/html', php_sapi: 'PHP 8.3 (127.0.0.1:9000)', ssl: 'Yok', cache: true, status: 'Aktif' },
            { id: 2, domain: 'zepanel.com', port: 19480, doc_root: 'www/zepanel', php_sapi: 'PHP 8.3 (127.0.0.1:9000)', ssl: 'TLS 1.3 Let\'s Encrypt', cache: true, status: 'Aktif' },
            { id: 3, domain: 'api.zepanel.local', port: 19480, doc_root: 'www/api', php_sapi: 'Node.js Proxy (:3000)', ssl: 'Yok', cache: false, status: 'Aktif' }
        ]);

        // Tüm 18 Çekirdek ve Genişletilmiş Sunucu Modülü (i18n dinamik anahtarlı)
        const modules = ref([
            { name: 'mod_cache', categoryKey: 'perf', file: 'modules/mod_cache.toml', enabled: true },
            { name: 'mod_security', categoryKey: 'sec', file: 'modules/mod_security.toml', enabled: true },
            { name: 'mod_fastcgi', categoryKey: 'proto', file: 'modules/mod_fastcgi.toml', enabled: true },
            { name: 'mod_rewrite', categoryKey: 'route', file: 'modules/mod_rewrite.toml', enabled: true },
            { name: 'mod_brotli', categoryKey: 'perf', file: 'modules/mod_brotli.toml', enabled: true },
            { name: 'mod_gzip', categoryKey: 'perf', file: 'modules/mod_gzip.toml', enabled: true },
            { name: 'mod_ssl', categoryKey: 'sec', file: 'modules/mod_ssl.toml', enabled: true },
            { name: 'mod_quic', categoryKey: 'proto', file: 'modules/mod_quic.toml', enabled: true },
            { name: 'mod_proxy', categoryKey: 'net', file: 'modules/mod_proxy.toml', enabled: true },
            { name: 'mod_static', categoryKey: 'core', file: 'modules/mod_static.toml', enabled: true },
            { name: 'mod_headers', categoryKey: 'sec', file: 'modules/mod_headers.toml', enabled: true },
            { name: 'mod_realip', categoryKey: 'net', file: 'modules/mod_realip.toml', enabled: true },
            { name: 'mod_pagespeed', categoryKey: 'perf', file: 'modules/mod_pagespeed.toml', enabled: true },
            { name: 'mod_geoip', categoryKey: 'sec', file: 'modules/mod_geoip.toml', enabled: true },
            { name: 'mod_redis', categoryKey: 'perf', file: 'modules/mod_redis.toml', enabled: true },
            { name: 'mod_coreruleset', categoryKey: 'sec', file: 'modules/mod_coreruleset.toml', enabled: true },
            { name: 'mod_autoindex', categoryKey: 'core', file: 'modules/mod_autoindex.toml', enabled: true },
            { name: 'mod_acme', categoryKey: 'sec', file: 'modules/mod_acme.toml', enabled: true }
        ]);

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

        const filteredModules = computed(() => {
            if (selectedModuleCategory.value === 'all') return modules.value;
            return modules.value.filter(m => m.categoryKey === selectedModuleCategory.value);
        });

        const bannedIps = ref([
            { ip: '185.220.101.5', reasonKey: 'reason_slowloris', time: '22:45' },
            { ip: '45.154.255.88', reasonKey: 'reason_ratelimit', time: '21:12' }
        ]);

        const logs = ref([
            { time: '23:20:19', ip: '127.0.0.1', method: 'GET', path: '/index.html', status: 200, latency: '0.04ms' },
            { time: '23:20:20', ip: '127.0.0.1', method: 'GET', path: '/admin/css/admin.css', status: 200, latency: '0.06ms' },
            { time: '23:20:20', ip: '127.0.0.1', method: 'GET', path: '/admin/js/vue.global.prod.js', status: 200, latency: '0.08ms' },
            { time: '23:20:21', ip: '127.0.0.1', method: 'GET', path: '/api/status', status: 200, latency: '0.03ms' }
        ]);

        const searchLog = ref('');
        const notification = ref('');
        const showNewVhostModal = ref(false);
        const newVhost = ref({ domain: '', port: 19480, doc_root: 'www/', php_sapi: 'PHP 8.3 (127.0.0.1:9000)' });
        const purgeUrlInput = ref('');
        let pollTimer = null;

        const toggleTheme = () => {
            theme.value = theme.value === 'light' ? 'dark' : 'light';
            localStorage.setItem('zmax_theme', theme.value);
            document.documentElement.setAttribute('data-theme', theme.value);
        };

        const showNotice = (msg) => {
            notification.value = msg;
            setTimeout(() => { notification.value = ''; }, 3500);
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
            return `${h}s ${m}d ${s}sn`;
        });

        const filteredLogs = computed(() => {
            if (!searchLog.value) return logs.value;
            const q = searchLog.value.toLowerCase();
            return logs.value.filter(l => l.path.toLowerCase().includes(q) || l.ip.includes(q) || String(l.status).includes(q));
        });

        const fetchStatus = async () => {
            try {
                const res = await fetch('api/status');
                if (res.ok) {
                    const data = await res.json();
                    stats.value.uptime_seconds = data.uptime_seconds;
                    stats.value.total_requests = data.total_requests;
                    stats.value.cache_hits = data.cache_hits;
                    stats.value.cache_misses = data.cache_misses;
                    stats.value.workers = data.workers;
                    stats.value.ram_mb = data.ram_mb;
                }
            } catch (e) {
                // Sessiz
            }
        };

        const purgeAllCache = async () => {
            try {
                const res = await fetch('api/purge', { method: 'POST' });
                const data = await res.json();
                showNotice(data.message || 'Önbellek başarıyla temizlendi.');
                fetchStatus();
            } catch (e) {
                showNotice('Önbellek temizlenirken hata oluştu.');
            }
        };

        const purgeSpecificUrl = () => {
            if (!purgeUrlInput.value) return;
            showNotice(`"${purgeUrlInput.value}" önbellek anahtarı temizlendi.`);
            purgeUrlInput.value = '';
        };

        const addNewVhost = () => {
            if (!newVhost.value.domain) return;
            vhosts.value.push({
                id: Date.now(),
                domain: newVhost.value.domain,
                port: newVhost.value.port,
                doc_root: newVhost.value.doc_root,
                php_sapi: newVhost.value.php_sapi,
                ssl: 'Yok',
                cache: true,
                status: 'Aktif'
            });
            showNotice(`${newVhost.value.domain} sanal konağı eklendi.`);
            showNewVhostModal.value = false;
            newVhost.value = { domain: '', port: 19480, doc_root: 'www/', php_sapi: 'PHP 8.3 (127.0.0.1:9000)' };
        };

        const removeVhost = (id) => {
            vhosts.value = vhosts.value.filter(v => v.id !== id);
            showNotice('Sanal konak silindi.');
        };

        const unbanIp = (ip) => {
            bannedIps.value = bannedIps.value.filter(b => b.ip !== ip);
            showNotice(`${ip} IP adresi engeli kaldırıldı.`);
        };

        onMounted(() => {
            document.documentElement.setAttribute('data-theme', theme.value);
            fetchStatus();
            pollTimer = setInterval(fetchStatus, 2000);
        });

        onUnmounted(() => {
            if (pollTimer) clearInterval(pollTimer);
        });

        return {
            theme,
            currentTab,
            stats,
            vhosts,
            modules,
            selectedModuleCategory,
            moduleCategories,
            filteredModules,
            bannedIps,
            logs,
            searchLog,
            notification,
            showNewVhostModal,
            newVhost,
            purgeUrlInput,
            hitRate,
            formattedUptime,
            filteredLogs,
            toggleTheme,
            showNotice,
            purgeAllCache,
            purgeSpecificUrl,
            addNewVhost,
            removeVhost,
            unbanIp,
            currentLang,
            availableLanguages,
            t,
            setLang
        };
    }
}).mount('#app');
