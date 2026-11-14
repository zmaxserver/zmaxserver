// ZMax WebAdmin - API istemcisi ve saf yardimcilar (U2). core.js'den tasindi, davranis ayni.

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

// <svc-status>
// Hizmet Durumları / Sunucu Durumu rozetlerini MEVCUT API verisinden hesaplayan saf fonksiyon.
// Kural: veri yoksa (token yok/401/hata) durum 'unknown' olur, ASLA 'running' sayılmaz.
// Durumlar: running | off (yapılandırmada kapalı) | warning | unknown | unsupported.
function computeServiceStatus(input) {
    const src = input || {};
    const st = src.status && typeof src.status === 'object' ? src.status : null;
    const vh = Array.isArray(src.vhosts) ? src.vhosts : null;
    const mods = Array.isArray(src.modules) ? src.modules : null;
    const noDataHint = src.hasToken ? 'svc_hint_api_error' : 'svc_hint_need_key';
    const LABEL = {
        running: 'status_running',
        off: 'status_off',
        warning: 'status_warning',
        unknown: 'status_unknown',
        unsupported: 'status_unsupported'
    };
    const CLS = {
        running: 'status-active',
        off: 'status-orange',
        warning: 'status-danger',
        unknown: 'status-unknown',
        unsupported: 'status-unknown'
    };
    const make = (state, hintKey) => ({ state, labelKey: LABEL[state], cls: CLS[state], hintKey: hintKey || '' });
    const noData = () => make('unknown', noDataHint);
    const modEnabled = (name) => {
        const m = mods.find((x) => x && x.name === name);
        return Boolean(m && m.enabled === true);
    };

    const rows = {};
    // Web Core: api/status "running"
    rows.web_core = !st ? noData()
        : (st.running === true ? make('running') : (st.running === false ? make('warning') : noData()));
    // WebAdmin: sayfa yüklendi (bu kod çalışıyor) + api/status erişilebilir
    rows.webadmin = st ? make('running') : noData();
    // PHP-FPM: canlı sağlık denetimi yok; hiçbir zaman "Çalışıyor" denmez
    rows.php = st ? make('unknown', 'svc_hint_no_probe') : noData();
    // L1 RAM önbellek: api/status cache.enabled
    rows.l1_cache = st && st.cache && typeof st.cache.enabled === 'boolean'
        ? make(st.cache.enabled ? 'running' : 'off') : noData();
    // WAF & DoS: security.rate_limit_enabled veya herhangi bir vHost waf_enabled
    const rate = st && st.security && typeof st.security.rate_limit_enabled === 'boolean'
        ? st.security.rate_limit_enabled : null;
    const vhWaf = vh ? vh.some((v) => v && v.waf_enabled === true) : null;
    rows.waf = (rate === true || vhWaf === true) ? make('running')
        : (rate === false && vhWaf === false ? make('off') : noData());
    // HTTP/3 & QUIC: ZMax'te yok
    rows.http3 = make('unsupported');
    // Brotli / Gzip: mod_brotli veya mod_gzip etkin
    rows.compress = !mods ? noData()
        : (modEnabled('mod_brotli') || modEnabled('mod_gzip') ? make('running') : make('off'));
    // Ters Proxy: mod_proxy etkin
    rows.proxy = !mods ? noData() : (modEnabled('mod_proxy') ? make('running') : make('off'));

    const counted = Object.keys(rows).filter((k) => rows[k].state !== 'unsupported');
    const total = counted.length;
    const count = (s) => counted.filter((k) => rows[k].state === s).length;
    const running = count('running');
    const unknown = count('unknown');
    const warning = count('warning');
    let summaryCls = 'status-orange';
    if (warning > 0) summaryCls = 'status-danger';
    else if (total > 0 && running === total) summaryCls = 'status-active';
    else if (running === 0) summaryCls = 'status-unknown';

    let overallState = 'unknown';
    if (st && (st.running === false || warning > 0)) overallState = 'warning';
    else if (st && st.running === true) overallState = 'stable';
    const overall = {
        state: overallState,
        labelKey: { stable: 'status_stable', warning: 'status_warning_caps', unknown: 'status_unknown_caps' }[overallState],
        cls: { stable: 'status-active', warning: 'status-danger', unknown: 'status-unknown' }[overallState]
    };
    return { rows, summary: { running, total, unknown, warning, cls: summaryCls }, overall };
}
// </svc-status>

const apiFetch = (url, options = {}) => {
    const token = (localStorage.getItem('zmax_api_token') || '').trim();
    if (!token) {
        return fetch(url, options);
    }
    const headers = new Headers(options.headers || {});
    headers.set('X-ZMax-Token', token);
    return fetch(url, { ...options, headers });
};

const normalizeIpArray = (val) => {
    if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
    if (typeof val === 'string') return val.split(',').map((x) => x.trim()).filter(Boolean);
    return [];
};

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
