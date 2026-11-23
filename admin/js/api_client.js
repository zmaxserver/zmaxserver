// ZMax WebAdmin - API İstemcisi (api_client.js)
// U2 Bileşeni: Token yönetimi, 401 yakalama, SSE akışı ve tüm API çağrıları

(function (window) {
    'use strict';

    class ZMaxApiClient {
        constructor() {
            this.baseUrl = '';
            this.tokenStorageKey = 'zmax_api_token';
            this.activeToken = localStorage.getItem(this.tokenStorageKey) || '';
            this.onUnauthorizedCallback = null;
            this.checkUrlToken();
        }

        // URL'den token okuma ve adres çubuğunu temizleme
        checkUrlToken() {
            try {
                if (typeof window === 'undefined' || !window.location) return;
                const urlParams = new URLSearchParams(window.location.search);
                let queryToken = urlParams.get('token');
                let foundInHash = false;

                if (!queryToken && window.location.hash) {
                    const hashMatch = window.location.hash.match(/token=([a-zA-Z0-9_\-]+)/);
                    if (hashMatch && hashMatch[1]) {
                        queryToken = hashMatch[1];
                        foundInHash = true;
                    }
                }

                if (queryToken && queryToken.trim()) {
                    const cleanToken = queryToken.trim();
                    this.setToken(cleanToken);
                    urlParams.delete('token');
                    const newSearch = urlParams.toString();
                    let newHash = window.location.hash;
                    if (foundInHash) {
                        newHash = newHash.replace(/[#&]?token=[a-zA-Z0-9_\-]+/, '');
                        if (newHash === '#') newHash = '';
                    }
                    const newUrl = window.location.pathname + (newSearch ? '?' + newSearch : '') + newHash;
                    window.history.replaceState({}, document.title, newUrl);
                }
            } catch (_) {}
        }

        getToken() {
            return (localStorage.getItem(this.tokenStorageKey) || this.activeToken || '').trim();
        }

        setToken(token) {
            const clean = (token || '').trim();
            this.activeToken = clean;
            if (clean) {
                localStorage.setItem(this.tokenStorageKey, clean);
            } else {
                localStorage.removeItem(this.tokenStorageKey);
            }
        }

        clearToken() {
            this.setToken('');
        }

        hasToken() {
            return Boolean(this.getToken());
        }

        setUnauthorizedHandler(callback) {
            this.onUnauthorizedCallback = callback;
        }

        // Temel fetch çağrısı: Bearer + X-ZMax-Token ekler, 401 yakalar
        async fetch(url, options = {}) {
            const token = this.getToken();
            const headers = new Headers(options.headers || {});

            if (token) {
                headers.set('X-ZMax-Token', token);
                headers.set('Authorization', `Bearer ${token}`);
            }

            const cleanUrl = url.startsWith('/') ? url.slice(1) : url;

            try {
                const res = await window.fetch(cleanUrl, { ...options, headers });
                if (res.status === 401) {
                    if (typeof this.onUnauthorizedCallback === 'function') {
                        this.onUnauthorizedCallback({ url: cleanUrl, options });
                    }
                }
                return res;
            } catch (err) {
                throw err;
            }
        }

        async fetchJson(url, options = {}) {
            const res = await this.fetch(url, options);
            if (!res.ok) {
                return null;
            }
            try {
                return await res.json();
            } catch (_) {
                return null;
            }
        }

        // Oturum doğrulama (Öneri 3 / ZMX P0: Kimliksiz /health yerine yetkili /session/verify ve /status kullanımı)
        async validateToken(customToken) {
            const tokenToTest = (customToken || this.getToken()).trim();
            if (!tokenToTest) return false;

            const headers = new Headers();
            headers.set('X-ZMax-Token', tokenToTest);
            headers.set('Authorization', `Bearer ${tokenToTest}`);

            try {
                let res = await window.fetch('api/v1/session/verify', { headers });
                if (res.status === 404 || res.status === 405) {
                    res = await window.fetch('api/v1/status', { headers });
                }
                return res.ok;
            } catch (_) {
                return false;
            }
        }

        // /api/v1/... Rotaları
        async getHealth() {
            return this.fetchJson('api/v1/health');
        }

        async getStatus() {
            let data = await this.fetchJson('api/v1/status');
            if (!data) {
                data = await this.fetchJson('api/status');
            }
            return data;
        }

        async getVhosts() {
            return this.fetchJson('api/v1/vhosts');
        }

        async saveVhost(domain, payload, isEdit = false) {
            const cleanDomain = encodeURIComponent(domain.trim().toLowerCase());
            const primaryUrl = `api/v1/vhosts/${cleanDomain}`;
            const reqOpts = {
                method: isEdit ? 'PUT' : 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            };

            let res = await this.fetch(primaryUrl, reqOpts);
            if (!res.ok && (res.status === 404 || res.status === 405) && !isEdit) {
                res = await this.fetch('api/v1/vhosts', reqOpts);
            } else if (!res.ok && res.status === 405 && isEdit) {
                res = await this.fetch(primaryUrl, { ...reqOpts, method: 'POST' });
            }
            return res;
        }

        async deleteVhost(domain) {
            const cleanDomain = encodeURIComponent(domain.trim().toLowerCase());
            return this.fetch(`api/v1/vhosts/${cleanDomain}`, { method: 'DELETE' });
        }

        async getModules() {
            return this.fetchJson('api/v1/modules');
        }

        async getBans() {
            return this.fetchJson('api/v1/security/bans');
        }

        async unbanIp(ip) {
            return this.fetch('api/v1/security/unban', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip })
            });
        }

        async purgeAll() {
            let res = await this.fetch('api/v1/cache/purge', { method: 'POST' });
            if (!res.ok && (res.status === 404 || res.status === 405)) {
                res = await this.fetch('api/purge', { method: 'POST' });
            }
            return res;
        }

        async purgeSpecific(payload) {
            const body = typeof payload === 'string' ? { uri: payload } : payload;
            let res = await this.fetch('api/v1/cache/purge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            if (!res.ok && (res.status === 404 || res.status === 405)) {
                res = await this.fetch('api/purge', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
            }
            return res;
        }

        async getLogs(domain = '') {
            const query = domain ? `?domain=${encodeURIComponent(domain)}` : '';
            let data = await this.fetchJson(`api/v1/logs${query}`);
            if (!data) {
                data = await this.fetchJson(`api/logs${query}`);
            }
            return data;
        }

        async reopenLogs() {
            return this.fetch('api/v1/logs/reopen', { method: 'POST' });
        }

        async gracefulReload() {
            let res = await this.fetch('api/v1/reload', { method: 'POST' });
            if (!res.ok && (res.status === 404 || res.status === 405)) {
                res = await this.fetch('api/reload', { method: 'POST' });
            }
            return res;
        }

        async getServerConfig() {
            return this.fetchJson('api/v1/config/server');
        }

        async saveServerConfig(payload) {
            return this.fetch('api/v1/config/server', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        }

        async getListeners() {
            return this.fetchJson('api/v1/listeners');
        }

        async saveListener(payload) {
            return this.fetch('api/v1/listeners', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        }

        async getLiveStats() {
            return this.fetchJson('api/v1/livestats');
        }

        // SSE Canlı Günlük Akışı Altyapısı (/api/v1/logs/stream) - Güvenli Başlık Modu
        createLogsStream(onMessage, onError) {
            const token = this.getToken();
            const abortController = new AbortController();
            let isClosed = false;

            // Fetch Streaming (Token'ı URL'ye yazmadan Authorization Header ile güvenli iletim)
            const startFetchStream = async () => {
                const headers = new Headers();
                if (token) {
                    headers.set('Authorization', `Bearer ${token}`);
                    headers.set('X-ZMax-Token', token);
                }
                headers.set('Accept', 'text/event-stream');

                try {
                    const response = await window.fetch('api/v1/logs/stream', {
                        headers,
                        signal: abortController.signal
                    });

                    if (!response.ok) {
                        throw new Error(`SSE Bağlantı Hatası: ${response.status}`);
                    }

                    const reader = response.body.getReader();
                    const decoder = new TextDecoder('utf-8');
                    let buffer = '';

                    while (!isClosed) {
                        const { done, value } = await reader.read();
                        if (done) break;
                        buffer += decoder.decode(value, { stream: true });
                        const lines = buffer.split('\n\n');
                        buffer = lines.pop() || '';

                        for (const block of lines) {
                            const trimmed = block.trim();
                            if (!trimmed || trimmed.startsWith(':')) continue; // Yorum/ping satırları
                            const dataLine = trimmed.split('\n').find((l) => l.startsWith('data:'));
                            if (dataLine) {
                                const jsonStr = dataLine.slice(5).trim();
                                if (typeof onMessage === 'function') {
                                    try {
                                        onMessage(JSON.parse(jsonStr));
                                    } catch (_) {
                                        onMessage(jsonStr);
                                    }
                                }
                            }
                        }
                    }
                } catch (err) {
                    if (!isClosed && err.name !== 'AbortError' && typeof onError === 'function') {
                        onError(err);
                    }
                }
            };

            startFetchStream();

            return {
                close: () => {
                    isClosed = true;
                    try {
                        abortController.abort();
                    } catch (_) {}
                }
            };
        }
    }

    window.ZMaxApiClient = new ZMaxApiClient();
})(window);
