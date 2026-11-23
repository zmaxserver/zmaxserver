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

        // Oturum doğrulama
        async validateToken(customToken) {
            const tokenToTest = (customToken || this.getToken()).trim();
            if (!tokenToTest) return false;

            const headers = new Headers();
            headers.set('X-ZMax-Token', tokenToTest);
            headers.set('Authorization', `Bearer ${tokenToTest}`);

            try {
                const res = await window.fetch('api/v1/health', { headers });
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

        // SSE Canlı Günlük Akışı Altyapısı (/api/v1/logs/stream)
        createLogsStream(onMessage, onError) {
            const token = this.getToken();
            const url = `api/v1/logs/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`;
            let eventSource = null;

            try {
                eventSource = new EventSource(url);
                eventSource.onmessage = (event) => {
                    if (typeof onMessage === 'function') {
                        try {
                            const parsed = JSON.parse(event.data);
                            onMessage(parsed);
                        } catch (_) {
                            onMessage(event.data);
                        }
                    }
                };
                eventSource.onerror = (err) => {
                    if (typeof onError === 'function') {
                        onError(err);
                    }
                };
            } catch (err) {
                if (typeof onError === 'function') {
                    onError(err);
                }
            }

            return {
                close: () => {
                    if (eventSource) {
                        eventSource.close();
                        eventSource = null;
                    }
                }
            };
        }
    }

    window.ZMaxApiClient = new ZMaxApiClient();
})(window);
