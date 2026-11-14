// ZMax WebAdmin - Canlı Loglar / Logs Görünümü
// U7 Bileşeni: Log görünümü, arama, filtreleme, durum kodları, canlı akış / SSE, duraklat/devam

(function (window) {
    'use strict';

    window.ZMaxViewLogs = {
        name: 'ViewLogs',
        props: {
            logs: {
                type: Array,
                required: true
            },
            vhosts: {
                type: Array,
                default: () => []
            },
            t: {
                type: Function,
                required: true
            }
        },
        emits: ['reopen-logs', 'show-notice', 'refresh-logs'],
        data() {
            return {
                searchLog: '',
                logDomainFilter: '',
                isPaused: false,
                isStreaming: false,
                streamSubscription: null,
                reopeningLogs: false,
                localLogs: []
            };
        },
        computed: {
            displayLogs() {
                const source = this.isStreaming ? this.localLogs : this.logs;
                let list = source;

                const domainFilter = this.logDomainFilter.trim().toLowerCase();
                if (domainFilter) {
                    list = list.filter((l) => !l.domain || l.domain.toLowerCase().includes(domainFilter));
                }

                const q = this.searchLog.trim().toLowerCase();
                if (!q) return list;

                return list.filter(
                    (l) =>
                        String(l.path || '').toLowerCase().includes(q) ||
                        String(l.ip || '').toLowerCase().includes(q) ||
                        String(l.domain || '').toLowerCase().includes(q) ||
                        String(l.status ?? '').includes(q)
                );
            }
        },
        methods: {
            togglePause() {
                this.isPaused = !this.isPaused;
            },
            toggleStream() {
                if (this.isStreaming) {
                    this.stopStream();
                } else {
                    this.startStream();
                }
            },
            startStream() {
                if (!window.ZMaxApiClient) return;
                this.isStreaming = true;
                this.localLogs = [...this.logs];
                this.streamSubscription = window.ZMaxApiClient.createLogsStream(
                    (logEntry) => {
                        if (!this.isPaused && logEntry) {
                            const normalized = {
                                time: logEntry.time || logEntry.timestamp || new Date().toLocaleTimeString(),
                                ip: logEntry.ip || logEntry.client_ip || '127.0.0.1',
                                domain: logEntry.domain || logEntry.host || '',
                                method: logEntry.method || 'GET',
                                path: logEntry.path || logEntry.uri || '/',
                                status: logEntry.status !== undefined ? logEntry.status : 200,
                                latency: logEntry.latency || (typeof logEntry.latency_ms === 'number' ? `${logEntry.latency_ms.toFixed(2)}ms` : '')
                            };
                            this.localLogs.unshift(normalized);
                            if (this.localLogs.length > 500) {
                                this.localLogs.pop();
                            }
                        }
                    },
                    () => {
                        this.stopStream();
                    }
                );
            },
            stopStream() {
                this.isStreaming = false;
                if (this.streamSubscription) {
                    this.streamSubscription.close();
                    this.streamSubscription = null;
                }
            },
            clearFilters() {
                this.searchLog = '';
                this.logDomainFilter = '';
                this.$emit('refresh-logs');
            },
            async triggerReopen() {
                if (this.reopeningLogs) return;
                this.reopeningLogs = true;
                try {
                    const res = await window.ZMaxApiClient.reopenLogs();
                    if (res && res.ok) {
                        this.$emit('show-notice', this.t('notice_logs_reopened'));
                        this.$emit('refresh-logs');
                    } else {
                        this.$emit('show-notice', this.t('notice_logs_reopen_error'));
                    }
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_logs_reopen_error'));
                } finally {
                    this.reopeningLogs = false;
                }
            },
            getStatusClass(status) {
                const s = Number(status);
                if (s >= 200 && s < 300) return 't-status-200';
                if (s >= 300 && s < 400) return 't-status-300';
                if (s >= 400 && s < 500) return 't-status-404';
                if (s >= 500) return 't-status-500';
                return 't-status-200';
            }
        },
        beforeUnmount() {
            this.stopStream();
        },
        template: `
            <div class="panel-card">
                <div class="panel-header">
                    <div>
                        <h3 class="panel-title">
                            <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>
                            <span>{{ t('logs_title') }}</span>
                        </h3>
                        <p class="panel-subtitle">{{ t('logs_desc') }}</p>
                    </div>
                    <div class="d-flex flex-wrap align-items-center gap-2">
                        <!-- Alan Adı Filtresi -->
                        <input
                            type="text"
                            list="zmax-log-domains"
                            v-model="logDomainFilter"
                            @change="$emit('refresh-logs', logDomainFilter)"
                            @keyup.enter="$emit('refresh-logs', logDomainFilter)"
                            :placeholder="t('logs_domain_placeholder')"
                            class="zmax-input zmax-input-sm"
                        >
                        <datalist id="zmax-log-domains">
                            <option v-for="vh in vhosts" :key="vh.domain" :value="vh.domain"></option>
                        </datalist>

                        <!-- Arama Kutusu -->
                        <input
                            type="text"
                            v-model="searchLog"
                            :placeholder="t('logs_filter_placeholder')"
                            class="zmax-input zmax-input-sm"
                        >

                        <!-- Duraklat / Devam Butonu -->
                        <button
                            type="button"
                            class="btn-zmax btn-ghost btn-sm-compact"
                            @click="togglePause"
                            :title="isPaused ? 'Akışı Sürdür' : 'Akışı Duraklat'"
                            :aria-label="isPaused ? 'Akışı Sürdür' : 'Akışı Duraklat'"
                        >
                            {{ isPaused ? '▶ Devam' : '⏸ Duraklat' }}
                        </button>

                        <!-- Filtreleri Temizle -->
                        <button
                            type="button"
                            class="btn-zmax btn-ghost btn-sm-compact"
                            @click="clearFilters"
                        >
                            {{ t('btn_clear') }}
                        </button>

                        <!-- Log Dosyalarını Yeniden Aç (Reopen) -->
                        <button
                            type="button"
                            class="btn-zmax btn-orange btn-sm-compact"
                            :disabled="reopeningLogs"
                            @click="triggerReopen"
                        >
                            {{ t('btn_reopen_logs') }}
                        </button>
                    </div>
                </div>

                <div class="terminal">
                    <div class="terminal-line" v-for="(l, i) in displayLogs" :key="i">
                        <span class="t-time">[{{ l.time }}]</span>
                        <span>{{ l.ip }}</span>
                        <strong class="text-orange">{{ l.method }}</strong>
                        <span class="t-path">{{ l.path }}</span>
                        <span :class="getStatusClass(l.status)">{{ l.status }} OK</span>
                        <span class="t-latency">{{ l.latency }}</span>
                    </div>
                    <div v-if="!displayLogs || displayLogs.length === 0" class="text-center text-muted-custom py-4">
                        Kayıt bulunamadı.
                    </div>
                </div>
            </div>
        `
    };
})(window);
