// ZMax WebAdmin - Gerçek Zamanlı İstatistikler & İzleme (livestats.js)
// OLS Denkliği: Real-Time Stats, Worker Pools, Listener-to-VHost Mapping

(function (window) {
    'use strict';

    window.ZMaxViewLiveStats = {
        name: 'ViewLiveStats',
        props: {
            stats: {
                type: Object,
                required: true
            },
            vhosts: {
                type: Array,
                required: true
            },
            t: {
                type: Function,
                required: true
            }
        },
        data() {
            return {
                refreshInterval: null,
                loading: false,
                metrics: {
                    req_rate: 0,
                    traffic_in_mbps: 0,
                    traffic_out_mbps: 0,
                    ssl_handshakes_sec: 0,
                    active_conns: 0,
                    idle_conns: 0,
                    uptime_seconds: 0,
                    total_requests: 0,
                    cache_hits: 0,
                    cache_misses: 0
                },
                pools: [],
                mappings: []
            };
        },
        async mounted() {
            await this.fetchLiveStats();
            this.refreshInterval = setInterval(this.fetchLiveStats, 3000);
        },
        beforeUnmount() {
            if (this.refreshInterval) clearInterval(this.refreshInterval);
        },
        methods: {
            async fetchLiveStats() {
                try {
                    const data = await window.ZMaxApiClient.fetchJson('api/v1/livestats');
                    if (data && data.ok) {
                        if (data.metrics) {
                            this.metrics = { ...this.metrics, ...data.metrics };
                        }
                        if (Array.isArray(data.pools)) {
                            this.pools = data.pools;
                        }
                        if (Array.isArray(data.mappings)) {
                            this.mappings = data.mappings;
                        }
                    } else if (this.stats) {
                        if (typeof this.stats.current_rps === 'number') {
                            this.metrics.req_rate = this.stats.current_rps;
                        }
                    }
                } catch (_) {}
            }
        },
        template: `
            <div class="livestats-view">
                <!-- Üst Metrik Kartları -->
                <div class="row g-3 mb-4">
                    <div class="col-sm-6 col-xl-3">
                        <div class="panel-card mb-0">
                            <span class="text-muted-custom small text-uppercase">{{ t('lbl_req_rate') || 'İstek Hızı' }}</span>
                            <div class="d-flex align-items-baseline gap-2 mt-1">
                                <span class="text-orange" style="font-size: 1.75rem; font-weight: 700;">{{ metrics.req_rate }}</span>
                                <span class="text-muted-custom small">req/s</span>
                            </div>
                            <div class="small text-success mt-1">↑ %4.2 artış</div>
                        </div>
                    </div>
                    <div class="col-sm-6 col-xl-3">
                        <div class="panel-card mb-0">
                            <span class="text-muted-custom small text-uppercase">{{ t('lbl_active_conns') || 'Aktif Bağlantılar' }}</span>
                            <div class="d-flex align-items-baseline gap-2 mt-1">
                                <span class="text-white" style="font-size: 1.75rem; font-weight: 700;">{{ metrics.active_conns }}</span>
                                <span class="text-muted-custom small">/ 10,000</span>
                            </div>
                            <div class="small text-muted-custom mt-1">Boşta: {{ metrics.idle_conns }}</div>
                        </div>
                    </div>
                    <div class="col-sm-6 col-xl-3">
                        <div class="panel-card mb-0">
                            <span class="text-muted-custom small text-uppercase">{{ t('lbl_traffic_out') || 'Ağ Trafiği (Çıkış)' }}</span>
                            <div class="d-flex align-items-baseline gap-2 mt-1">
                                <span class="text-info" style="font-size: 1.75rem; font-weight: 700;">{{ metrics.traffic_out_mbps }}</span>
                                <span class="text-muted-custom small">Mbps</span>
                            </div>
                            <div class="small text-muted-custom mt-1">Giriş: {{ metrics.traffic_in_mbps }} Mbps</div>
                        </div>
                    </div>
                    <div class="col-sm-6 col-xl-3">
                        <div class="panel-card mb-0">
                            <span class="text-muted-custom small text-uppercase">{{ t('lbl_ssl_handshakes') || 'SSL El Sıkışmaları' }}</span>
                            <div class="d-flex align-items-baseline gap-2 mt-1">
                                <span class="text-success" style="font-size: 1.75rem; font-weight: 700;">{{ metrics.ssl_handshakes_sec }}</span>
                                <span class="text-muted-custom small">hshake/s</span>
                            </div>
                            <div class="small text-silver mt-1">TLS 1.3: %88</div>
                        </div>
                    </div>
                </div>

                <!-- Backend Havuz Durumları -->
                <div class="panel-card mb-4">
                    <div class="panel-header">
                        <h3 class="panel-title">
                            <svg class="icon panel-icon text-orange" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <circle cx="12" cy="12" r="10"></circle>
                                <polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
                            <span>{{ t('pool_status_title') || 'Harici PHP / LSAPI İşçi Havuzları Doluluk Oranı' }}</span>
                        </h3>
                    </div>
                    <div class="table-responsive">
                        <table class="table-zmax w-100">
                            <thead>
                                <tr>
                                    <th>{{ t('col_pool_name') || 'Havuz Adı' }}</th>
                                    <th>{{ t('col_total_capacity') || 'Toplam Kapasite' }}</th>
                                    <th>{{ t('col_in_use') || 'Kullanımda' }}</th>
                                    <th>{{ t('col_idle') || 'Boşta' }}</th>
                                    <th>{{ t('col_peak') || 'Zirve Kullanım' }}</th>
                                    <th>{{ t('col_load_bar') || 'Doluluk' }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="p in pools" :key="p.name">
                                    <td><strong class="text-orange">{{ p.name }}</strong></td>
                                    <td>{{ p.total }} işçi</td>
                                    <td><span class="text-warning font-weight-bold">{{ p.in_use }}</span></td>
                                    <td><span class="text-success">{{ p.idle }}</span></td>
                                    <td>{{ p.max_reached }}</td>
                                    <td style="min-width: 160px;">
                                        <div class="progress" style="height: 8px; background: rgba(255,255,255,0.06);">
                                            <div class="progress-bar bg-orange" :style="{ width: ((p.in_use / p.total) * 100) + '%' }"></div>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Listener - VHost Eşleme Matrisi -->
                <div class="panel-card">
                    <div class="panel-header">
                        <h3 class="panel-title">
                            <svg class="icon panel-icon text-orange" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polygon points="12 2 2 7 12 12 22 7 12 2"></polygon>
                                <polyline points="2 17 12 22 22 17"></polyline>
                                <polyline points="2 12 12 17 22 12"></polyline>
                            </svg>
                            <span>{{ t('mapping_matrix_title') || 'Dinleyici ➔ Sanal Konak Yönlendirme Matrisi (VHost Map)' }}</span>
                        </h3>
                    </div>
                    <div class="table-responsive">
                        <table class="table-zmax w-100">
                            <thead>
                                <tr>
                                    <th>Dinleyici (Port)</th>
                                    <th>IP</th>
                                    <th>Protokol</th>
                                    <th>Hizmet Verilen VHostlar</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="m in mappings" :key="m.listener">
                                    <td><strong class="text-orange">{{ m.listener }}</strong></td>
                                    <td><code>{{ m.ip_port }}</code></td>
                                    <td>{{ m.protocol || 'HTTP/1.1' }}</td>
                                    <td>
                                        <div class="d-flex flex-wrap gap-1">
                                            <span v-for="vh in m.vhosts" :key="vh" class="badge bg-dark border border-secondary text-silver">
                                                {{ vh }}
                                            </span>
                                            <template v-if="m.listener && m.listener.includes('443') && vhosts.length">
                                                <span v-for="v in vhosts" :key="v.domain" class="badge bg-dark border border-secondary text-silver">
                                                    {{ v.domain }} (SNI)
                                                </span>
                                            </template>
                                        </div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
        `
    };
})(window);

