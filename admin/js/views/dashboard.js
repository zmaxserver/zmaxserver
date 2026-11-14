// ZMax WebAdmin - Genel Bakış / Dashboard Görünümü
// U4 Bileşeni: Durum kartları (RPS, bellek, FD, süre, CPU, servis durumları)

(function (window) {
    'use strict';

    window.ZMaxViewDashboard = {
        name: 'ViewDashboard',
        props: {
            stats: {
                type: Object,
                required: true
            },
            vhostsCount: {
                type: Number,
                default: 0
            },
            hitRate: {
                type: [String, Number],
                default: '0'
            },
            formattedUptime: {
                type: String,
                default: '0s 0d 0sn'
            },
            t: {
                type: Function,
                required: true
            }
        },
        emits: ['fetch-status', 'purge-all-cache'],
        template: `
            <div>
                <!-- Karşılama Kartı -->
                <div class="welcome-banner">
                    <div class="welcome-info">
                        <div class="welcome-avatar">
                            <svg class="icon icon-lg" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path>
                                <polyline points="9 22 9 12 15 12 15 22"></polyline>
                            </svg>
                        </div>
                        <div>
                            <div class="welcome-title">{{ t('welcome_title') }}</div>
                            <div class="welcome-meta">
                                panel.zmaxserver.local · {{ t('card_uptime') }}: {{ formattedUptime }}
                            </div>
                        </div>
                    </div>
                    <div class="welcome-actions">
                        <button type="button" class="btn-zmax btn-ghost" @click="$emit('fetch-status')">
                            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polyline points="23 4 23 10 17 10"></polyline>
                                <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"></path>
                            </svg>
                            {{ t('btn_reload') }}
                        </button>
                        <button type="button" class="btn-zmax btn-orange" @click="$emit('purge-all-cache')">
                            <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                            </svg>
                            {{ t('cache_purge_btn') }}
                        </button>
                    </div>
                </div>

                <!-- Özet Kartları (Bootstrap Grid) -->
                <div class="row g-3 mb-4">
                    <div class="col-12 col-sm-6 col-md-4 col-xl">
                        <div class="summary-card">
                            <div class="summary-icon">
                                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                            </div>
                            <div>
                                <div class="summary-label">{{ t('nav_vhosts') }}</div>
                                <div class="summary-val">{{ vhostsCount }}</div>
                            </div>
                        </div>
                    </div>

                    <div class="col-12 col-sm-6 col-md-4 col-xl">
                        <div class="summary-card">
                            <div class="summary-icon">
                                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                            </div>
                            <div>
                                <div class="summary-label">{{ t('card_cache_hit_rate') }}</div>
                                <div class="summary-val">{{ hitRate }}%</div>
                            </div>
                        </div>
                    </div>

                    <div class="col-12 col-sm-6 col-md-4 col-xl">
                        <div class="summary-card">
                            <div class="summary-icon">
                                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>
                            </div>
                            <div>
                                <div class="summary-label">{{ t('card_ram_usage') }}</div>
                                <div class="summary-val">{{ stats.ram_mb }} MB</div>
                            </div>
                        </div>
                    </div>

                    <div class="col-12 col-sm-6 col-md-6 col-xl">
                        <div class="summary-card">
                            <div class="summary-icon">
                                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
                            </div>
                            <div>
                                <div class="summary-label">{{ t('card_total_req') }}</div>
                                <div class="summary-val">{{ stats.total_requests }}</div>
                            </div>
                        </div>
                    </div>

                    <div class="col-12 col-sm-12 col-md-6 col-xl">
                        <div class="summary-card">
                            <div class="summary-icon">
                                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>
                            </div>
                            <div>
                                <div class="summary-label">{{ t('card_workers') }}</div>
                                <div class="summary-val">{{ stats.workers }}</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- İki Sütunlu Panel (Sunucu Durumu & Hizmet Durumları) -->
                <div class="row g-3 mb-4">
                    <!-- Sol: Sunucu Durumu -->
                    <div class="col-12 col-xl-6">
                        <div class="panel-card mb-0">
                            <div class="panel-header">
                                <div class="panel-title">
                                    <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect><line x1="8" y1="21" x2="16" y2="21"></line><line x1="12" y1="17" x2="12" y2="21"></line></svg>
                                    <span>{{ t('server_status_title') }}</span>
                                </div>
                                <span class="status-capsule status-active">{{ t('status_stable') }}</span>
                            </div>

                            <div class="meter-row">
                                <div class="meter-header">
                                    <span class="label">{{ t('lbl_cpu') }} ({{ stats.workers }} vCPU {{ t('lbl_worker_unit') }})</span>
                                    <span class="val">{{ stats.cpu_usage }}%</span>
                                </div>
                                <progress class="zmax-progress" max="100" :value="stats.cpu_usage"></progress>
                            </div>

                            <div class="meter-row">
                                <div class="meter-header">
                                    <span class="label">{{ t('lbl_memory') }}</span>
                                    <span class="val">{{ stats.ram_mb }} MB / 256 MB</span>
                                </div>
                                <progress class="zmax-progress zmax-progress-green" max="100" value="5"></progress>
                            </div>

                            <div class="meter-row meter-row-last">
                                <div class="meter-header">
                                    <span class="label">{{ t('lbl_disk_cache') }}</span>
                                    <span class="val">0.2 GB / 20 GB</span>
                                </div>
                                <progress class="zmax-progress zmax-progress-yellow" max="100" value="2"></progress>
                            </div>

                            <div class="info-kv-list">
                                <div class="info-kv-row"><span class="text-muted-custom">{{ t('lbl_hostname') }}</span> <strong>zmaxserver.local</strong></div>
                                <div class="info-kv-row"><span class="text-muted-custom">{{ t('lbl_ip_port') }}</span> <strong>{{ stats.listeners && stats.listeners.http ? stats.listeners.http : '0.0.0.0:19480' }}</strong></div>
                                <div class="info-kv-row"><span class="text-muted-custom">{{ t('lbl_engine') }}</span> <strong>ZMax Server v{{ stats.version || '…' }} ({{ t('footer_engine') }})</strong></div>
                            </div>
                        </div>
                    </div>

                    <!-- Sağ: Hizmet Durumları -->
                    <div class="col-12 col-xl-6">
                        <div class="panel-card mb-0">
                            <div class="panel-header">
                                <div class="panel-title">
                                    <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                                    <span>{{ t('service_status_title') }}</span>
                                </div>
                                <span class="status-capsule status-active">{{ t('status_all_running') }}</span>
                            </div>

                            <div class="row g-2">
                                <div class="col-12 col-sm-6">
                                    <div class="service-item">
                                        <div class="service-info">
                                            <svg class="icon service-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                                            <div>
                                                <div class="service-name">{{ t('srv_web_core') }}</div>
                                                <div class="service-port">{{ t('th_port') }}: {{ stats.ports && stats.ports.http ? stats.ports.http : 19480 }}</div>
                                            </div>
                                        </div>
                                        <span class="status-capsule status-active">{{ t('status_running') }}</span>
                                    </div>
                                </div>

                                <div class="col-12 col-sm-6">
                                    <div class="service-item">
                                        <div class="service-info">
                                            <svg class="icon service-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                                            <div>
                                                <div class="service-name">{{ t('srv_webadmin') }}</div>
                                                <div class="service-port">{{ t('th_port') }}: {{ stats.ports && stats.ports.admin ? stats.ports.admin : 19485 }}</div>
                                            </div>
                                        </div>
                                        <span class="status-capsule status-active">{{ t('status_running') }}</span>
                                    </div>
                                </div>

                                <div class="col-12 col-sm-6">
                                    <div class="service-item">
                                        <div class="service-info">
                                            <svg class="icon service-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"></path><line x1="4" y1="22" x2="4" y2="15"></line></svg>
                                            <div>
                                                <div class="service-name">{{ t('srv_php') }}</div>
                                                <div class="service-port">127.0.0.1:9000</div>
                                            </div>
                                        </div>
                                        <span class="status-capsule status-active">{{ t('status_running') }}</span>
                                    </div>
                                </div>

                                <div class="col-12 col-sm-6">
                                    <div class="service-item">
                                        <div class="service-info">
                                            <svg class="icon service-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                                            <div>
                                                <div class="service-name">{{ t('srv_l1_cache') }}</div>
                                                <div class="service-port">{{ t('srv_pool') }}</div>
                                            </div>
                                        </div>
                                        <span class="status-capsule status-active">{{ t('status_running') }}</span>
                                    </div>
                                </div>

                                <div class="col-12 col-sm-6">
                                    <div class="service-item">
                                        <div class="service-info">
                                            <svg class="icon service-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                                            <div>
                                                <div class="service-name">{{ t('srv_waf') }}</div>
                                                <div class="service-port">Token Bucket</div>
                                            </div>
                                        </div>
                                        <span class="status-capsule status-active">{{ t('status_running') }}</span>
                                    </div>
                                </div>

                                <div class="col-12 col-sm-6">
                                    <div class="service-item">
                                        <div class="service-info">
                                            <svg class="icon service-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path></svg>
                                            <div>
                                                <div class="service-name">{{ t('srv_http3') }}</div>
                                                <div class="service-port">UDP: {{ stats.ports && stats.ports.https ? stats.ports.https : 19483 }}</div>
                                            </div>
                                        </div>
                                        <span class="status-capsule status-active">{{ t('status_running') }}</span>
                                    </div>
                                </div>

                                <div class="col-12 col-sm-6">
                                    <div class="service-item">
                                        <div class="service-info">
                                            <svg class="icon service-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                                            <div>
                                                <div class="service-name">{{ t('srv_compress') }}</div>
                                                <div class="service-port">{{ t('srv_compression_sub') }}</div>
                                            </div>
                                        </div>
                                        <span class="status-capsule status-active">{{ t('status_running') }}</span>
                                    </div>
                                </div>

                                <div class="col-12 col-sm-6">
                                    <div class="service-item">
                                        <div class="service-info">
                                            <svg class="icon service-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>
                                            <div>
                                                <div class="service-name">{{ t('srv_proxy') }}</div>
                                                <div class="service-port">WebSocket / Node</div>
                                            </div>
                                        </div>
                                        <span class="status-capsule status-active">{{ t('status_running') }}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `
    };
})(window);
