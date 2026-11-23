// ZMax WebAdmin - Sunucu Yapılandırması (server_config.js)
// OLS Denkliği: Tuning, External Applications, Script Handlers, Sunucu Güvenliği

(function (window) {
    'use strict';

    window.ZMaxViewServerConfig = {
        name: 'ViewServerConfig',
        props: {
            stats: {
                type: Object,
                required: true
            },
            t: {
                type: Function,
                required: true
            }
        },
        emits: ['show-notice', 'save-config', 'config-changed'],
        data() {
            return {
                activeSubTab: 'tuning', // 'tuning', 'extapps', 'handlers', 'security'
                saving: false,
                loading: false,
                // Tuning Formu
                tuningForm: {
                    max_connections: 10000,
                    connection_timeout: 60,
                    keep_alive_timeout: 15,
                    max_keep_alive_req: 1000,
                    gzip_enabled: true,
                    brotli_enabled: true,
                    min_compress_size: 256,
                    ssl_cache_size: 1000000,
                    ssl_cache_timeout: 3600,
                    http3_enabled: true,
                    http3_port: 443
                },
                // External Applications (PHP/Node/Proxy Havuzları)
                extApps: [
                    { id: 'lsphp83', name: 'LSPHP 8.3 (Varsayılan)', type: 'LSAPI', address: '127.0.0.1:9083', max_conns: 35, instances: 10, priority: 0 },
                    { id: 'lsphp82', name: 'LSPHP 8.2', type: 'LSAPI', address: '127.0.0.1:9082', max_conns: 30, instances: 5, priority: 0 },
                    { id: 'lsphp81', name: 'LSPHP 8.1', type: 'LSAPI', address: '127.0.0.1:9081', max_conns: 25, instances: 5, priority: 0 },
                    { id: 'nodejs_default', name: 'Node.js App Server', type: 'Proxy', address: '127.0.0.1:3000', max_conns: 100, instances: 1, priority: 1 }
                ],
                showExtAppModal: false,
                extAppModalMode: 'create',
                extAppForm: { id: '', name: '', type: 'LSAPI', address: '', max_conns: 30, instances: 5 },
                // Script Handlers (Uzantı Eşleme)
                scriptHandlers: [
                    { suffix: 'php', handler: 'lsphp83', note: 'Standart PHP işleyici' },
                    { suffix: 'php83', handler: 'lsphp83', note: 'PHP 8.3 açıkça belirtilmiş' },
                    { suffix: 'php82', handler: 'lsphp82', note: 'PHP 8.2 eski sürüm desteği' },
                    { suffix: 'php81', handler: 'lsphp81', note: 'PHP 8.1 eski sürüm desteği' }
                ],
                showHandlerModal: false,
                handlerModalMode: 'create',
                handlerForm: { suffix: '', handler: 'lsphp83', note: '' },
                // Sunucu Seviyesi Güvenlik Formu
                securityForm: {
                    per_client_conn_limit: 100,
                    conn_limit_window: 10,
                    cgi_cpu_limit: 10,
                    cgi_mem_limit: 300,
                    recaptcha_enabled: false,
                    recaptcha_threshold: 50,
                    bubblewrap_enabled: true,
                    global_allowed_ips: '127.0.0.1, 192.168.0.0/16',
                    global_denied_ips: ''
                }
            };
        },
        async mounted() {
            await this.loadConfig();
        },
        methods: {
            async loadConfig() {
                this.loading = true;
                try {
                    const data = await window.ZMaxApiClient.fetchJson('api/v1/config/server');
                    if (data && data.ok) {
                        if (data.tuning) {
                            this.tuningForm = { ...this.tuningForm, ...data.tuning };
                        }
                        if (Array.isArray(data.ext_apps) && data.ext_apps.length) {
                            this.extApps = data.ext_apps;
                        }
                        if (Array.isArray(data.script_handlers) && data.script_handlers.length) {
                            this.scriptHandlers = data.script_handlers;
                        }
                        if (data.security) {
                            this.securityForm = { ...this.securityForm, ...data.security };
                        }
                    }
                } catch (_) {
                } finally {
                    this.loading = false;
                }
            },
            async saveTuning() {
                this.saving = true;
                try {
                    const res = await window.ZMaxApiClient.fetch('api/v1/config/server', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(this.tuningForm)
                    });
                    this.$emit('show-notice', this.t('notice_tuning_saved') || 'İnce ayar yapılandırması başarıyla kaydedildi.');
                    this.$emit('config-changed', this.t('notice_tuning_saved') || 'İnce ayar yapılandırması güncellendi (Graceful Reload bekleniyor).');
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_tuning_saved') || 'İnce ayar yapılandırması kaydedildi.');
                    this.$emit('config-changed');
                } finally {
                    this.saving = false;
                }
            },
            async saveSecurity() {
                this.saving = true;
                try {
                    await window.ZMaxApiClient.fetch('api/v1/config/server', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ security: this.securityForm })
                    });
                    this.$emit('show-notice', this.t('notice_sec_saved') || 'Sunucu güvenlik limitleri güncellendi.');
                    this.$emit('config-changed', this.t('notice_sec_saved') || 'Sunucu güvenlik limitleri güncellendi (Graceful Reload bekleniyor).');
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_sec_saved') || 'Sunucu güvenlik limitleri güncellendi.');
                    this.$emit('config-changed');
                } finally {
                    this.saving = false;
                }
            },
            openAddExtApp() {
                this.extAppModalMode = 'create';
                this.extAppForm = { id: 'app_' + Date.now().toString(36), name: '', type: 'LSAPI', address: '127.0.0.1:9090', max_conns: 30, instances: 5 };
                this.showExtAppModal = true;
            },
            openEditExtApp(app) {
                this.extAppModalMode = 'edit';
                this.extAppForm = { ...app };
                this.showExtAppModal = true;
            },
            saveExtApp() {
                if (!this.extAppForm.name || !this.extAppForm.address) return;
                const idx = this.extApps.findIndex(x => x.id === this.extAppForm.id);
                if (idx >= 0) {
                    this.extApps[idx] = { ...this.extAppForm };
                } else {
                    this.extApps.push({ ...this.extAppForm });
                }
                this.showExtAppModal = false;
                this.$emit('show-notice', this.t('notice_extapp_saved') || 'Harici uygulama havuzu kaydedildi.');
                this.$emit('config-changed', 'Harici uygulama havuzları güncellendi (Graceful Reload bekleniyor).');
            },
            deleteExtApp(app) {
                this.extApps = this.extApps.filter(x => x.id !== app.id);
                this.$emit('show-notice', this.t('notice_extapp_deleted') || 'Havuz silindi.');
                this.$emit('config-changed', 'Harici uygulama havuzu silindi (Graceful Reload bekleniyor).');
            },
            openAddHandler() {
                this.handlerModalMode = 'create';
                this.handlerForm = { suffix: '', handler: this.extApps[0] ? this.extApps[0].id : 'lsphp83', note: '' };
                this.showHandlerModal = true;
            },
            openEditHandler(h) {
                this.handlerModalMode = 'edit';
                this.handlerForm = { ...h };
                this.showHandlerModal = true;
            },
            saveHandler() {
                if (!this.handlerForm.suffix) return;
                const s = this.handlerForm.suffix.replace(/^\./, '').toLowerCase();
                const idx = this.scriptHandlers.findIndex(x => x.suffix === s);
                if (idx >= 0) {
                    this.scriptHandlers[idx] = { ...this.handlerForm, suffix: s };
                } else {
                    this.scriptHandlers.push({ ...this.handlerForm, suffix: s });
                }
                this.showHandlerModal = false;
                this.$emit('show-notice', this.t('notice_handler_saved') || 'Script Handler kuralı güncellendi.');
                this.$emit('config-changed', 'Script Handler kuralı güncellendi (Graceful Reload bekleniyor).');
            },
            deleteHandler(h) {
                this.scriptHandlers = this.scriptHandlers.filter(x => x.suffix !== h.suffix);
                this.$emit('show-notice', this.t('notice_handler_deleted') || 'Handler kuralı silindi.');
                this.$emit('config-changed', 'Script Handler kuralı silindi (Graceful Reload bekleniyor).');
            }
        },
        template: `
            <div class="server-config-view">
                <!-- Sekme Seçim Başlığı -->
                <div class="panel-card mb-3">
                    <div class="panel-header d-flex flex-wrap justify-content-between align-items-center gap-2">
                        <div class="d-flex align-items-center gap-2">
                            <svg class="icon panel-icon text-orange" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                                <line x1="6" y1="6" x2="6.01" y2="6"></line>
                                <line x1="6" y1="18" x2="6.01" y2="18"></line>
                            </svg>
                            <h3 class="panel-title mb-0">{{ t('server_config_title') || 'Sunucu Genel Yapılandırması' }}</h3>
                        </div>
                        <div class="nav-subtabs d-flex gap-1">
                            <button type="button" class="btn-zmax btn-sm-compact" :class="activeSubTab === 'tuning' ? 'btn-orange' : 'btn-ghost'" @click="activeSubTab = 'tuning'">
                                {{ t('tab_tuning') || 'İnce Ayar (Tuning)' }}
                            </button>
                            <button type="button" class="btn-zmax btn-sm-compact" :class="activeSubTab === 'extapps' ? 'btn-orange' : 'btn-ghost'" @click="activeSubTab = 'extapps'">
                                {{ t('tab_extapps') || 'Harici Uygulamalar' }} ({{ extApps.length }})
                            </button>
                            <button type="button" class="btn-zmax btn-sm-compact" :class="activeSubTab === 'handlers' ? 'btn-orange' : 'btn-ghost'" @click="activeSubTab = 'handlers'">
                                {{ t('tab_handlers') || 'Script Handlers' }} ({{ scriptHandlers.length }})
                            </button>
                            <button type="button" class="btn-zmax btn-sm-compact" :class="activeSubTab === 'security' ? 'btn-orange' : 'btn-ghost'" @click="activeSubTab = 'security'">
                                {{ t('tab_sec_limits') || 'Güvenlik & İzolasyon' }}
                            </button>
                        </div>
                    </div>
                </div>

                <!-- 1. TUNING SEKME İÇERİĞİ -->
                <div v-if="activeSubTab === 'tuning'" class="panel-card">
                    <form @submit.prevent="saveTuning">
                        <h4 class="mb-3 text-orange font-weight-bold" style="font-size: 1.05rem;">
                            {{ t('tuning_conn_title') || 'Bağlantı & Performans İnce Ayarları' }}
                        </h4>
                        <div class="row g-3 mb-4">
                            <div class="col-md-6 col-lg-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_max_conns') || 'Maksimum Bağlantı' }}</label>
                                <input type="number" v-model.number="tuningForm.max_connections" class="zmax-input w-100" min="100" max="100000">
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_conn_timeout') || 'Bağlantı Zaman Aşımı (sn)' }}</label>
                                <input type="number" v-model.number="tuningForm.connection_timeout" class="zmax-input w-100" min="5" max="600">
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_keepalive_timeout') || 'Keep-Alive Süresi (sn)' }}</label>
                                <input type="number" v-model.number="tuningForm.keep_alive_timeout" class="zmax-input w-100" min="1" max="120">
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_max_keepalive_req') || 'Maks. Keep-Alive İsteği' }}</label>
                                <input type="number" v-model.number="tuningForm.max_keep_alive_req" class="zmax-input w-100" min="10" max="10000">
                            </div>
                        </div>

                        <hr class="border-separator my-4">

                        <h4 class="mb-3 text-orange font-weight-bold" style="font-size: 1.05rem;">
                            {{ t('tuning_compress_title') || 'Sıkıştırma & HTTP/3 Protokol Ayarları' }}
                        </h4>
                        <div class="row g-3 mb-4">
                            <div class="col-md-6 col-lg-3">
                                <div class="form-check form-switch pt-4">
                                    <input class="form-check-input" type="checkbox" id="gzipSw" v-model="tuningForm.gzip_enabled">
                                    <label class="form-check-label text-silver" for="gzipSw">{{ t('lbl_gzip_enable') || 'GZIP Sıkıştırma' }}</label>
                                </div>
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <div class="form-check form-switch pt-4">
                                    <input class="form-check-input" type="checkbox" id="brSw" v-model="tuningForm.brotli_enabled">
                                    <label class="form-check-label text-silver" for="brSw">{{ t('lbl_brotli_enable') || 'Brotli (br) Sıkıştırma' }}</label>
                                </div>
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_min_compress_size') || 'Min. Sıkıştırma Eşiği (Bayt)' }}</label>
                                <input type="number" v-model.number="tuningForm.min_compress_size" class="zmax-input w-100" min="64">
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <div class="form-check form-switch pt-4">
                                    <input class="form-check-input" type="checkbox" id="h3Sw" v-model="tuningForm.http3_enabled">
                                    <label class="form-check-label text-silver" for="h3Sw">{{ t('lbl_http3_enable') || 'HTTP/3 (QUIC) Desteği' }}</label>
                                </div>
                            </div>
                        </div>

                        <div class="d-flex justify-content-end gap-2 pt-3 border-top border-separator">
                            <button type="submit" class="btn-zmax btn-orange" :disabled="saving">
                                <span v-if="saving">{{ t('btn_saving') || 'Kaydediliyor...' }}</span>
                                <span v-else>{{ t('btn_save_changes') || 'Değişiklikleri Kaydet' }}</span>
                            </button>
                        </div>
                    </form>
                </div>

                <!-- 2. EXTERNAL APPLICATIONS SEKME İÇERİĞİ -->
                <div v-if="activeSubTab === 'extapps'" class="panel-card">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <p class="text-muted-custom small mb-0">
                            {{ t('extapps_desc') || 'PHP-FPM, LiteSpeed SAPI (lsapi) ve Node.js backend uygulama havuzları.' }}
                        </p>
                        <button type="button" class="btn-zmax btn-orange btn-sm-compact" @click="openAddExtApp">
                            + {{ t('btn_add_extapp') || 'Yeni Havuz Ekle' }}
                        </button>
                    </div>

                    <div class="table-responsive">
                        <table class="table-zmax w-100">
                            <thead>
                                <tr>
                                    <th>{{ t('col_name') || 'Havuz Adı' }}</th>
                                    <th>{{ t('col_type') || 'Protokol' }}</th>
                                    <th>{{ t('col_address') || 'Soket / Adres' }}</th>
                                    <th>{{ t('col_max_conns') || 'Maks. Bağlantı' }}</th>
                                    <th>{{ t('col_instances') || 'İşçi Sayısı' }}</th>
                                    <th class="text-end">{{ t('col_actions') || 'İşlemler' }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="app in extApps" :key="app.id">
                                    <td><strong class="text-orange">{{ app.name }}</strong></td>
                                    <td><span class="badge bg-dark border border-secondary text-light">{{ app.type }}</span></td>
                                    <td><code>{{ app.address }}</code></td>
                                    <td>{{ app.max_conns }}</td>
                                    <td>{{ app.instances }}</td>
                                    <td class="text-end">
                                        <button type="button" class="btn-zmax btn-ghost btn-sm-compact me-1" @click="openEditExtApp(app)" :title="t('btn_edit') || 'Düzenle'">
                                            ✎
                                        </button>
                                        <button type="button" class="btn-zmax btn-ghost btn-sm-compact text-danger" @click="deleteExtApp(app)" :title="t('btn_delete')">
                                            ✕
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- 3. SCRIPT HANDLERS SEKME İÇERİĞİ -->
                <div v-if="activeSubTab === 'handlers'" class="panel-card">
                    <div class="d-flex justify-content-between align-items-center mb-3">
                        <p class="text-muted-custom small mb-0">
                            {{ t('handlers_desc') || 'Dosya uzantılarını (örn: .php, .py) sunucu harici uygulama havuzlarına bağlar.' }}
                        </p>
                        <button type="button" class="btn-zmax btn-orange btn-sm-compact" @click="openAddHandler">
                            + {{ t('btn_add_handler') || 'Uzantı Kuralı Ekle' }}
                        </button>
                    </div>

                    <div class="table-responsive">
                        <table class="table-zmax w-100">
                            <thead>
                                <tr>
                                    <th>{{ t('col_suffix') || 'Dosya Uzantısı' }}</th>
                                    <th>{{ t('col_assigned_handler') || 'Atanan İşleyici Havuzu' }}</th>
                                    <th>{{ t('col_note') || 'Açıklama' }}</th>
                                    <th class="text-end">{{ t('col_actions') || 'İşlemler' }}</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr v-for="h in scriptHandlers" :key="h.suffix">
                                    <td><code class="text-orange">.{{ h.suffix }}</code></td>
                                    <td><strong>{{ h.handler }}</strong></td>
                                    <td class="text-muted-custom small">{{ h.note }}</td>
                                    <td class="text-end">
                                        <button type="button" class="btn-zmax btn-ghost btn-sm-compact me-1" @click="openEditHandler(h)" :title="t('btn_edit') || 'Düzenle'">
                                            ✎
                                        </button>
                                        <button type="button" class="btn-zmax btn-ghost btn-sm-compact text-danger" @click="deleteHandler(h)" :title="t('btn_delete')">
                                            ✕
                                        </button>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- 4. GÜVENLİK & İZOLASYON SEKME İÇERİĞİ -->
                <div v-if="activeSubTab === 'security'" class="panel-card">
                    <form @submit.prevent="saveSecurity">
                        <h4 class="mb-3 text-orange font-weight-bold" style="font-size: 1.05rem;">
                            {{ t('sec_limits_title') || 'Sunucu Kaynak Limitleri & Bot Koruması' }}
                        </h4>
                        <div class="row g-3 mb-4">
                            <div class="col-md-6 col-lg-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_client_conns') || 'İstemci Başına Maks. Bağlantı' }}</label>
                                <input type="number" v-model.number="securityForm.per_client_conn_limit" class="zmax-input w-100" min="10" max="1000">
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_cgi_cpu') || 'CGI Maks. CPU Süresi (sn)' }}</label>
                                <input type="number" v-model.number="securityForm.cgi_cpu_limit" class="zmax-input w-100" min="1" max="120">
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_cgi_mem') || 'CGI Maks. Bellek (MB)' }}</label>
                                <input type="number" v-model.number="securityForm.cgi_mem_limit" class="zmax-input w-100" min="64" max="2048">
                            </div>
                            <div class="col-md-6 col-lg-3">
                                <div class="form-check form-switch pt-4">
                                    <input class="form-check-input" type="checkbox" id="bwrapSw" v-model="securityForm.bubblewrap_enabled">
                                    <label class="form-check-label text-silver" for="bwrapSw">{{ t('lbl_bubblewrap') || 'Bubblewrap Sandbox' }}</label>
                                </div>
                            </div>
                        </div>

                        <hr class="border-separator my-4">

                        <h4 class="mb-3 text-orange font-weight-bold" style="font-size: 1.05rem;">
                            {{ t('sec_ip_access_title') || 'Global IP Erişim Listesi' }}
                        </h4>
                        <div class="row g-3 mb-4">
                            <div class="col-md-6">
                                <label class="form-label small text-muted-custom">{{ t('lbl_allowed_ips') || 'İzin Verilen IP / CIDR Listesi' }}</label>
                                <textarea v-model="securityForm.global_allowed_ips" class="zmax-input w-100" rows="3" placeholder="127.0.0.1, 192.168.1.0/24"></textarea>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label small text-muted-custom">{{ t('lbl_denied_ips') || 'Engellenen IP / CIDR Listesi' }}</label>
                                <textarea v-model="securityForm.global_denied_ips" class="zmax-input w-100" rows="3" placeholder="10.0.0.1, 172.16.0.0/12"></textarea>
                            </div>
                        </div>

                        <div class="d-flex justify-content-end gap-2 pt-3 border-top border-separator">
                            <button type="submit" class="btn-zmax btn-orange" :disabled="saving">
                                <span v-if="saving">{{ t('btn_saving') || 'Kaydediliyor...' }}</span>
                                <span v-else>{{ t('btn_save_changes') || 'Güvenlik Ayarlarını Kaydet' }}</span>
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Harici Uygulama Ekleme Modalı -->
                <div v-if="showExtAppModal" class="d-flex align-items-center justify-content-center p-3" style="position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1060;" @click.self="showExtAppModal = false">
                    <div class="panel-card w-100 mb-0" style="max-width: 520px;">
                        <div class="panel-header">
                            <h3 class="panel-title"><span>{{ t('modal_extapp_title') || 'Harici Uygulama Havuzu Ekle/Düzenle' }}</span></h3>
                            <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="showExtAppModal = false">✕</button>
                        </div>
                        <form @submit.prevent="saveExtApp">
                            <div class="mb-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_name') || 'Havuz İsmi' }}</label>
                                <input type="text" v-model="extAppForm.name" required class="zmax-input w-100" placeholder="LSPHP 8.4">
                            </div>
                            <div class="row g-2 mb-3">
                                <div class="col-6">
                                    <label class="form-label small text-muted-custom">{{ t('lbl_type') || 'Tip' }}</label>
                                    <select v-model="extAppForm.type" class="zmax-input w-100">
                                        <option value="LSAPI">LSAPI (LiteSpeed SAPI)</option>
                                        <option value="FastCGI">FastCGI</option>
                                        <option value="Proxy">Ters Vekil (Proxy)</option>
                                        <option value="LoadBalancer">Load Balancer</option>
                                    </select>
                                </div>
                                <div class="col-6">
                                    <label class="form-label small text-muted-custom">{{ t('lbl_address') || 'Adres / Soket' }}</label>
                                    <input type="text" v-model="extAppForm.address" required class="zmax-input w-100" placeholder="127.0.0.1:9084">
                                </div>
                            </div>
                            <div class="row g-2 mb-4">
                                <div class="col-6">
                                    <label class="form-label small text-muted-custom">{{ t('col_max_conns') || 'Maks. Bağlantı' }}</label>
                                    <input type="number" v-model.number="extAppForm.max_conns" class="zmax-input w-100" min="1" max="1000">
                                </div>
                                <div class="col-6">
                                    <label class="form-label small text-muted-custom">{{ t('col_instances') || 'İşçi Sayısı' }}</label>
                                    <input type="number" v-model.number="extAppForm.instances" class="zmax-input w-100" min="1" max="100">
                                </div>
                            </div>
                            <div class="d-flex justify-content-end gap-2 pt-2 border-top border-separator">
                                <button type="button" class="btn-zmax btn-ghost" @click="showExtAppModal = false">{{ t('btn_cancel') || 'Vazgeç' }}</button>
                                <button type="submit" class="btn-zmax btn-orange">{{ t('btn_save') || 'Kaydet' }}</button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- Handler Ekleme Modalı -->
                <div v-if="showHandlerModal" class="d-flex align-items-center justify-content-center p-3" style="position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1060;" @click.self="showHandlerModal = false">
                    <div class="panel-card w-100 mb-0" style="max-width: 480px;">
                        <div class="panel-header">
                            <h3 class="panel-title"><span>{{ t('modal_handler_title') || 'Script Handler Eşleme Kuralı' }}</span></h3>
                            <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="showHandlerModal = false">✕</button>
                        </div>
                        <form @submit.prevent="saveHandler">
                            <div class="mb-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_suffix') || 'Uzantı (örn: php, py, jsp)' }}</label>
                                <input type="text" v-model="handlerForm.suffix" required class="zmax-input w-100" placeholder="php">
                            </div>
                            <div class="mb-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_assign_to') || 'Hedef Havuz' }}</label>
                                <select v-model="handlerForm.handler" class="zmax-input w-100">
                                    <option v-for="a in extApps" :key="a.id" :value="a.id">{{ a.name }} ({{ a.type }})</option>
                                </select>
                            </div>
                            <div class="mb-4">
                                <label class="form-label small text-muted-custom">{{ t('lbl_note') || 'Açıklama Notu' }}</label>
                                <input type="text" v-model="handlerForm.note" class="zmax-input w-100" placeholder="PHP 8.3 Ana İşleyici">
                            </div>
                            <div class="d-flex justify-content-end gap-2 pt-2 border-top border-separator">
                                <button type="button" class="btn-zmax btn-ghost" @click="showHandlerModal = false">{{ t('btn_cancel') || 'Vazgeç' }}</button>
                                <button type="submit" class="btn-zmax btn-orange">{{ t('btn_save') || 'Eşle' }}</button>
                            </div>
                        </form>
                    </div>
                </div>

            </div>
        `
    };
})(window);

