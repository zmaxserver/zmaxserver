// ZMax WebAdmin - Dinleyiciler ve Port Yönetimi (listeners.js)
// OLS Denkliği: Listener General, Listener SSL, Virtual Host Mappings

(function (window) {
    'use strict';

    window.ZMaxViewListeners = {
        name: 'ViewListeners',
        props: {
            vhosts: {
                type: Array,
                required: true
            },
            t: {
                type: Function,
                required: true
            }
        },
        emits: ['show-notice', 'config-changed'],
        data() {
            return {
                listeners: [
                    {
                        id: 'http_default',
                        name: 'Default HTTP (80)',
                        ip: '*',
                        port: 80,
                        secure: false,
                        protocol: 'HTTP/1.1, HTTP/2',
                        vhost_mappings: ['* (Tüm VHostlar)'],
                        status: 'active'
                    },
                    {
                        id: 'https_default',
                        name: 'Default HTTPS (443)',
                        ip: '*',
                        port: 443,
                        secure: true,
                        protocol: 'HTTP/2, HTTP/3 (QUIC)',
                        tls_versions: ['TLSv1.2', 'TLSv1.3'],
                        vhost_mappings: ['* (Tüm VHostlar, SNI)'],
                        status: 'active'
                    },
                    {
                        id: 'webadmin_listener',
                        name: 'WebAdmin Konsolu',
                        ip: '127.0.0.1',
                        port: 7088,
                        secure: false,
                        protocol: 'HTTP/1.1',
                        vhost_mappings: ['admin.localhost'],
                        status: 'active'
                    }
                ],
                showModal: false,
                modalMode: 'create',
                form: {
                    id: '',
                    name: '',
                    ip: '*',
                    port: 8080,
                    secure: false,
                    tls12: true,
                    tls13: true,
                    alpn_h2: true,
                    alpn_h3: false,
                    cert_file: '',
                    key_file: '',
                    assigned_vhosts: []
                }
            };
        },
        async mounted() {
            await this.loadListeners();
        },
        methods: {
            async loadListeners() {
                try {
                    const data = await window.ZMaxApiClient.fetchJson('api/v1/listeners');
                    if (data && data.ok && Array.isArray(data.listeners) && data.listeners.length) {
                        this.listeners = data.listeners;
                    }
                } catch (_) {}
            },
            openCreateModal() {
                this.modalMode = 'create';
                this.form = {
                    id: 'lis_' + Date.now().toString(36),
                    name: '',
                    ip: '*',
                    port: 8080,
                    secure: false,
                    tls12: true,
                    tls13: true,
                    alpn_h2: true,
                    alpn_h3: false,
                    cert_file: '',
                    key_file: '',
                    assigned_vhosts: []
                };
                this.showModal = true;
            },
            openEditModal(l) {
                this.modalMode = 'edit';
                this.form = {
                    id: l.id,
                    name: l.name,
                    ip: l.ip,
                    port: l.port,
                    secure: l.secure,
                    tls12: true,
                    tls13: true,
                    alpn_h2: true,
                    alpn_h3: Boolean(l.protocol && l.protocol.includes('HTTP/3')),
                    cert_file: l.cert_file || '',
                    key_file: l.key_file || '',
                    assigned_vhosts: [...(l.vhost_mappings || [])]
                };
                this.showModal = true;
            },
            toggleAllVhosts(e) {
                if (e.target.checked) {
                    this.form.assigned_vhosts = ['*'];
                } else {
                    this.form.assigned_vhosts = [];
                }
            },
            async saveListener() {
                if (!this.form.name || !this.form.port) return;
                const idx = this.listeners.findIndex(x => x.id === this.form.id);
                const protoStr = (this.form.secure ? (this.form.alpn_h3 ? 'HTTP/2, HTTP/3 (QUIC)' : 'HTTP/2') : 'HTTP/1.1, HTTP/2');
                const tlsVers = [];
                if (this.form.tls12) tlsVers.push('TLSv1.2');
                if (this.form.tls13) tlsVers.push('TLSv1.3');

                const data = {
                    id: this.form.id,
                    name: this.form.name,
                    ip: this.form.ip,
                    port: Number(this.form.port),
                    secure: Boolean(this.form.secure),
                    protocol: protoStr,
                    tls_versions: tlsVers,
                    cert_file: this.form.cert_file,
                    key_file: this.form.key_file,
                    vhost_mappings: this.form.assigned_vhosts.length ? this.form.assigned_vhosts : ['* (Varsayılan)'],
                    status: 'active'
                };

                try {
                    await window.ZMaxApiClient.fetch('api/v1/listeners', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                } catch (_) {}

                if (idx >= 0) {
                    this.listeners[idx] = data;
                } else {
                    this.listeners.push(data);
                }
                this.showModal = false;
                this.$emit('show-notice', this.t('notice_listener_saved') || 'Dinleyici ayarları başarıyla kaydedildi.');
                this.$emit('config-changed', 'Dinleyiciler güncellendi (Graceful Reload bekleniyor).');
            },
            deleteListener(l) {
                if (l.port === 80 || l.port === 443) {
                    alert('Standart 80/443 dinleyicileri kaldırılamaz!');
                    return;
                }
                this.listeners = this.listeners.filter(x => x.id !== l.id);
                this.$emit('show-notice', this.t('notice_listener_deleted') || 'Dinleyici silindi.');
                this.$emit('config-changed', 'Dinleyici silindi (Graceful Reload bekleniyor).');
            }
        },
        template: `
            <div class="listeners-view">
                <div class="panel-card mb-3">
                    <div class="panel-header d-flex justify-content-between align-items-center">
                        <div class="d-flex align-items-center gap-2">
                            <svg class="icon panel-icon text-orange" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
                            </svg>
                            <h3 class="panel-title mb-0">{{ t('listeners_title') || 'Dinleyiciler & Ağ Portları' }}</h3>
                        </div>
                        <button type="button" class="btn-zmax btn-orange btn-sm-compact" @click="openCreateModal">
                            + {{ t('btn_add_listener') || 'Yeni Dinleyici Ekle' }}
                        </button>
                    </div>
                    <p class="text-muted-custom small px-3 mb-2">
                        {{ t('listeners_desc') || 'Sunucunun dinleyeceği IP/port kombinasyonları, SSL/TLS yapılandırması ve alan adı eşlemeleri (VHost Mappings).' }}
                    </p>
                </div>

                <div class="row g-3">
                    <div v-for="l in listeners" :key="l.id" class="col-md-6 col-xl-4">
                        <div class="panel-card h-100 d-flex flex-column justify-content-between">
                            <div>
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <h4 class="font-weight-bold text-white mb-0" style="font-size: 1.1rem;">
                                        {{ l.name }}
                                    </h4>
                                    <span class="badge" :class="l.secure ? 'bg-success text-dark' : 'bg-secondary text-light'">
                                        {{ l.secure ? 'SSL / TLS' : 'Düz HTTP' }}
                                    </span>
                                </div>
                                <div class="mb-3">
                                    <span class="text-orange font-monospace" style="font-size: 1.25rem; font-weight: 600;">
                                        {{ l.ip }}:{{ l.port }}
                                    </span>
                                </div>
                                <div class="small text-muted-custom mb-2">
                                    <strong>Protokol:</strong> {{ l.protocol }}
                                </div>
                                <div class="small text-muted-custom mb-3">
                                    <strong>Eşleşen VHostlar:</strong>
                                    <div class="d-flex flex-wrap gap-1 mt-1">
                                        <span v-for="m in l.vhost_mappings" :key="m" class="badge bg-dark border border-secondary text-silver">
                                            {{ m }}
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div class="d-flex justify-content-end gap-2 pt-3 border-top border-separator">
                                <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="openEditModal(l)">
                                    {{ t('btn_edit') || 'Düzenle' }}
                                </button>
                                <button v-if="l.port !== 80 && l.port !== 443" type="button" class="btn-zmax btn-ghost btn-sm-compact text-danger" @click="deleteListener(l)">
                                    {{ t('btn_delete') || 'Sil' }}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Dinleyici Ekle / Düzenle Modalı -->
                <div v-if="showModal" class="d-flex align-items-center justify-content-center p-3" style="position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1060;" @click.self="showModal = false">
                    <div class="panel-card w-100 mb-0" style="max-width: 540px;">
                        <div class="panel-header">
                            <h3 class="panel-title"><span>{{ modalMode === 'create' ? (t('modal_add_listener') || 'Yeni Dinleyici Ekle') : (t('modal_edit_listener') || 'Dinleyiciyi Düzenle') }}</span></h3>
                            <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="showModal = false">✕</button>
                        </div>
                        <form @submit.prevent="saveListener">
                            <div class="mb-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_listener_name') || 'Dinleyici Adı' }}</label>
                                <input type="text" v-model="form.name" required class="zmax-input w-100" placeholder="Örn: HTTP Alternatif">
                            </div>
                            <div class="row g-2 mb-3">
                                <div class="col-6">
                                    <label class="form-label small text-muted-custom">{{ t('lbl_ip_binding') || 'IP Adresi (* = Tümü)' }}</label>
                                    <input type="text" v-model="form.ip" required class="zmax-input w-100" placeholder="*">
                                </div>
                                <div class="col-6">
                                    <label class="form-label small text-muted-custom">{{ t('lbl_port') || 'Port Numarası' }}</label>
                                    <input type="number" v-model.number="form.port" required class="zmax-input w-100" min="1" max="65535">
                                </div>
                            </div>
                            <div class="mb-3">
                                <div class="form-check form-switch">
                                    <input class="form-check-input" type="checkbox" id="secSw" v-model="form.secure">
                                    <label class="form-check-label text-silver" for="secSw">{{ t('lbl_enable_ssl') || 'SSL / TLS Güvenli Bağlantı Etkin' }}</label>
                                </div>
                            </div>
                            <div v-if="form.secure" class="p-3 mb-3 rounded border border-separator" style="background: rgba(255,255,255,0.02);">
                                <h6 class="text-orange small font-weight-bold mb-2">TLS Protokolleri & Özellikler</h6>
                                <div class="d-flex gap-3 mb-3">
                                    <label class="small text-silver"><input type="checkbox" v-model="form.tls12"> TLSv1.2</label>
                                    <label class="small text-silver"><input type="checkbox" v-model="form.tls13"> TLSv1.3</label>
                                    <label class="small text-silver"><input type="checkbox" v-model="form.alpn_h2"> HTTP/2</label>
                                    <label class="small text-silver"><input type="checkbox" v-model="form.alpn_h3"> HTTP/3 (QUIC)</label>
                                </div>
                                <div class="row g-2">
                                    <div class="col-6">
                                        <label class="form-label small text-muted-custom">Sertifika Dosyası (.crt)</label>
                                        <input type="text" v-model="form.cert_file" placeholder="/etc/ssl/server.crt" class="zmax-input w-100" style="font-size: 0.85rem;">
                                    </div>
                                    <div class="col-6">
                                        <label class="form-label small text-muted-custom">Özel Anahtar (.key)</label>
                                        <input type="text" v-model="form.key_file" placeholder="/etc/ssl/server.key" class="zmax-input w-100" style="font-size: 0.85rem;">
                                    </div>
                                </div>
                            </div>

                            <div class="mb-3">
                                <label class="form-label small text-muted-custom">Eşleşen Sanal Konaklar (VHost Mappings)</label>
                                <div class="p-2 rounded border border-separator" style="max-height: 110px; overflow-y: auto; background: rgba(0,0,0,0.2);">
                                    <label class="small text-silver d-flex align-items-center gap-1 mb-1">
                                        <input type="checkbox" value="*" :checked="form.assigned_vhosts.includes('*') || !form.assigned_vhosts.length" @change="toggleAllVhosts">
                                        * (Tüm Sanal Konaklar / Varsayılan)
                                    </label>
                                    <label v-for="v in vhosts" :key="v.domain" class="small text-silver d-flex align-items-center gap-1 mb-1">
                                        <input type="checkbox" :value="v.domain" v-model="form.assigned_vhosts">
                                        {{ v.domain }}
                                    </label>
                                </div>
                            </div>
                            <div class="d-flex justify-content-end gap-2 pt-2 border-top border-separator">
                                <button type="button" class="btn-zmax btn-ghost" @click="showModal = false">{{ t('btn_cancel') || 'Vazgeç' }}</button>
                                <button type="submit" class="btn-zmax btn-orange">{{ t('btn_save') || 'Kaydet' }}</button>
                            </div>
                        </form>
                    </div>
                </div>

            </div>
        `
    };
})(window);

