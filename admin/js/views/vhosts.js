// ZMax WebAdmin - Sanal Konaklar / VHosts Görünümü (vhosts.js)
// OLS Denkliği: 6 Sekmeli Gelişmiş VHost Düzenleme Modalı (General, Context, Rewrite, SSL/ACME, Hata Sayfaları, Güvenlik)

(function (window) {
    'use strict';

    function createEmptyVhostForm() {
        return {
            domain: '',
            document_root: '',
            aliases: '',
            index_files: 'index.php, index.html',
            php_enabled: true,
            php_sapi: 'lsapi',
            php_upstream: '127.0.0.1:9083',
            cache_enabled: true,
            ssl_enabled: true,
            tls_http2: true,
            waf_enabled: true,
            hotlink_protection: false,
            allow_ips: '',
            deny_ips: '',
            logging_enabled: true,
            logging_access_log: '',
            // OLS Sekmeleri
            rewrite_enabled: true,
            rewrite_rules: '# Rewrite kuralları\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]',
            ssl_cert_path: '',
            ssl_key_path: '',
            acme_auto: true,
            err_404_path: '',
            err_403_path: '',
            err_500_path: '',
            basic_auth_enabled: false,
            basic_auth_realm: 'Restricted Area',
            contexts: [
                { uri: '/static/', type: 'Static', target: 'public/static' },
                { uri: '/api/', type: 'Proxy', target: 'http://127.0.0.1:3000' }
            ]
        };
    }

    window.ZMaxViewVhosts = {
        name: 'ViewVhosts',
        props: {
            vhosts: {
                type: Array,
                required: true
            },
            filteredVhosts: {
                type: Array,
                required: true
            },
            t: {
                type: Function,
                required: true
            }
        },
        emits: ['vhost-saved', 'vhost-deleted', 'show-notice', 'config-changed'],
        data() {
            return {
                showVhostModal: false,
                vhostModalMode: 'create', // 'create' veya 'edit'
                modalTab: 'general', // 'general', 'context', 'rewrite', 'ssl', 'errors', 'security'
                savingVhost: false,
                deletingVhost: false,
                vhostForm: createEmptyVhostForm()
            };
        },
        methods: {
            getEmptyForm() {
                return createEmptyVhostForm();
            },
            normalizeIpArray(val) {
                if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
                if (typeof val === 'string') return val.split(',').map((x) => x.trim()).filter(Boolean);
                return [];
            },
            openCreateModal() {
                this.vhostModalMode = 'create';
                this.modalTab = 'general';
                this.vhostForm = this.getEmptyForm();
                this.showVhostModal = true;
            },
            openEditModal(vh) {
                this.vhostModalMode = 'edit';
                this.modalTab = 'general';
                const aliasesStr = Array.isArray(vh.aliases) ? vh.aliases.join(', ') : (vh.aliases || (vh.domain ? `www.${vh.domain}` : ''));
                const indexStr = Array.isArray(vh.index_files) ? vh.index_files.join(', ') : (vh.index_files || 'index.php, index.html');
                const contextsList = Array.isArray(vh.contexts) ? vh.contexts : (Array.isArray(vh.proxy) ? vh.proxy : [
                    { uri: '/static/', type: 'Static', target: 'public/static' },
                    { uri: '/api/', type: 'Proxy', target: 'http://127.0.0.1:3000' }
                ]);
                const rwRules = (vh.rewrite && vh.rewrite.rules) ? vh.rewrite.rules : '# Rewrite kuralları\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]';

                this.vhostForm = {
                    ...this.getEmptyForm(),
                    domain: vh.domain || '',
                    document_root: vh.doc_root || vh.document_root || '',
                    aliases: aliasesStr,
                    index_files: indexStr,
                    php_enabled: Boolean(vh.php_enabled),
                    php_sapi: vh.php_sapi_raw || (vh.php && vh.php.sapi) || 'lsapi',
                    php_upstream: vh.php_upstream_raw || (vh.php && vh.php.upstream) || '127.0.0.1:9083',
                    cache_enabled: Boolean(vh.cache ?? (vh.cache && vh.cache.enabled)),
                    ssl_enabled: Boolean(vh.ssl_enabled ?? (vh.ssl && vh.ssl.enabled)),
                    ssl_cert_path: (vh.ssl && (vh.ssl.certificate || vh.ssl.cert_file)) || vh.ssl_cert_path || '',
                    ssl_key_path: (vh.ssl && (vh.ssl.private_key || vh.ssl.key_file)) || vh.ssl_key_path || '',
                    acme_auto: vh.ssl ? Boolean(vh.ssl.acme) : true,
                    tls_http2: Boolean(vh.http2 ?? (vh.tls && vh.tls.http2)),
                    waf_enabled: Boolean(vh.waf_enabled ?? (vh.waf && vh.waf.enabled)),
                    hotlink_protection: Boolean(vh.hotlink_protection),
                    basic_auth_enabled: Boolean(vh.basic_auth_enabled ?? (vh.security && vh.security.basic_auth)),
                    basic_auth_realm: (vh.security && vh.security.realm) || vh.basic_auth_realm || 'Restricted Area',
                    allow_ips: Array.isArray(vh.allow_ips) ? vh.allow_ips.join(', ') : (vh.allow_ips || ''),
                    deny_ips: Array.isArray(vh.deny_ips) ? vh.deny_ips.join(', ') : (vh.deny_ips || ''),
                    logging_enabled: Boolean(vh.logging_enabled ?? (vh.logging && vh.logging.enabled)),
                    logging_access_log: vh.access_log || (vh.logging && vh.logging.access_log) || (vh.domain ? `logs/${vh.domain}.access.log` : ''),
                    rewrite_enabled: vh.rewrite ? Boolean(vh.rewrite.enabled) : true,
                    rewrite_rules: rwRules,
                    err_404_path: (vh.error_pages && vh.error_pages['404']) || vh.err_404_path || '',
                    err_403_path: (vh.error_pages && vh.error_pages['403']) || vh.err_403_path || '',
                    err_500_path: (vh.error_pages && vh.error_pages['500']) || vh.err_500_path || '',
                    contexts: contextsList
                };
                this.showVhostModal = true;
            },
            closeModal() {
                this.showVhostModal = false;
            },
            applyRewritePreset(preset) {
                if (preset === 'wordpress') {
                    this.vhostForm.rewrite_rules = '# WordPress Standart Yeniden Yazma\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]';
                } else if (preset === 'laravel') {
                    this.vhostForm.rewrite_rules = '# Laravel / Modern PHP Yeniden Yazma\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^ index.php [L]';
                } else if (preset === 'spa') {
                    this.vhostForm.rewrite_rules = '# SPA (Vue / React / Angular)\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.html$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.html [L]';
                }
            },
            addContextRow() {
                this.vhostForm.contexts.push({ uri: '/', type: 'Proxy', target: 'http://127.0.0.1:8080' });
            },
            removeContextRow(idx) {
                this.vhostForm.contexts.splice(idx, 1);
            },
            async saveVhost() {
                const domain = this.vhostForm.domain.trim().toLowerCase();
                if (!domain || this.savingVhost) return;

                this.savingVhost = true;
                const loggingEnabled = Boolean(this.vhostForm.logging_enabled);
                const accessLogInput = this.vhostForm.logging_access_log.trim();

                const payload = {
                    domain,
                    document_root: this.vhostForm.document_root.trim() || `www/${domain}`,
                    aliases: this.vhostForm.aliases ? this.vhostForm.aliases.split(',').map(s => s.trim()).filter(Boolean) : [`www.${domain}`],
                    index_files: this.vhostForm.index_files ? this.vhostForm.index_files.split(',').map(s => s.trim()).filter(Boolean) : ['index.php', 'index.html'],
                    php_enabled: Boolean(this.vhostForm.php_enabled),
                    php_sapi: this.vhostForm.php_sapi.trim() || 'lsapi',
                    php_upstream: this.vhostForm.php_upstream.trim() || '127.0.0.1:9083',
                    cache_enabled: Boolean(this.vhostForm.cache_enabled),
                    ssl_enabled: Boolean(this.vhostForm.ssl_enabled),
                    waf_enabled: Boolean(this.vhostForm.waf_enabled),
                    hotlink_protection: Boolean(this.vhostForm.hotlink_protection),
                    allow_ips: this.normalizeIpArray(this.vhostForm.allow_ips),
                    deny_ips: this.normalizeIpArray(this.vhostForm.deny_ips),
                    tls: {
                        http2: Boolean(this.vhostForm.tls_http2)
                    },
                    logging: {
                        enabled: loggingEnabled,
                        access_log: accessLogInput || (loggingEnabled ? `logs/${domain}.access.log` : '')
                    },
                    // OLS Sekmeleri
                    php: {
                        enabled: Boolean(this.vhostForm.php_enabled),
                        sapi: this.vhostForm.php_sapi.trim() || 'lsapi',
                        upstream: this.vhostForm.php_upstream.trim() || '127.0.0.1:9083'
                    },
                    cache: {
                        enabled: Boolean(this.vhostForm.cache_enabled)
                    },
                    ssl: {
                        enabled: Boolean(this.vhostForm.ssl_enabled),
                        certificate: this.vhostForm.ssl_cert_path.trim(),
                        private_key: this.vhostForm.ssl_key_path.trim(),
                        cert_file: this.vhostForm.ssl_cert_path.trim(),
                        key_file: this.vhostForm.ssl_key_path.trim(),
                        acme: Boolean(this.vhostForm.acme_auto)
                    },
                    rewrite: {
                        enabled: Boolean(this.vhostForm.rewrite_enabled),
                        rules: this.vhostForm.rewrite_rules
                    },
                    security: {
                        waf_enabled: Boolean(this.vhostForm.waf_enabled),
                        hotlink_protection: Boolean(this.vhostForm.hotlink_protection),
                        basic_auth: Boolean(this.vhostForm.basic_auth_enabled),
                        realm: this.vhostForm.basic_auth_realm || 'Restricted Area'
                    },
                    contexts: this.vhostForm.contexts || [],
                    error_pages: {
                        '403': this.vhostForm.err_403_path || '',
                        '404': this.vhostForm.err_404_path || '',
                        '500': this.vhostForm.err_500_path || ''
                    }
                };

                const isEdit = this.vhostModalMode === 'edit';

                try {
                    const res = await window.ZMaxApiClient.saveVhost(domain, payload, isEdit);
                    if (res && res.ok) {
                        this.showVhostModal = false;
                        this.$emit('show-notice', `${domain} — ${this.t(isEdit ? 'notice_vhost_updated' : 'notice_vhost_added')}`);
                        this.$emit('vhost-saved', { domain, isEdit });
                        this.$emit('config-changed', `${domain} — Yapılandırma güncellendi (Graceful Reload bekleniyor).`);
                    } else {
                        const errMsg = (res && (res.error || res.message)) || 'Kayıt başarısız oldu';
                        this.$emit('show-notice', `${domain} — Hata: ${errMsg}`);
                    }
                } catch (err) {
                    const errMsg = (err && err.message) || 'Ağ veya sunucu bağlantı hatası';
                    this.$emit('show-notice', `${domain} — Hata: ${errMsg}`);
                } finally {
                    this.savingVhost = false;
                }
            },
            async deleteVhost(vh) {
                const domain = vh.domain;
                if (!domain || this.deletingVhost) return;

                const confirmMsg = `${domain} ${this.t('confirm_delete_vhost') || 'alan adını silmek istediğinize emin misiniz?'}`;
                if (!window.confirm(confirmMsg)) return;

                this.deletingVhost = true;
                try {
                    const res = await window.ZMaxApiClient.deleteVhost(domain);
                    if (res && res.ok) {
                        this.$emit('show-notice', `${domain} — ${this.t('notice_vhost_deleted') || 'Sanal konak silindi'}`);
                        this.$emit('vhost-deleted', domain);
                        this.$emit('config-changed', `${domain} — Sanal konak silindi (Graceful Reload bekleniyor).`);
                    } else {
                        const errMsg = (res && (res.error || res.message)) || 'Silme işlemi başarısız oldu';
                        this.$emit('show-notice', `${domain} — Hata: ${errMsg}`);
                    }
                } catch (err) {
                    const errMsg = (err && err.message) || 'Ağ veya sunucu hatası';
                    this.$emit('show-notice', `${domain} — Hata: ${errMsg}`);
                } finally {
                    this.deletingVhost = false;
                }
            }
        },
        template: `
            <div class="panel-card">
                <div class="panel-header">
                    <div>
                        <h3 class="panel-title">
                            <svg class="icon panel-icon text-orange" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path></svg>
                            <span>{{ t('vhosts_title') }}</span>
                        </h3>
                        <p class="panel-subtitle">{{ t('vhosts_desc') }}</p>
                    </div>
                    <div class="d-flex flex-wrap align-items-center gap-2">
                        <span class="status-capsule status-active">
                            <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polyline points="20 6 9 17 4 12"></polyline></svg>
                            {{ t('vhosts_sync') }}
                        </span>
                        <button type="button" class="btn-zmax btn-orange btn-sm-compact" @click="openCreateModal">
                            + {{ t('btn_add_vhost') }}
                        </button>
                    </div>
                </div>

                <div class="table-responsive">
                    <table class="zmax-table">
                        <thead>
                            <tr>
                                <th>{{ t('th_domain') }}</th>
                                <th>{{ t('th_port') }}</th>
                                <th>{{ t('th_docroot') }}</th>
                                <th>{{ t('th_php_backend') }}</th>
                                <th>{{ t('th_cache') }}</th>
                                <th>{{ t('th_ssl') }}</th>
                                <th>{{ t('th_waf') }}</th>
                                <th>{{ t('th_hotlink') }}</th>
                                <th>{{ t('th_access_log') }}</th>
                                <th>{{ t('th_access_policy') }}</th>
                                <th class="text-end">{{ t('th_actions') }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="vh in filteredVhosts" :key="vh.domain">
                                <td>
                                    <div class="vhost-primary">
                                        <div class="vhost-name"><strong class="text-white">{{ vh.domain }}</strong></div>
                                        <div class="vhost-sub text-muted-custom small">www.{{ vh.domain }}</div>
                                    </div>
                                </td>
                                <td><span class="badge bg-dark border border-secondary text-silver">{{ vh.port_badge || '80 / 443' }}</span></td>
                                <td><code class="small">{{ vh.doc_root }}</code></td>
                                <td>
                                    <span v-if="vh.php_enabled" class="badge bg-dark border border-secondary text-orange">
                                        {{ vh.php_sapi_raw || 'LSAPI' }}
                                    </span>
                                    <span v-else class="text-muted-custom small">—</span>
                                </td>
                                <td><span class="status-dot" :class="vh.cache ? 'status-dot-active' : 'status-dot-muted'"></span></td>
                                <td><span class="status-dot" :class="vh.ssl_enabled ? 'status-dot-active' : 'status-dot-muted'"></span></td>
                                <td><span class="status-dot" :class="vh.waf_enabled ? 'status-dot-active' : 'status-dot-muted'"></span></td>
                                <td><span class="status-dot" :class="vh.hotlink_protection ? 'status-dot-active' : 'status-dot-muted'"></span></td>
                                <td><span class="status-dot" :class="vh.logging_enabled ? 'status-dot-active' : 'status-dot-muted'"></span></td>
                                <td><span class="small text-muted-custom">{{ vh.access_policy_label || 'Açık' }}</span></td>
                                <td class="text-end">
                                    <div class="d-inline-flex align-items-center gap-1">
                                        <button type="button" class="btn-zmax btn-ghost btn-sm-compact p-1" @click="openEditModal(vh)" :title="t('btn_edit')">
                                            <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                                            </svg>
                                        </button>
                                        <button type="button" class="btn-zmax btn-ghost text-danger btn-sm-compact p-1" @click="deleteVhost(vh)" :title="t('btn_delete')">
                                            <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                                <polyline points="3 6 5 6 21 6"></polyline>
                                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                            </svg>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- 6 SEKMelİ GELİŞMİŞ VHOST MODALI -->
                <div v-if="showVhostModal" class="d-flex align-items-center justify-content-center p-3" style="position: fixed; inset: 0; background: rgba(0, 0, 0, 0.75); z-index: 1050; overflow-y: auto;" @click.self="closeModal">
                    <div class="panel-card w-100 mb-0" style="max-width: 820px; max-height: 94vh; overflow-y: auto;">
                        <div class="panel-header pb-2 border-bottom border-separator">
                            <div>
                                <h3 class="panel-title">
                                    <span class="text-orange">{{ vhostModalMode === 'edit' ? vhostForm.domain : (t('vhost_modal_add_title') || 'Yeni Sanal Konak Ekle') }}</span>
                                </h3>
                                <div class="nav-subtabs d-flex flex-wrap gap-1 mt-2">
                                    <button type="button" class="btn-zmax btn-sm-compact" :class="modalTab === 'general' ? 'btn-orange' : 'btn-ghost'" @click="modalTab = 'general'">
                                        {{ t('tab_general') || 'Genel' }}
                                    </button>
                                    <button type="button" class="btn-zmax btn-sm-compact" :class="modalTab === 'context' ? 'btn-orange' : 'btn-ghost'" @click="modalTab = 'context'">
                                        {{ t('tab_context') || 'Context (URI)' }}
                                    </button>
                                    <button type="button" class="btn-zmax btn-sm-compact" :class="modalTab === 'rewrite' ? 'btn-orange' : 'btn-ghost'" @click="modalTab = 'rewrite'">
                                        {{ t('tab_rewrite') || 'Rewrite & .htaccess' }}
                                    </button>
                                    <button type="button" class="btn-zmax btn-sm-compact" :class="modalTab === 'ssl' ? 'btn-orange' : 'btn-ghost'" @click="modalTab = 'ssl'">
                                        {{ t('tab_ssl_acme') || 'SSL & ACME' }}
                                    </button>
                                    <button type="button" class="btn-zmax btn-sm-compact" :class="modalTab === 'errors' ? 'btn-orange' : 'btn-ghost'" @click="modalTab = 'errors'">
                                        {{ t('tab_error_pages') || 'Hata Sayfaları' }}
                                    </button>
                                    <button type="button" class="btn-zmax btn-sm-compact" :class="modalTab === 'security' ? 'btn-orange' : 'btn-ghost'" @click="modalTab = 'security'">
                                        {{ t('tab_security_auth') || 'Güvenlik & Auth' }}
                                    </button>
                                </div>
                            </div>
                            <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="closeModal">✕</button>
                        </div>

                        <form @submit.prevent="saveVhost" class="pt-3">
                            <!-- SEKME 1: GENEL AYARLAR -->
                            <div v-show="modalTab === 'general'" class="row g-3">
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_domain') || 'Alan Adı (Domain)' }}</label>
                                    <input type="text" v-model="vhostForm.domain" :readonly="vhostModalMode === 'edit'" required placeholder="example.com" class="zmax-input w-100">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_aliases') || 'Takma Adlar (Aliases)' }}</label>
                                    <input type="text" v-model="vhostForm.aliases" placeholder="www.example.com, test.example.com" class="zmax-input w-100">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_docroot') || 'Doküman Kök Dizini (DocRoot)' }}</label>
                                    <input type="text" v-model="vhostForm.document_root" placeholder="www/example.com" class="zmax-input w-100">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_index_files') || 'Index Dosyaları' }}</label>
                                    <input type="text" v-model="vhostForm.index_files" placeholder="index.php, index.html" class="zmax-input w-100">
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_php_sapi_type') || 'PHP İşleyici Türü' }}</label>
                                    <select v-model="vhostForm.php_sapi" class="zmax-input w-100">
                                        <option value="lsapi">LiteSpeed SAPI (lsapi)</option>
                                        <option value="fastcgi">FastCGI (php-fpm)</option>
                                        <option value="proxy">Proxy (Ters Vekil)</option>
                                    </select>
                                </div>
                                <div class="col-md-4">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_php_backend_sock') || 'PHP Backend Soketi' }}</label>
                                    <input type="text" v-model="vhostForm.php_upstream" placeholder="127.0.0.1:9083" class="zmax-input w-100">
                                </div>
                                <div class="col-md-4 pt-4">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhPhpEn" v-model="vhostForm.php_enabled">
                                        <label class="form-check-label small text-silver" for="vhPhpEn">{{ t('lbl_php_enable_sw') || 'PHP İşleme Açık' }}</label>
                                    </div>
                                </div>
                            </div>

                            <!-- SEKME 2: CONTEXT YÖNETİMİ -->
                            <div v-show="modalTab === 'context'">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <p class="text-muted-custom small mb-0">
                                        {{ t('context_desc') || 'URI bazlı Statik Dizin, Proxy ve Yönlendirme (Context) kuralları.' }}
                                    </p>
                                    <button type="button" class="btn-zmax btn-orange btn-sm-compact" @click="addContextRow">
                                        + {{ t('btn_add_context') || 'Yeni Context Ekle' }}
                                    </button>
                                </div>
                                <div class="table-responsive">
                                    <table class="table-zmax w-100">
                                        <thead>
                                            <tr>
                                                <th>{{ t('col_uri_path') || 'URI Yolu' }}</th>
                                                <th>{{ t('col_type') || 'Tip' }}</th>
                                                <th>{{ t('col_target_path') || 'Hedef Dizin / Port' }}</th>
                                                <th class="text-end">{{ t('th_actions') || 'İşlem' }}</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr v-for="(c, idx) in vhostForm.contexts" :key="idx">
                                                <td><input type="text" v-model="c.uri" class="zmax-input py-1 px-2" style="font-size: 0.85rem;"></td>
                                                <td>
                                                    <select v-model="c.type" class="zmax-input py-1 px-2" style="font-size: 0.85rem;">
                                                        <option value="Proxy">Proxy (Ters Vekil)</option>
                                                        <option value="Static">Static Dizin</option>
                                                        <option value="Redirect">Redirect (301)</option>
                                                    </select>
                                                </td>
                                                <td><input type="text" v-model="c.target" class="zmax-input py-1 px-2 w-100" style="font-size: 0.85rem;"></td>
                                                <td class="text-end">
                                                    <button type="button" class="btn-zmax btn-ghost btn-sm-compact text-danger p-1" @click="removeContextRow(idx)">✕</button>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>

                            <!-- SEKME 3: REWRITE & .HTACCESS -->
                            <div v-show="modalTab === 'rewrite'">
                                <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-2">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhRwSw" v-model="vhostForm.rewrite_enabled">
                                        <label class="form-check-label small text-silver" for="vhRwSw">Yeniden Yazma Motoru (Rewrite Engine) Aktif</label>
                                    </div>
                                    <div class="d-flex align-items-center gap-1">
                                        <span class="text-muted-custom small me-1">Hızlı Şablon:</span>
                                        <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="applyRewritePreset('wordpress')">WordPress</button>
                                        <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="applyRewritePreset('laravel')">Laravel</button>
                                        <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="applyRewritePreset('spa')">SPA</button>
                                    </div>
                                </div>
                                <label class="form-label small text-muted-custom">Yeniden Yazma Kuralları (Rewrite Rules):</label>
                                <textarea v-model="vhostForm.rewrite_rules" rows="8" class="zmax-input w-100 font-monospace" style="font-size: 0.85rem; line-height: 1.4;"></textarea>
                            </div>

                            <!-- SEKME 4: SSL & ACME -->
                            <div v-show="modalTab === 'ssl'" class="row g-3">
                                <div class="col-12">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhSslSw" v-model="vhostForm.ssl_enabled">
                                        <label class="form-check-label text-silver" for="vhSslSw">HTTPS / SSL Bağlantılarını Kabul Et</label>
                                    </div>
                                </div>
                                <div class="col-12">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhAcmeSw" v-model="vhostForm.acme_auto">
                                        <label class="form-check-label text-silver" for="vhAcmeSw">Let's Encrypt / ACME Otomatik Sertifika & Yenileme</label>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">Sertifika Dosya Yolu (.crt / .pem)</label>
                                    <input type="text" v-model="vhostForm.ssl_cert_path" placeholder="/etc/ssl/certs/domain.crt" class="zmax-input w-100">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">Özel Anahtar Dosya Yolu (.key)</label>
                                    <input type="text" v-model="vhostForm.ssl_key_path" placeholder="/etc/ssl/private/domain.key" class="zmax-input w-100">
                                </div>
                            </div>

                            <!-- SEKME 5: HATA SAYFALARI -->
                            <div v-show="modalTab === 'errors'" class="row g-3">
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">404 Not Found Sayfası</label>
                                    <input type="text" v-model="vhostForm.err_404_path" placeholder="errors/404.html" class="zmax-input w-100">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">403 Forbidden Sayfası</label>
                                    <input type="text" v-model="vhostForm.err_403_path" placeholder="errors/403.html" class="zmax-input w-100">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">500 / 502 Sunucu Hatası Sayfası</label>
                                    <input type="text" v-model="vhostForm.err_500_path" placeholder="errors/500.html" class="zmax-input w-100">
                                </div>
                            </div>

                            <!-- SEKME 6: GÜVENLİK & AUTH -->
                            <div v-show="modalTab === 'security'" class="row g-3">
                                <div class="col-md-6">
                                    <div class="form-check form-switch mb-2">
                                        <input class="form-check-input" type="checkbox" id="vhWafSw" v-model="vhostForm.waf_enabled">
                                        <label class="form-check-label small text-silver" for="vhWafSw">WAF Koruması (SQLi & XSS Engelleme)</label>
                                    </div>
                                    <div class="form-check form-switch mb-2">
                                        <input class="form-check-input" type="checkbox" id="vhHotSw" v-model="vhostForm.hotlink_protection">
                                        <label class="form-check-label small text-silver" for="vhHotSw">Hotlink Koruması (Görsel Çalma Engeli)</label>
                                    </div>
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhAuthSw" v-model="vhostForm.basic_auth_enabled">
                                        <label class="form-check-label small text-silver" for="vhAuthSw">Dizin Şifreleme (Basic Auth Koruması)</label>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">İzin Verilen / Engellenen IP'ler</label>
                                    <input type="text" v-model="vhostForm.allow_ips" placeholder="İzin: 192.168.1.100" class="zmax-input w-100 mb-2">
                                    <input type="text" v-model="vhostForm.deny_ips" placeholder="Yasak: 10.0.0.5" class="zmax-input w-100">
                                </div>
                            </div>

                            <div class="d-flex justify-content-end gap-2 pt-3 mt-4 border-top border-separator">
                                <button type="button" class="btn-zmax btn-ghost" @click="closeModal">{{ t('btn_cancel') }}</button>
                                <button type="submit" class="btn-zmax btn-orange" :disabled="savingVhost">{{ t('btn_save') }}</button>
                            </div>
                        </form>
                    </div>
                </div>

            </div>
        `
    };
})(window);
