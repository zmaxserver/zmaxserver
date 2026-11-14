// ZMax WebAdmin - Sanal Konaklar / VHosts Görünümü
// U5 Bileşeni: VHost CRUD tablosu, ikonlu işlem butonları (title + aria-label), modal yönetimi

(function (window) {
    'use strict';

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
        emits: ['vhost-saved', 'vhost-deleted', 'show-notice'],
        data() {
            return {
                showVhostModal: false,
                vhostModalMode: 'create', // 'create' veya 'edit'
                savingVhost: false,
                deletingVhost: false,
                vhostForm: this.getEmptyForm()
            };
        },
        methods: {
            getEmptyForm() {
                return {
                    domain: '',
                    document_root: '',
                    php_enabled: true,
                    php_sapi: 'fastcgi',
                    php_upstream: '127.0.0.1:9000',
                    cache_enabled: true,
                    ssl_enabled: false,
                    tls_http2: true,
                    waf_enabled: true,
                    hotlink_protection: false,
                    allow_ips: '',
                    deny_ips: '',
                    logging_enabled: false,
                    logging_access_log: ''
                };
            },
            normalizeIpArray(val) {
                if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
                if (typeof val === 'string') return val.split(',').map((x) => x.trim()).filter(Boolean);
                return [];
            },
            openCreateModal() {
                this.vhostModalMode = 'create';
                this.vhostForm = this.getEmptyForm();
                this.showVhostModal = true;
            },
            openEditModal(vh) {
                this.vhostModalMode = 'edit';
                this.vhostForm = {
                    domain: vh.domain || '',
                    document_root: vh.doc_root || '',
                    php_enabled: Boolean(vh.php_enabled),
                    php_sapi: vh.php_sapi_raw || 'fastcgi',
                    php_upstream: vh.php_upstream_raw || '127.0.0.1:9000',
                    cache_enabled: Boolean(vh.cache),
                    ssl_enabled: Boolean(vh.ssl_enabled),
                    tls_http2: Boolean(vh.http2),
                    waf_enabled: Boolean(vh.waf_enabled),
                    hotlink_protection: Boolean(vh.hotlink_protection),
                    allow_ips: Array.isArray(vh.allow_ips) ? vh.allow_ips.join(', ') : '',
                    deny_ips: Array.isArray(vh.deny_ips) ? vh.deny_ips.join(', ') : '',
                    logging_enabled: Boolean(vh.logging_enabled),
                    logging_access_log: vh.access_log || (vh.domain ? `logs/${vh.domain}.access.log` : '')
                };
                this.showVhostModal = true;
            },
            closeModal() {
                this.showVhostModal = false;
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
                    php_enabled: Boolean(this.vhostForm.php_enabled),
                    php_sapi: this.vhostForm.php_sapi.trim() || 'fastcgi',
                    php_upstream: this.vhostForm.php_upstream.trim() || '127.0.0.1:9000',
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
                    }
                };

                const isEdit = this.vhostModalMode === 'edit';

                try {
                    const res = await window.ZMaxApiClient.saveVhost(domain, payload, isEdit);
                    if (res && res.ok) {
                        this.showVhostModal = false;
                        this.$emit('show-notice', `${domain} — ${this.t(isEdit ? 'notice_vhost_updated' : 'notice_vhost_added')}`);
                        this.$emit('vhost-saved', { domain, isEdit });
                    } else {
                        this.$emit('show-notice', this.t('notice_vhost_error'));
                    }
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_vhost_error'));
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
                    } else {
                        this.$emit('show-notice', this.t('notice_vhost_error'));
                    }
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_vhost_error'));
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
                            <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path></svg>
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
                                <th>{{ t('th_php') }}</th>
                                <th>{{ t('th_ssl') }}</th>
                                <th>{{ t('th_cache') }}</th>
                                <th>{{ t('th_security_logs') }}</th>
                                <th>{{ t('th_status') }}</th>
                                <th>{{ t('th_action') }}</th>
                            </tr>
                        </thead>
                        <tbody>
                            <tr v-for="vh in filteredVhosts" :key="vh.id || vh.domain">
                                <td><strong>{{ vh.domain }}</strong></td>
                                <td>{{ vh.port }}</td>
                                <td><code>{{ vh.doc_root }}</code></td>
                                <td><span class="status-capsule status-orange">{{ vh.php_sapi }}</span></td>
                                <td>
                                    <div class="d-flex flex-wrap gap-1">
                                        <span class="status-capsule status-active">{{ vh.sslKey ? t(vh.sslKey) : vh.sslText }}</span>
                                        <span class="status-capsule" :class="vh.http2 ? 'status-active' : 'status-orange'">HTTP/2: {{ vh.http2 ? t('status_on') : t('status_off') }}</span>
                                    </div>
                                </td>
                                <td><span class="status-capsule status-active">{{ vh.cache ? t('status_enabled') : t('status_none') }}</span></td>
                                <td>
                                    <div class="d-flex flex-wrap gap-1">
                                        <span class="status-capsule" :class="vh.waf_enabled ? 'status-active' : 'status-orange'">WAF: {{ vh.waf_enabled ? t('status_on') : t('status_off') }}</span>
                                        <span class="status-capsule" :class="vh.logging_enabled ? 'status-active' : 'status-orange'">Log: {{ vh.logging_enabled ? t('status_on') : t('status_off') }}</span>
                                    </div>
                                </td>
                                <td><span class="status-capsule status-active">{{ t(vh.statusKey || 'status_active') }}</span></td>
                                <td>
                                    <div class="d-flex align-items-center gap-1">
                                        <!-- İkonlu Düzenle Butonu (title + aria-label) -->
                                        <button
                                            type="button"
                                            class="btn-zmax btn-ghost btn-sm-compact p-1"
                                            @click="openEditModal(vh)"
                                            :title="t('btn_edit')"
                                            :aria-label="t('btn_edit') + ' - ' + vh.domain"
                                        >
                                            <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path>
                                                <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path>
                                            </svg>
                                        </button>
                                        <!-- İkonlu Sil Butonu (title + aria-label) -->
                                        <button
                                            type="button"
                                            class="btn-zmax btn-ghost text-danger btn-sm-compact p-1"
                                            @click="deleteVhost(vh)"
                                            :title="t('btn_delete') || 'Sil'"
                                            :aria-label="(t('btn_delete') || 'Sil') + ' - ' + vh.domain"
                                        >
                                            <svg class="icon icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                <polyline points="3 6 5 6 21 6"></polyline>
                                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                                <line x1="10" y1="11" x2="10" y2="17"></line>
                                                <line x1="14" y1="11" x2="14" y2="17"></line>
                                            </svg>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- vHost Ekleme / Düzenleme Modalı -->
                <div v-if="showVhostModal" class="d-flex align-items-center justify-content-center p-3" style="position: fixed; inset: 0; background: rgba(0, 0, 0, 0.65); z-index: 1050; overflow-y: auto;" @click.self="closeModal">
                    <div class="panel-card w-100 mb-0" style="max-width: 720px; max-height: 92vh; overflow-y: auto;">
                        <div class="panel-header">
                            <h3 class="panel-title">
                                <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path></svg>
                                <span>{{ vhostModalMode === 'edit' ? t('vhost_modal_edit_title') : t('vhost_modal_add_title') }}</span>
                            </h3>
                            <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="closeModal" :aria-label="t('close_menu')">✕</button>
                        </div>

                        <form @submit.prevent="saveVhost">
                            <div class="row g-3">
                                <div class="col-12 col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_domain') }}</label>
                                    <input type="text" v-model="vhostForm.domain" :readonly="vhostModalMode === 'edit'" required placeholder="example.com" class="zmax-input w-100">
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_docroot') }}</label>
                                    <input type="text" v-model="vhostForm.document_root" placeholder="www/example.com" class="zmax-input w-100">
                                </div>

                                <div class="col-12 col-md-4 d-flex align-items-center">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhPhpEnabled" v-model="vhostForm.php_enabled">
                                        <label class="form-check-label small" for="vhPhpEnabled">{{ t('lbl_vhost_php_enabled') }}</label>
                                    </div>
                                </div>
                                <div class="col-12 col-md-4">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_php_sapi') }}</label>
                                    <input type="text" v-model="vhostForm.php_sapi" :disabled="!vhostForm.php_enabled" placeholder="fastcgi" class="zmax-input w-100">
                                </div>
                                <div class="col-12 col-md-4">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_php_upstream') }}</label>
                                    <input type="text" v-model="vhostForm.php_upstream" :disabled="!vhostForm.php_enabled" placeholder="127.0.0.1:9000" class="zmax-input w-100">
                                </div>

                                <div class="col-6 col-md-4">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhCacheEnabled" v-model="vhostForm.cache_enabled">
                                        <label class="form-check-label small" for="vhCacheEnabled">{{ t('lbl_vhost_cache') }}</label>
                                    </div>
                                </div>
                                <div class="col-6 col-md-4">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhSslEnabled" v-model="vhostForm.ssl_enabled">
                                        <label class="form-check-label small" for="vhSslEnabled">{{ t('lbl_vhost_ssl') }}</label>
                                    </div>
                                </div>
                                <div class="col-6 col-md-4">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhHttp2" v-model="vhostForm.tls_http2">
                                        <label class="form-check-label small" for="vhHttp2">{{ t('lbl_vhost_http2') }}</label>
                                    </div>
                                </div>

                                <div class="col-6 col-md-6">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhWafEnabled" v-model="vhostForm.waf_enabled">
                                        <label class="form-check-label small" for="vhWafEnabled">{{ t('lbl_vhost_waf') }}</label>
                                    </div>
                                </div>
                                <div class="col-6 col-md-6">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhHotlink" v-model="vhostForm.hotlink_protection">
                                        <label class="form-check-label small" for="vhHotlink">{{ t('lbl_vhost_hotlink') }}</label>
                                    </div>
                                </div>

                                <div class="col-12 col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_allow_ips') }}</label>
                                    <input type="text" v-model="vhostForm.allow_ips" :placeholder="t('ph_ip_list')" class="zmax-input w-100">
                                </div>
                                <div class="col-12 col-md-6">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_deny_ips') }}</label>
                                    <input type="text" v-model="vhostForm.deny_ips" :placeholder="t('ph_ip_list')" class="zmax-input w-100">
                                </div>

                                <div class="col-12 col-md-4 d-flex align-items-center">
                                    <div class="form-check form-switch">
                                        <input class="form-check-input" type="checkbox" id="vhLogEnabled" v-model="vhostForm.logging_enabled">
                                        <label class="form-check-label small" for="vhLogEnabled">{{ t('lbl_vhost_logging_enabled') }}</label>
                                    </div>
                                </div>
                                <div class="col-12 col-md-8">
                                    <label class="form-label text-muted-custom small mb-1">{{ t('lbl_vhost_access_log') }}</label>
                                    <input type="text" v-model="vhostForm.logging_access_log" placeholder="logs/example.com.access.log" class="zmax-input w-100">
                                </div>
                            </div>

                            <div class="d-flex justify-content-end gap-2 mt-4">
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
