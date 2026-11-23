// ZMax WebAdmin - Sanal Konak Şablonları (templates.js)
// OLS Denkliği: Virtual Host Templates, Member VHosts

(function (window) {
    'use strict';

    window.ZMaxViewTemplates = {
        name: 'ViewTemplates',
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
        emits: ['show-notice'],
        data() {
            return {
                templates: [
                    {
                        id: 'tpl_wordpress',
                        name: 'WordPress Standart Şablonu',
                        doc_root: 'www/$VH_NAME',
                        php_handler: 'lsphp83',
                        rewrite_rules: 'WordPress Permalinks (.htaccess otomatik yükle)',
                        cache_policy: 'LSCache Standart',
                        members_count: 3
                    },
                    {
                        id: 'tpl_laravel',
                        name: 'Laravel / Modern PHP Şablonu',
                        doc_root: 'www/$VH_NAME/public',
                        php_handler: 'lsphp83',
                        rewrite_rules: 'RewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^(.*)$ index.php [QSA,L]',
                        cache_policy: 'Önbellek Kapalı (Dinamik)',
                        members_count: 1
                    },
                    {
                        id: 'tpl_nodejs',
                        name: 'Node.js / Reverse Proxy Şablonu',
                        doc_root: 'www/$VH_NAME',
                        php_handler: 'Yok (Node Proxy)',
                        rewrite_rules: 'Ters vekil 127.0.0.1:$VH_PORT',
                        cache_policy: 'Statik Varlıklar Önbellekli',
                        members_count: 0
                    }
                ],
                showModal: false,
                form: {
                    id: '',
                    name: '',
                    doc_root: 'www/$VH_NAME',
                    php_handler: 'lsphp83',
                    cache_policy: 'LSCache Standart'
                }
            };
        },
        methods: {
            openCreateModal() {
                this.form = {
                    id: 'tpl_' + Date.now().toString(36),
                    name: '',
                    doc_root: 'www/$VH_NAME',
                    php_handler: 'lsphp83',
                    cache_policy: 'LSCache Standart'
                };
                this.showModal = true;
            },
            saveTemplate() {
                if (!this.form.name) return;
                this.templates.push({
                    ...this.form,
                    rewrite_rules: 'Varsayılan Şablon Kuralları',
                    members_count: 0
                });
                this.showModal = false;
                this.$emit('show-notice', this.t('notice_tpl_saved') || 'VHost şablonu başarıyla oluşturuldu.');
            },
            deleteTemplate(tpl) {
                this.templates = this.templates.filter(x => x.id !== tpl.id);
                this.$emit('show-notice', this.t('notice_tpl_deleted') || 'Şablon silindi.');
            }
        },
        template: `
            <div class="templates-view">
                <div class="panel-card mb-3">
                    <div class="panel-header d-flex justify-content-between align-items-center">
                        <div class="d-flex align-items-center gap-2">
                            <svg class="icon panel-icon text-orange" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                            </svg>
                            <h3 class="panel-title mb-0">{{ t('templates_title') || 'Sanal Konak Şablonları (Templates)' }}</h3>
                        </div>
                        <button type="button" class="btn-zmax btn-orange btn-sm-compact" @click="openCreateModal">
                            + {{ t('btn_add_template') || 'Yeni Şablon Oluştur' }}
                        </button>
                    </div>
                    <p class="text-muted-custom small px-3 mb-2">
                        {{ t('templates_desc') || 'Toplu hosting yönetimi için önceden tanımlanmış PHP sürümü, doküman kökü, yeniden yazma ve önbellek şablonları.' }}
                    </p>
                </div>

                <div class="row g-3">
                    <div v-for="tpl in templates" :key="tpl.id" class="col-md-6 col-xl-4">
                        <div class="panel-card h-100 d-flex flex-column justify-content-between">
                            <div>
                                <div class="d-flex justify-content-between align-items-start mb-2">
                                    <h4 class="font-weight-bold text-white mb-0" style="font-size: 1.05rem;">
                                        {{ tpl.name }}
                                    </h4>
                                    <span class="badge bg-dark border border-secondary text-orange">
                                        {{ tpl.members_count }} Üye
                                    </span>
                                </div>
                                <div class="small text-muted-custom mb-1">
                                    <strong>DocRoot Şablonu:</strong> <code>{{ tpl.doc_root }}</code>
                                </div>
                                <div class="small text-muted-custom mb-1">
                                    <strong>PHP İşleyici:</strong> <span class="text-silver">{{ tpl.php_handler }}</span>
                                </div>
                                <div class="small text-muted-custom mb-3">
                                    <strong>Önbellek Politikası:</strong> <span class="text-silver">{{ tpl.cache_policy }}</span>
                                </div>
                            </div>
                            <div class="d-flex justify-content-end gap-2 pt-3 border-top border-separator">
                                <button type="button" class="btn-zmax btn-ghost btn-sm-compact me-1" @click="openEditModal(tpl)">
                                    {{ t('btn_edit') || 'Düzenle' }}
                                </button>
                                <button type="button" class="btn-zmax btn-ghost btn-sm-compact text-danger" @click="deleteTemplate(tpl)">
                                    {{ t('btn_delete') || 'Sil' }}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Şablon Ekleme Modalı -->
                <div v-if="showModal" class="d-flex align-items-center justify-content-center p-3" style="position: fixed; inset: 0; background: rgba(0,0,0,0.75); z-index: 1060;" @click.self="showModal = false">
                    <div class="panel-card w-100 mb-0" style="max-width: 500px;">
                        <div class="panel-header">
                            <h3 class="panel-title"><span>{{ modalMode === 'edit' ? (t('modal_edit_tpl') || 'Şablonu Düzenle') : (t('modal_add_tpl') || 'Yeni Sanal Konak Şablonu') }}</span></h3>
                            <button type="button" class="btn-zmax btn-ghost btn-sm-compact" @click="showModal = false">✕</button>
                        </div>
                        <form @submit.prevent="saveTemplate">
                            <div class="mb-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_tpl_name') || 'Şablon Adı' }}</label>
                                <input type="text" v-model="form.name" required class="zmax-input w-100" placeholder="Örn: E-Ticaret / Opencart">
                            </div>
                            <div class="mb-3">
                                <label class="form-label small text-muted-custom">{{ t('lbl_docroot_tpl') || 'DocRoot Şablon Kalıbı' }}</label>
                                <input type="text" v-model="form.doc_root" required class="zmax-input w-100" placeholder="www/$VH_NAME">
                            </div>
                            <div class="mb-4">
                                <label class="form-label small text-muted-custom">{{ t('lbl_php_handler') || 'Varsayılan PHP İşleyicisi' }}</label>
                                <select v-model="form.php_handler" class="zmax-input w-100">
                                    <option value="lsphp83">LSPHP 8.3</option>
                                    <option value="lsphp82">LSPHP 8.2</option>
                                    <option value="lsphp81">LSPHP 8.1</option>
                                    <option value="none">PHP Yok (Statik / Proxy)</option>
                                </select>
                            </div>
                            <div class="d-flex justify-content-end gap-2 pt-2 border-top border-separator">
                                <button type="button" class="btn-zmax btn-ghost" @click="showModal = false">{{ t('btn_cancel') || 'Vazgeç' }}</button>
                                <button type="submit" class="btn-zmax btn-orange">{{ modalMode === 'edit' ? (t('btn_save') || 'Kaydet') : (t('btn_create') || 'Oluştur') }}</button>
                            </div>
                        </form>
                    </div>
                </div>

            </div>
        `
    };
})(window);

