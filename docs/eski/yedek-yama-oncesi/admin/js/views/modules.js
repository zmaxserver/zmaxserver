// ZMax WebAdmin - Sunucu Modülleri Görünümü
// Mevcut ekran koruma: 18 sunucu modülü, kategori filtreleme ve arama

(function (window) {
    'use strict';

    window.ZMaxViewModules = {
        name: 'ViewModules',
        props: {
            modules: {
                type: Array,
                required: true
            },
            filteredModules: {
                type: Array,
                required: true
            },
            selectedModuleCategory: {
                type: String,
                default: 'all'
            },
            moduleCategories: {
                type: Array,
                required: true
            },
            t: {
                type: Function,
                required: true
            }
        },
        emits: ['update:selectedModuleCategory'],
        template: `
            <div class="panel-card">
                <div class="panel-header">
                    <div>
                        <h3 class="panel-title">
                            <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                            <span>{{ t('modules_title') }} ({{ modules.length }} {{ t('modules_active_suffix') }})</span>
                        </h3>
                        <p class="panel-subtitle">{{ t('modules_desc') }}</p>
                    </div>
                    <div class="d-flex flex-wrap gap-2">
                        <button
                            type="button"
                            v-for="cat in moduleCategories"
                            :key="cat.key"
                            class="filter-btn"
                            :class="{ active: selectedModuleCategory === cat.key }"
                            @click="$emit('update:selectedModuleCategory', cat.key)"
                        >
                            {{ t(cat.labelKey) }}
                        </button>
                    </div>
                </div>

                <div class="row g-3">
                    <div class="col-12 col-md-6 col-xl-4" v-for="m in filteredModules" :key="m.name">
                        <div class="module-card">
                            <div>
                                <div class="module-card-top">
                                    <div class="module-card-title">
                                        <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><rect x="3" y="3" width="7" height="7"></rect><rect x="14" y="3" width="7" height="7"></rect><rect x="14" y="14" width="7" height="7"></rect><rect x="3" y="14" width="7" height="7"></rect></svg>
                                        <span>{{ t(m.name + '_title') }}</span>
                                    </div>
                                    <span class="status-capsule status-active">{{ t('status_active') }}</span>
                                </div>
                                <p class="module-card-desc">{{ t(m.name + '_desc') }}</p>
                            </div>
                            <div class="module-card-footer">
                                <span class="status-capsule status-orange">{{ t('cat_' + m.categoryKey) }}</span>
                                <code class="module-file-path">{{ m.file }}</code>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `
    };
})(window);
