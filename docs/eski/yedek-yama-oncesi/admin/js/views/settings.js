// ZMax WebAdmin - Yapılandırma / Ayarlar Görünümü
// Mevcut ekran koruma: Dinleyici portları, mimalloc, fastcgi, toml bilgisi

(function (window) {
    'use strict';

    window.ZMaxViewSettings = {
        name: 'ViewSettings',
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
        template: `
            <div class="panel-card">
                <div class="panel-header">
                    <h3 class="panel-title">
                        <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path></svg>
                        <span>{{ t('settings_title') }}</span>
                    </h3>
                </div>
                <div class="settings-list">
                    <div>• <span class="text-muted-custom">{{ t('lbl_web_listener') }}:</span> <strong class="text-orange">{{ stats.listeners && stats.listeners.http ? stats.listeners.http : '0.0.0.0:19480' }}</strong></div>
                    <div>• <span class="text-muted-custom">{{ t('lbl_admin_listener') }}:</span> <strong class="text-orange">{{ stats.listeners && stats.listeners.admin ? stats.listeners.admin : '127.0.0.1:19485' }}</strong></div>
                    <div>• <span class="text-muted-custom">{{ t('lbl_api_listener') }}:</span> <strong class="text-orange">{{ stats.listeners && stats.listeners.api ? stats.listeners.api : '127.0.0.1:19486' }}</strong></div>
                    <div>• <span class="text-muted-custom">{{ t('lbl_allocator') }}:</span> <strong>mimalloc (~12 MB {{ t('lbl_idle') }})</strong></div>
                    <div>• <span class="text-muted-custom">{{ t('lbl_fastcgi') }}:</span> <strong>127.0.0.1:9000</strong></div>
                    <div>• <span class="text-muted-custom">{{ t('lbl_config_file') }}:</span> <code>conf/zmax.toml</code></div>
                </div>
            </div>
        `
    };
})(window);
