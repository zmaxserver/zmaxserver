// ZMax WebAdmin - Önbellek ve WAF / Güvenlik Görünümü
// U6 Bileşeni: Purge (tümü, URL/domain, tag) + Ban / Unban listesi

(function (window) {
    'use strict';

    window.ZMaxViewCacheWaf = {
        name: 'ViewCacheWaf',
        props: {
            mode: {
                type: String,
                default: 'both' // 'cache', 'security' veya 'both'
            },
            bannedIps: {
                type: Array,
                required: true
            },
            t: {
                type: Function,
                required: true
            }
        },
        emits: ['purge-all', 'purge-url', 'unban-ip', 'show-notice'],
        data() {
            return {
                purgeUrlInput: '',
                purgeTagInput: '',
                purging: false,
                unbanningIp: ''
            };
        },
        methods: {
            async purgeAll() {
                if (this.purging) return;
                this.purging = true;
                try {
                    const res = await window.ZMaxApiClient.purgeAll();
                    if (res && res.ok) {
                        this.$emit('show-notice', this.t('notice_purged_all'));
                        this.$emit('purge-all');
                    } else {
                        this.$emit('show-notice', this.t('notice_purge_error'));
                    }
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_purge_error'));
                } finally {
                    this.purging = false;
                }
            },
            async purgeSpecificUrl() {
                const key = this.purgeUrlInput.trim();
                if (!key || this.purging) return;
                this.purging = true;
                try {
                    const res = await window.ZMaxApiClient.purgeSpecific({ uri: key });
                    if (res && res.ok) {
                        this.$emit('show-notice', `${key} — ${this.t('notice_purged_url')}`);
                        this.purgeUrlInput = '';
                        this.$emit('purge-url', key);
                    } else {
                        this.$emit('show-notice', this.t('notice_purge_error'));
                    }
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_purge_error'));
                } finally {
                    this.purging = false;
                }
            },
            async purgeSpecificTag() {
                const tag = this.purgeTagInput.trim();
                if (!tag || this.purging) return;
                this.purging = true;
                try {
                    const res = await window.ZMaxApiClient.purgeSpecific({ tag });
                    if (res && res.ok) {
                        this.$emit('show-notice', `Tag: ${tag} — ${this.t('notice_purged_url')}`);
                        this.purgeTagInput = '';
                        this.$emit('purge-url', `tag:${tag}`);
                    } else {
                        this.$emit('show-notice', this.t('notice_purge_error'));
                    }
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_purge_error'));
                } finally {
                    this.purging = false;
                }
            },
            async unban(ip) {
                if (!ip || this.unbanningIp) return;
                this.unbanningIp = ip;
                try {
                    const res = await window.ZMaxApiClient.unbanIp(ip);
                    let data = null;
                    try {
                        data = await res.json();
                    } catch (_) {
                        data = null;
                    }
                    if (res && res.ok && (!data || data.ok !== false)) {
                        this.$emit('show-notice', `${ip} — ${this.t('notice_unbanned')}`);
                        this.$emit('unban-ip', ip);
                    } else {
                        this.$emit('show-notice', this.t('notice_unban_error'));
                    }
                } catch (_) {
                    this.$emit('show-notice', this.t('notice_unban_error'));
                } finally {
                    this.unbanningIp = '';
                }
            }
        },
        template: `
            <div>
                <!-- 1. ÖNBELLEK YÖNETİCİSİ (CACHE) -->
                <div v-if="mode === 'cache' || mode === 'both'" class="panel-card mb-4">
                    <div class="panel-header">
                        <div>
                            <h3 class="panel-title">
                                <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon></svg>
                                <span>{{ t('cache_title') }}</span>
                            </h3>
                            <p class="panel-subtitle">{{ t('cache_desc') }}</p>
                        </div>
                        <button type="button" class="btn-zmax btn-danger-zmax" :disabled="purging" @click="purgeAll">
                            {{ t('cache_purge_btn') }}
                        </button>
                    </div>

                    <div class="purge-box">
                        <h4 class="purge-box-title">{{ t('cache_purge_title') }}</h4>
                        <div class="d-flex flex-column flex-sm-row gap-2 mb-2">
                            <input
                                type="text"
                                v-model="purgeUrlInput"
                                @keyup.enter="purgeSpecificUrl"
                                :placeholder="t('cache_purge_placeholder')"
                                class="zmax-input flex-grow-1"
                            >
                            <button type="button" class="btn-zmax btn-orange" :disabled="purging || !purgeUrlInput.trim()" @click="purgeSpecificUrl">
                                {{ t('cache_purge_one') }}
                            </button>
                        </div>
                        <div class="d-flex flex-column flex-sm-row gap-2">
                            <input
                                type="text"
                                v-model="purgeTagInput"
                                @keyup.enter="purgeSpecificTag"
                                placeholder="Tag bazlı temizleme: örn. api, static"
                                class="zmax-input flex-grow-1"
                            >
                            <button type="button" class="btn-zmax btn-ghost" :disabled="purging || !purgeTagInput.trim()" @click="purgeSpecificTag">
                                Tag Temizle
                            </button>
                        </div>
                    </div>

                    <div class="row g-3">
                        <div class="col-12 col-md-6">
                            <div class="cache-tier-card">
                                <strong class="text-white-custom">{{ t('cache_l1_title') }}</strong>
                                <div class="cache-tier-desc">{{ t('cache_l1_desc') }}</div>
                                <span class="status-capsule status-active">{{ t('status_active') }}</span>
                            </div>
                        </div>
                        <div class="col-12 col-md-6">
                            <div class="cache-tier-card">
                                <strong class="text-white-custom">{{ t('cache_l2_title') }}</strong>
                                <div class="cache-tier-desc"><code>cachedata/</code> — {{ t('cache_l2_desc') }}</div>
                                <span class="status-capsule status-active">{{ t('status_ready') }}</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 2. GÜVENLİK / WAF BANLARI (SECURITY) -->
                <div v-if="mode === 'security' || mode === 'both'" class="panel-card">
                    <div class="panel-header">
                        <div>
                            <h3 class="panel-title">
                                <svg class="icon panel-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                                <span>{{ t('waf_title') }}</span>
                            </h3>
                            <p class="panel-subtitle">{{ t('waf_desc') }}</p>
                        </div>
                        <span class="status-capsule status-active">{{ t('waf_shield_active') }}</span>
                    </div>

                    <div>
                        <h4 class="waf-section-title">{{ t('waf_banned_ips') }}</h4>
                        <div class="table-responsive">
                            <table class="zmax-table">
                                <thead>
                                    <tr>
                                        <th>{{ t('th_ip') }}</th>
                                        <th>{{ t('th_reason') }}</th>
                                        <th>{{ t('th_date') }}</th>
                                        <th>{{ t('th_action') }}</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="b in bannedIps" :key="b.ip">
                                        <td><strong>{{ b.ip }}</strong></td>
                                        <td><span class="status-capsule status-danger">{{ t(b.reasonKey) || b.reason || 'WAF' }}</span></td>
                                        <td>{{ t('today_label') }} {{ b.time }}</td>
                                        <td>
                                            <!-- İkonlu Unban Butonu (title + aria-label) -->
                                            <button
                                                type="button"
                                                class="btn-zmax btn-ghost btn-sm-compact d-inline-flex align-items-center gap-1"
                                                :disabled="unbanningIp === b.ip"
                                                @click="unban(b.ip)"
                                                :title="t('btn_unban') + ' (' + b.ip + ')'"
                                                :aria-label="t('btn_unban') + ' - ' + b.ip"
                                            >
                                                <svg class="icon icon-sm text-orange" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                                    <path d="M7 11V7a5 5 0 0 1 9.9-1"></path>
                                                </svg>
                                                <span>{{ t('btn_unban') }}</span>
                                            </button>
                                        </td>
                                    </tr>
                                    <tr v-if="!bannedIps || bannedIps.length === 0">
                                        <td colspan="4" class="text-center text-muted-custom py-3">
                                            Aktif engellenmiş IP adresi bulunmuyor.
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        `
    };
})(window);
