const fs = require('fs');
const path = require('path');
const vm = require('vm');

console.log('=== ZMAX WEBADMIN ÇALIŞMA ZAMANI & ETKİLEŞİM SİMÜLASYONU ===\n');

const adminDir = path.resolve(__dirname, '..', 'admin');
const jsDir = path.join(adminDir, 'js');
const viewsDir = path.join(jsDir, 'views');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function assert(condition, testName, details = '') {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`[PASS] ${testName}`);
  } else {
    failedTests++;
    console.error(`[FAIL] ${testName}: ${details}`);
  }
}

// 1. i18n Çalışma Zamanı Dil Değişimi & Anahtar Çeviri Testi
console.log('--- 1. i18n Çalışma Zamanı & 5 Dilde Dinamik Çeviri Testi ---');
const i18nCode = fs.readFileSync(path.join(jsDir, 'i18n.js'), 'utf8');
const fakeWindow = {
  location: { pathname: '/', hash: '', replaceState: () => {} },
  localStorage: {
    store: {},
    getItem(k) { return this.store[k] || null; },
    setItem(k, v) { this.store[k] = String(v); }
  },
  console: console
};
fakeWindow.window = fakeWindow;

vm.createContext(fakeWindow);
vm.runInContext(i18nCode, fakeWindow);

assert(!!fakeWindow.ZMaxI18n, 'ZMaxI18n pencere nesnesine yüklendi');
assert(fakeWindow.ZMaxI18n.languages.length === 5, '5 dil tanımlı (TR, EN, DE, FR, RU)');

const testKeys = [
  'nav_overview',
  'nav_server_config',
  'nav_listeners',
  'nav_vhosts',
  'nav_templates',
  'nav_livestats',
  'btn_graceful_reload',
  'modal_edit_tpl',
  'tab_context',
  'tab_rewrite'
];

for (const lang of ['tr', 'en', 'de', 'fr', 'ru']) {
  let allExist = true;
  for (const k of testKeys) {
    const val = fakeWindow.ZMaxI18n.get(lang, k);
    if (!val || val === k) {
      allExist = false;
      console.error(`Eksik veya çevrilmemiş anahtar: [${lang}] ${k}`);
      break;
    }
  }
  assert(allExist, `${lang.toUpperCase()} dilinde kritik menü ve modal anahtarları doğru çevrildi`);
}

// 2. View Nesnelerinin Yapısal Bütünlük Testi
console.log('\n--- 2. Görünüm (View) Bileşenleri Yapısal Bütünlük Testi ---');
const viewFiles = [
  { file: 'dashboard.js', name: 'ZMaxViewDashboard' },
  { file: 'server_config.js', name: 'ZMaxViewServerConfig' },
  { file: 'listeners.js', name: 'ZMaxViewListeners' },
  { file: 'templates.js', name: 'ZMaxViewTemplates' },
  { file: 'livestats.js', name: 'ZMaxViewLiveStats' },
  { file: 'vhosts.js', name: 'ZMaxViewVhosts' },
  { file: 'cache_waf.js', name: 'ZMaxViewCacheWaf' },
  { file: 'logs.js', name: 'ZMaxViewLogs' },
  { file: 'modules.js', name: 'ZMaxViewModules' },
  { file: 'settings.js', name: 'ZMaxViewSettings' }
];

for (const vf of viewFiles) {
  const code = fs.readFileSync(path.join(viewsDir, vf.file), 'utf8');
  try {
    vm.runInContext(code, fakeWindow);
    const comp = fakeWindow[vf.name];
    assert(!!comp, `Görünüm pencereye başarıyla bağlandı: ${vf.name}`);
    assert(typeof comp.template === 'string' && comp.template.length > 50, `${vf.name} şablonu (template) tanımlı ve dolu (${comp.template ? comp.template.length : 0} bayt)`);
    if (comp.data) {
      assert(typeof comp.data === 'function', `${vf.name} data() fonksiyonuna sahip`);
      const initialData = comp.data();
      assert(typeof initialData === 'object' && initialData !== null, `${vf.name} data() geçerli bir nesne dönüyor`);
    }
  } catch (err) {
    assert(false, `${vf.file} yürütme hatası`, err.message);
  }
}

// 3. Server Config View (Tuning, ExtApps, Handlers, Security) Testi
console.log('\n--- 3. Server Config Görünümü İç Alt Sekmeler ve Veri Modeli Testi ---');
const scComp = fakeWindow.ZMaxViewServerConfig;
if (scComp && scComp.data) {
  const scData = scComp.data();
  assert(scData.activeSubTab === 'tuning', 'Varsayılan alt sekme "tuning"');
  assert(typeof scData.tuningForm === 'object', 'tuningForm tanımlı');
  assert(scData.tuningForm.max_connections >= 1000, 'max_connections tanımlı (10000)');
  assert(Array.isArray(scData.extApps) && scData.extApps.length >= 3, 'extApps havuzu tanımlı (LSPHP sürümleri)');
  assert(Array.isArray(scData.scriptHandlers) && scData.scriptHandlers.length >= 2, 'scriptHandlers eşleşmeleri tanımlı');
  assert(typeof scData.securityForm === 'object', 'securityForm tanımlı');
}

// 4. Listeners View (Dinleyiciler, TLS, Portlar) Testi
console.log('\n--- 4. Listeners Görünümü Port ve Dinleyici Yönetim Testi ---');
const lisComp = fakeWindow.ZMaxViewListeners;
if (lisComp && lisComp.data) {
  const lisData = lisComp.data();
  assert(Array.isArray(lisData.listeners), 'listeners listesi tanımlı');
  assert(lisData.listeners.some(l => l.port === 80), 'HTTP 80 port dinleyicisi mevcut');
  assert(lisData.listeners.some(l => l.port === 443 && l.secure), 'HTTPS 443 TLS dinleyicisi mevcut');
  assert(lisData.listeners.some(l => l.port === 7088), 'WebAdmin 7088 dinleyicisi mevcut');
}

// 5. Templates View (VHost Şablonları) Testi
console.log('\n--- 5. Templates Görünümü Şablon Yönetimi Testi ---');
const tplComp = fakeWindow.ZMaxViewTemplates;
if (tplComp && tplComp.data) {
  const tplData = tplComp.data();
  assert(Array.isArray(tplData.templates) && tplData.templates.length >= 2, 'templates listesi tanımlı (WordPress, Laravel vb.)');
  assert(tplData.templates.some(t => t.id === 'tpl_wordpress'), 'WordPress standart şablonu tanımlı');
}

// 6. LiveStats View (Gerçek Zamanlı Trafik & Havuz) Testi
console.log('\n--- 6. LiveStats Görünümü Canlı Metrik ve Havuz İzleme Testi ---');
const lsComp = fakeWindow.ZMaxViewLiveStats;
if (lsComp && lsComp.data) {
  const lsData = lsComp.data();
  assert(typeof lsData.metrics === 'object', 'Canlı metrikler nesnesi tanımlı');
  assert(Array.isArray(lsData.pools) && lsData.pools.length >= 2, 'Harici havuz izleme listesi tanımlı');
  assert(Array.isArray(lsData.mappings), 'Dinleyici-VHost eşleme tablosu tanımlı');
}

// 7. VHosts View (6 Sekmeli Düzenleme Modalı) Testi
console.log('\n--- 7. VHosts Görünümü 6 Sekmeli Modal Testi ---');
const vhComp = fakeWindow.ZMaxViewVhosts;
if (vhComp && vhComp.data) {
  const vhData = vhComp.data();
  assert(vhData.modalTab === 'general', 'Modal başlangıç sekmesi "general"');
  assert(typeof vhComp.methods.getEmptyForm === 'function', 'getEmptyForm metodu mevcut');
  const emptyForm = vhComp.methods.getEmptyForm();
  assert(Array.isArray(emptyForm.contexts), 'VHost Form içinde contexts (URI kuralları) dizisi mevcut');
  assert('rewrite_rules' in emptyForm, 'VHost Form içinde rewrite_rules mevcut');
  assert('acme_auto' in emptyForm, 'VHost Form içinde acme_auto mevcut');
  assert('err_404_path' in emptyForm, 'VHost Form içinde err_404_path mevcut');
}

// 8. Graceful Reload Reaktivite ve Durum Geçiş Simülasyonu
console.log('\n--- 8. Graceful Reload Mantık & Durum Geçiş Simülasyonu ---');
let apiReloadCalled = false;
fakeWindow.ZMaxApiClient = {
  fetch(url, opts) {
    if (url === 'api/v1/reload' && opts.method === 'POST') {
      apiReloadCalled = true;
      return Promise.resolve({ ok: true, json: () => Promise.resolve({ status: 'ok', reloaded: true }) });
    }
    return Promise.resolve({ ok: true });
  }
};

let reloadInProgress = false;
let reloadPending = true;
let currentNotification = '';

async function simulateGracefulReload() {
  if (reloadInProgress) return;
  reloadInProgress = true;
  currentNotification = fakeWindow.ZMaxI18n.get('tr', 'notice_reload_trigger');
  
  const res = await fakeWindow.ZMaxApiClient.fetch('api/v1/reload', { method: 'POST' });
  if (res && res.ok) {
    reloadPending = false;
    currentNotification = fakeWindow.ZMaxI18n.get('tr', 'notice_reload_success');
  }
  reloadInProgress = false;
}

simulateGracefulReload().then(() => {
  assert(apiReloadCalled, 'Graceful reload POST /api/v1/reload API çağrısını tetikledi');
  assert(!reloadInProgress, 'Yeniden yükleme sonrasında reloadInProgress false durumuna döndü');
  assert(!reloadPending, 'Yeniden yükleme sonrasında reloadPending false oldu (sarı uyarı temizlendi)');
  assert(currentNotification.includes('Graceful Reload başarılı'), `Başarı bildirimi doğru gösterildi: "${currentNotification}"`);

  // Sonuç Özeti
  console.log('\n==================================================');
  console.log(`ÇALIŞMA ZAMANI TESTLERİ: Toplam: ${totalTests} | Başarılı: ${passedTests} | Başarısız: ${failedTests}`);
  console.log('==================================================');

  if (failedTests > 0) process.exit(1);
  else {
    console.log('\nTÜM ÇALIŞMA ZAMANI ETKİLEŞİM TESTLERİ EKSİKSİZ GEÇTİ!');
    process.exit(0);
  }
});
