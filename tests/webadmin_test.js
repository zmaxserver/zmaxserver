const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

console.log('=== ZMAX WEBADMIN KAPSAMLI ENTEGRASYON VE ARAYÜZ TESTİ ===\n');

const adminDir = path.resolve(__dirname, '..', 'admin');
const jsDir = path.join(adminDir, 'js');
const viewsDir = path.join(jsDir, 'views');
const nodeBin = process.execPath;

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

// 1. JS Sözdizimi Testleri (node --check)
console.log('--- 1. JavaScript Dosyaları Sözdizimi Kontrolü (node --check) ---');
function getJsFiles(dir) {
  let results = [];
  const list = fs.readdirSync(dir);
  for (const file of list) {
    const fullPath = path.join(dir, file);
    const stat = fs.statSync(fullPath);
    if (stat.isDirectory()) {
      results = results.concat(getJsFiles(fullPath));
    } else if (file.endsWith('.js') && !file.includes('.min.') && !file.includes('vue.global')) {
      results.push(fullPath);
    }
  }
  return results;
}

const jsFiles = getJsFiles(jsDir);
for (const file of jsFiles) {
  const relPath = path.relative(adminDir, file);
  try {
    execSync(`"${nodeBin}" --check "${file}"`, { stdio: 'pipe' });
    assert(true, `Sözdizimi geçerli: ${relPath}`);
  } catch (err) {
    assert(false, `Sözdizimi hatası: ${relPath}`, err.message);
  }
}

// 2. Görünüm (Views) Dosyaları Varlığı ve Export Kontrolü
console.log('\n--- 2. Görünüm Dosyaları ve Bileşen Kontrolü ---');
const expectedViews = [
  'server_config.js',
  'listeners.js',
  'templates.js',
  'livestats.js',
  'vhosts.js',
  'dashboard.js',
  'cache_waf.js',
  'logs.js',
  'modules.js',
  'settings.js'
];

for (const v of expectedViews) {
  const vPath = path.join(viewsDir, v);
  const exists = fs.existsSync(vPath);
  assert(exists, `Görünüm dosyası mevcut: admin/js/views/${v}`);
  if (exists) {
    const content = fs.readFileSync(vPath, 'utf8');
    const hasViewDef = content.includes('const ') || content.includes('window.') || content.includes('export ');
    assert(hasViewDef && (content.includes('template:') || content.includes('template =') || content.includes('template')), `Bileşen şablonu/tanımı mevcut: ${v}`);
  }
}

// 3. index.html DOM Yapısı ve Menü Eşleşmesi Kontrolü
console.log('\n--- 3. index.html Sekme & Menü & Reload Buton Kontrolü ---');
const indexHtmlPath = path.join(adminDir, 'index.html');
assert(fs.existsSync(indexHtmlPath), 'admin/index.html mevcut');
const indexHtml = fs.readFileSync(indexHtmlPath, 'utf8');

// Sol menü sekmeleri kontrolü
const requiredTabs = ['server_config', 'listeners', 'templates', 'livestats'];
for (const tab of requiredTabs) {
  const tabInHtml = indexHtml.includes(`'${tab}'`) || indexHtml.includes(`"${tab}"`) || indexHtml.includes(`switchTab('${tab}')`) || indexHtml.includes(`currentTab === '${tab}'`) || indexHtml.includes(`currentTab = '${tab}'`);
  assert(tabInHtml, `Sol menüde '${tab}' sekmesi tanımlı ve switchTab ile bağlı`);
}

// Graceful Reload butonu kontrolü
const hasReloadButton = indexHtml.includes('triggerGracefulReload') || indexHtml.includes('gracefulReload');
assert(hasReloadButton, "Üst barda veya menüde 'Graceful Reload' butonu ve tetikleyicisi mevcut");

// Script yükleme etiketleri kontrolü
for (const v of expectedViews) {
  const hasScriptTag = indexHtml.includes(`views/${v}`);
  assert(hasScriptTag, `index.html içinde <script src="js/views/${v}"> etiketi mevcut`);
}

// 4. app.js Entegrasyon ve Yönlendirme Kontrolü
console.log('\n--- 4. app.js View Bileşenleri ve Metot Kontrolü ---');
const appJsPath = path.join(jsDir, 'app.js');
assert(fs.existsSync(appJsPath), 'admin/js/app.js mevcut');
const appJs = fs.readFileSync(appJsPath, 'utf8');

// Check graceful reload method
const hasGracefulMethod = appJs.includes('triggerGracefulReload') || appJs.includes('gracefulReload');
assert(hasGracefulMethod, 'app.js içinde graceful reload fonksiyonu tanımlı');

// Check tab definitions / view registrations
for (const tab of requiredTabs) {
  const isTabHandled = appJs.includes(tab);
  assert(isTabHandled, `app.js içinde '${tab}' sekmesi veya görünümü işleniyor`);
}

// 5. i18n.js 5 Dil (TR, EN, DE, FR, RU) Simetri ve Bütünlük Kontrolü
console.log('\n--- 5. i18n.js Çoklu Dil (TR, EN, DE, FR, RU) Simetri Denetimi ---');
const i18nPath = path.join(jsDir, 'i18n.js');
assert(fs.existsSync(i18nPath), 'admin/js/i18n.js mevcut');

// Load i18n object in Node sandbox
let i18nObj = null;
try {
  const i18nCode = fs.readFileSync(i18nPath, 'utf8');
  const vm = require('vm');
  const sandbox = { window: {}, console: console };
  vm.createContext(sandbox);
  vm.runInContext(i18nCode, sandbox);
  i18nObj = sandbox.window.ZMaxI18n ? sandbox.window.ZMaxI18n.translations : (sandbox.translations || sandbox.I18N);
} catch (e) {
  console.error('i18n yükleme hatası:', e);
}

assert(i18nObj !== null, 'i18n nesnesi başarıyla ayrıştırıldı');

if (i18nObj) {
  const languages = ['tr', 'en', 'de', 'fr', 'ru'];
  for (const lang of languages) {
    assert(!!i18nObj[lang], `Dil sözlüğü mevcut: ${lang.toUpperCase()}`);
  }

  const trKeys = Object.keys(i18nObj['tr'] || {}).sort();
  console.log(`TR sözlük toplam anahtar sayısı: ${trKeys.length}`);

  for (const lang of languages) {
    if (lang === 'tr') continue;
    const currentKeys = Object.keys(i18nObj[lang] || {}).sort();
    const missingInCurrent = trKeys.filter(k => !(k in i18nObj[lang]));
    const extraInCurrent = currentKeys.filter(k => !(k in i18nObj['tr']));

    assert(missingInCurrent.length === 0, `${lang.toUpperCase()} sözlüğünde eksik anahtar yok (Eksik: ${missingInCurrent.length})`, missingInCurrent.slice(0, 5).join(', '));
    assert(extraInCurrent.length === 0, `${lang.toUpperCase()} sözlüğünde fazlalık anahtar yok (Fazla: ${extraInCurrent.length})`, extraInCurrent.slice(0, 5).join(', '));
    assert(currentKeys.length === trKeys.length, `${lang.toUpperCase()} ve TR anahtar sayıları birebir eşit (${currentKeys.length} === ${trKeys.length})`);
  }

  // Yeni menü ve OLS bileşen anahtarları kontrolü
  const crucialKeys = [
    'nav_server_config',
    'nav_listeners',
    'nav_templates',
    'nav_livestats',
    'btn_graceful_reload',
    'btn_reloading',
    'notice_reload_trigger',
    'notice_reload_success'
  ];
  for (const k of crucialKeys) {
    let allHave = true;
    for (const lang of languages) {
      if (!i18nObj[lang] || !i18nObj[lang][k]) {
        allHave = false;
        break;
      }
    }
    assert(allHave, `Kritik anahtar '${k}' 5 dilde eksiksiz tanımlı`);
  }
}

// 6. Test Özeti
console.log('\n==================================================');
console.log(`TEST SONUÇLARI: Toplam: ${totalTests} | Başarılı: ${passedTests} | Başarısız: ${failedTests}`);
console.log('==================================================');

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log('\nTÜM WEBADMIN ARAYÜZ VE ENTEGRASYON TESTLERİ BAŞARIYLA GEÇTİ!');
  process.exit(0);
}
