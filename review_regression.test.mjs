import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {test} from 'node:test';
import {catalogPayloadUrl, firmwareMatches, githubReleaseUrl, loadGithubRelease, parsePayloadMap, payloadStoreUrl, savePayloadToHost, searchCatalog} from './src/catalog.js';
import {addCatalogEntry, addExtra, commitVersionUpdates, itemById, listedReleaseItems, loadPlan, planReleaseUpdate, planVersionUpdates, removeFromPlan, resetPlan, searchWithPinned} from './src/elfplan.js';
import {elfldrGetRequest, elfldrPortOpen, initializePayloadSender, payloadFetchUrl, payloadUrlForItem, runAutoChain} from './src/payload_loader.js';

test('PS5 启动：仅认浏览器 UA，不凭端口分支，一律进入可点击提权', async () => {
  const file = readFileSync(new URL('./src/site.js', import.meta.url), 'utf8');
  const source = file.slice(0, file.lastIndexOf('\nboot().catch('))
    .replace(/^import .*$/gm, '');
  const events = [];
  let response = {ip: '192.168.1.2', ports: {'8080': true}};
  const consoleNode = {appendChild() {}, scrollTop: 0, scrollHeight: 0};
  const context = {
    navigator: {userAgent: 'PlayStation 5'},
    window: {firmware: {rejection: () => null}, fw_str: '13.60'},
    location: {search: '', hostname: '192.168.1.2', origin: 'http://localhost'},
    document: {
      getElementById: id => id === 'console' ? consoleNode : {addEventListener() {}},
      createElement: () => ({textContent: ''}),
    },
    URLSearchParams,
    fetch: async () => ({json: async () => response}),
    loadPlan: () => ({order: [], off: new Set()}),
    savePlan() {}, resetPlan() {}, itemById() {}, formatSize() {},
  };
  const sandbox = {...context, observed: events};
  runInNewContext(source + `
    renderRows = () => {};
    updatePlanMode = () => {};
    enterPartial = () => observed.push('partial');
    enterUnknown = () => observed.push('unknown');
    enterReady = () => observed.push('ready');
    enterJailbroken = () => observed.push('jailbroken');
    globalThis.runBoot = boot;
  `, sandbox);
  await sandbox.runBoot();
  assert.deepEqual(events, ['ready']);
  response = {ip: '192.168.1.2'};
  await sandbox.runBoot();
  assert.deepEqual(events, ['ready', 'ready']);
  response = {ip: '192.168.1.2', ports: {'9021': true}};
  await sandbox.runBoot();
  assert.deepEqual(events, ['ready', 'ready', 'ready']);
});

test('发送链按勾选顺序运行，首个 ELF 失败即停止且按钮恢复', async () => {
  const requested = [];
  const button = {disabled: false, addEventListener() {}};
  globalThis.localStorage = {
    getItem: () => JSON.stringify({order: ['kstuff', 'smp'], off: ['websrv']}),
  };
  globalThis.window = {writeLog() {}, setElfRowState() {}, canTrustPortProbe: () => false};
  globalThis.document = {
    getElementById: id => id === 'btn-runplan' ? button : {checked: false},
    querySelectorAll: () => [],
  };
  globalThis.fetch = async url => {
    requested.push(url);
    if (url === '/api/jbstate') {
      return {json: async () => ({ports: {}})};
    }
    return {ok: false, status: 503};
  };
  initializePayloadSender({}, {});
  await runAutoChain();
  assert.equal(requested.filter(url => url.startsWith('payloads/')).length, 0);
  assert.equal(button.disabled, false);
});

test('本站 ELF 地址：内网 HTTPS 改走 80，公网 HTTPS 保持不变', () => {
  assert.equal(
    payloadFetchUrl('kstuff.elf', 'https://manuals.playstation.net/'),
    'http://manuals.playstation.net/payloads/kstuff.elf',
  );
  assert.equal(
    payloadFetchUrl('panplay.elf', 'https://192.168.1.250/index.html'),
    'http://192.168.1.250/payloads/panplay.elf',
  );
  assert.equal(
    payloadFetchUrl('ftpsrv.elf', 'https://user.github.io/psx/'),
    'https://user.github.io/psx/payloads/ftpsrv.elf',
  );
  assert.equal(
    payloadFetchUrl('kstuff.elf', 'http://192.168.1.2:8000/'),
    'http://192.168.1.2:8000/payloads/kstuff.elf',
  );
  assert.equal(
    payloadFetchUrl('library/etaHEN.elf', 'https://manuals.playstation.net/'),
    'http://manuals.playstation.net/payloads/library/etaHEN.elf',
  );
  assert.throws(() => payloadFetchUrl('library/../kstuff.elf'));
  assert.throws(() => payloadFetchUrl('library/a/b.elf'));
  const req = elfldrGetRequest('http://manuals.playstation.net/payloads/kstuff.elf');
  assert.match(req, /^GET \/\?uri=http%3A%2F%2Fmanuals\.playstation\.net%2Fpayloads%2Fkstuff\.elf HTTP\/1\.1\r\n/);
  assert.match(req, /Host: 127\.0\.0\.1:9021\r\nConnection: close\r\n\r\n$/);
});

test('自动加载进行中忽略手动发送', async () => {
  const messages = [];
  const listeners = new Map();
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  globalThis.SYS_SOCKET = 1;
  globalThis.SYS_CONNECT = 2;
  globalThis.SYS_CLOSE = 3;
  globalThis.SYS_WRITE = 4;
  globalThis.SYS_READ = 5;
  globalThis.localStorage = {
    getItem: () => JSON.stringify({order: ['kstuff'], off: ['smp', 'websrv']}),
  };
  globalThis.location = {href: 'https://manuals.playstation.net/'};
  globalThis.window = {writeLog: message => messages.push(message), setElfRowState() {}};
  const rows = {
    addEventListener(_, callback) { listeners.set('click', callback); },
  };
  globalThis.document = {
    getElementById: id => id === 'elf-rows' ? rows : {disabled: false, checked: false, addEventListener() {}},
    querySelectorAll: () => [],
  };
  initializePayloadSender({
    malloc() { return {add32() { return this; }, backing: {set() {}}}; },
    write1() {}, write2() {}, write4() {},
  }, {
    syscall() { return gate.then(() => ({low: -1})); },
  });
  const auto = runAutoChain();
  listeners.get('click')({
    target: {closest: () => ({dataset: {file: 'kstuff.elf'}, disabled: false})},
  });
  assert.match(messages.join('\n'), /自动加载正在运行/);
  release();
  await auto;
});

test('首页保留脚本依赖的 DOM，且不包含 FTP 中转页', () => {
  const home = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const css = readFileSync(new URL('./ui.css', import.meta.url), 'utf8');
  const homeIds = [
    'exploit-status', 'status-title',
    'status-body', 'status-actions', 'rail', 'stage-webkit', 'stage-kernel',
    'stage-elfldr', 'console', 'act-payloads', 'btn-runplan', 'btn-resetplan',
    'plan-mode', 'elf-rows', 'catalog-q', 'catalog-clear', 'catalog-hits', 'catalog-note', 'btn-updatever',
  ];
  assert.match(home, /href="\.\/ui\.css"/);
  const actual = [...home.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(actual).size, actual.length, '静态 id 不得重复');
  for (const id of homeIds) assert.ok(actual.includes(id), `缺少 #${id}`);
  assert.equal(existsSync(new URL('./ftp.html', import.meta.url)), false);
  assert.doesNotMatch(home, /矩阵端口|正在扫描主机|扫描局域网|pcsend|本机网卡|act-services|qr-modal|扫码服务|statebar|终端节点|矩阵状态/);
  assert.doesNotMatch(css, /\.pcsend|\.qr-modal|\.site-nav|#act-services/);
  assert.equal(existsSync(new URL('./src/qrcode.js', import.meta.url)), false);
  assert.doesNotMatch(readFileSync(new URL('./src/site.js', import.meta.url), 'utf8'), /\/api\/jbstate|\/api\/elfsend/);
  assert.doesNotMatch(readFileSync(new URL('./serve.py', import.meta.url), 'utf8'), /ftp_relay/);
  assert.match(css, /#body-exploit\.exploit-row\s*\{[^}]*grid-template-columns:\s*40%\s+minmax\(0,\s*1fr\)/);
  assert.match(css, /\.home-workspace\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)/);
  assert.match(css, /body\.flow-done \.home-workspace\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)/);
  assert.match(css, /\[hidden\].*display: none !important/);
  assert.match(css, /#console div:last-child:not\(\.e\):not\(\.g\)/);
});

test('提权主流程与 Relapse 的 run() 顺序一致', () => {
  const site = readFileSync(new URL('./src/site.js', import.meta.url), 'utf8');
  const main = readFileSync(new URL('./src/main.js', import.meta.url), 'utf8');
  const run = site.slice(site.indexOf('async function runExploit'), site.indexOf('function enterReady'));
  const steps = [
    'window.firmware.rejection()',
    'Credits: Sonic_Iso, Jordy, ntfargo',
    'Agent: ${navigator.userAgent}',
    'Firmware: ${window.fw_str}',
    'await getPrimitive()',
    'WebKit base: 0x${getWebKitBase().toString(16)}',
    'await import("./relapse_exploit.js")',
    'await main(activePrimitive)',
  ];
  let at = 0;
  for (const step of steps) {
    const next = run.indexOf(step, at);
    assert.ok(next > at, `run() 缺少或顺序不对: ${step}`);
    at = next + step.length;
  }
  assert.match(main, /log\("elfldr is listening on port 9021", "info"\)/);
  assert.doesNotMatch(main, /elfldr did not load/);
  const mainFn = main.slice(main.indexOf('async function main'), main.indexOf('const fwScript'));
  const probeAt = mainFn.indexOf('elfldrPortOpen');
  const kernelAt = mainFn.indexOf('runKernelExploit');
  assert.ok(probeAt > 0 && kernelAt > probeAt, '9021 探测必须在内核利用之前');
  assert.doesNotMatch(site, /jb-retry|textarea|autorun-opt|!payloadPanelReady && act/);
  const ready = site.slice(site.indexOf('function enterReady'), site.indexOf('function startMatrixRain'));
  assert.match(ready, /id="jb-start"/);
  assert.match(ready, /if \(rejection\)/);
});

test('9021 只在 connect 成功时视为已监听，并且总会关掉套接字', async () => {
  globalThis.SYS_SOCKET = 0x61;
  globalThis.SYS_CONNECT = 0x62;
  globalThis.SYS_CLOSE = 0x06;
  const addr = { add32() { return addr; } };
  const p = {
    malloc() { return addr; },
    write1() {},
    write2() {},
    write4() {},
  };

  async function probe(responses) {
    const calls = [];
    let i = 0;
    const chain = {
      async syscall(number, ...args) {
        calls.push([number, ...args]);
        const next = responses[i++];
        if (next instanceof Error) throw next;
        return { low: next };
      },
    };
    const open = await elfldrPortOpen(p, chain);
    return { open, calls };
  }

  const up = await probe([5, 0, 0]);
  assert.equal(up.open, true);
  assert.deepEqual(up.calls.map((call) => call[0]), [0x61, 0x62, 0x06]);
  assert.equal(up.calls[2][1], 5);

  const refused = await probe([5, -1, 0]);
  assert.equal(refused.open, false);
  assert.deepEqual(refused.calls.map((call) => call[0]), [0x61, 0x62, 0x06]);

  const noSocket = await probe([-1]);
  assert.equal(noSocket.open, false);
  assert.deepEqual(noSocket.calls.map((call) => call[0]), [0x61]);

  const broken = await probe([new Error('chain failed')]);
  assert.equal(broken.open, false);
});

test('新版工作区保留键盘入口、表单标签与日志语义', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /class="skip-link" href="#workspace"/);
  assert.match(html, /<main id="workspace"[^>]*tabindex="-1"/);
  assert.match(html, /id="console" role="log" aria-live="off"/);
  assert.equal((html.match(/aria-current="page"/g) || []).length, 0);
  const css = readFileSync(new URL('./ui.css', import.meta.url), 'utf8');
  assert.match(css, /prefers-reduced-motion: reduce/);
  assert.doesNotMatch(css, /@import|url\(["']?https?:/);
});

test('全部流程完成后自动折叠 01 和 02', async () => {
  const file = readFileSync(new URL('./src/site.js', import.meta.url), 'utf8');
  const source = file.slice(0, file.lastIndexOf('\nboot().catch('))
    .replace(/^import .*$/gm, '');

  const nodes = {};
  const getEl = (id) => {
    if (!nodes[id]) {
      nodes[id] = {
        id,
        hidden: false,
        textContent: '',
        innerHTML: '',
        value: '',
        href: '',
        dataset: {},
        classList: {
          set: new Set(),
          toggle(cls, force) {
            if (force) this.set.add(cls);
            else this.set.delete(cls);
          },
        },
        addEventListener() {},
        setAttribute() {},
      };
    }
    return nodes[id];
  };
  const bodyClasses = new Set();
  const sandbox = {
    navigator: {userAgent: 'PlayStation 5/10.01'},
    window: {},
    location: {search: '', hostname: '192.168.1.10', origin: 'http://192.168.1.10'},
    document: {
      body: {
        classList: {
          toggle(cls, force) {
            if (force) bodyClasses.add(cls);
            else bodyClasses.delete(cls);
          },
        },
      },
      getElementById: getEl,
      querySelector: () => null,
      createElement: () => ({dataset: {}, appendChild() {}}),
      addEventListener() {},
    },
    URLSearchParams,
    fetch: async () => ({json: async () => ({})}),
    loadPlan: () => ({order: ['kstuff', 'websrv'], off: new Set()}),
    savePlan() {}, resetPlan() {},
    itemById: (id) => ({id, name: id, file: id + '.elf', ver: '1.0', desc: '', src: '', size: 1024}),
    formatSize: () => '1 KB',
  };
  runInNewContext(source, sandbox);

  // 触发全部流程完成回调
  sandbox.window.onFlowComplete({
    ip: '192.168.1.88',
    host_ip: '192.168.1.10',
    http_port: 80,
    ports: {'9021': true, '8080': true},
  });

  // 验证 01、02 已自动折叠，且 body 标记为 flow-done
  assert.equal(bodyClasses.has('flow-done'), true);
  assert.equal(getEl('body-exploit').hidden, true);
  assert.equal(getEl('body-payloads').hidden, true);
  assert.equal(getEl('flow-complete-banner').hidden, false);
  assert.equal(getEl('flow-banner-title').textContent, '组件加载已完成');
});

test('目录只解析数据，加入的 ELF 下载到本站后再加载', () => {
  const text = readFileSync(new URL('./payloads/payload_map.js', import.meta.url), 'utf8');
  const items = parsePayloadMap(text);
  assert.ok(items.length >= 40);
  assert.ok(items.every((item) => /^[A-Za-z0-9._-]+\.(elf|bin)$/i.test(item.file)));
  assert.ok(items.some((item) => item.file === 'install-prospero-store.elf'));
  assert.equal(items.some((item) => item.file === 'elfldr-ps5.elf'), false);
  assert.equal(items.some((item) => /appcache/i.test(item.name)), false);
  const linux = items.find((item) => item.file === 'ps5-linux-loader-13.60.elf');
  assert.ok(linux);
  assert.equal(firmwareMatches(linux, '10.01'), false);
  assert.equal(firmwareMatches(linux, '13.60'), true);
  assert.equal(searchCatalog([linux], 'linux', '10.01').length, 0);
  assert.equal(searchCatalog([linux], 'linux', '').length, 1);
  assert.ok(searchCatalog(items, 'prospero', '13.60').some((item) => item.file === 'install-prospero-store.elf'));
  assert.equal(searchCatalog(items, '', '13.60').length, 0);
  assert.equal(searchCatalog(items, 'eta', '13.60').length <= 8, true);
  assert.equal(catalogPayloadUrl('etaHEN.elf'), 'http://45.56.67.85/payloads/payloads/etaHEN.elf');
  assert.throws(() => catalogPayloadUrl('../x.elf'));
  assert.equal(
    payloadUrlForItem({file: 'etaHEN.elf', extra: true, library: true}, 'https://manuals.playstation.net/'),
    'http://manuals.playstation.net/payloads/library/etaHEN.elf',
  );
  assert.equal(
    payloadUrlForItem({file: 'kstuff.elf'}, 'https://user.github.io/psx/'),
    'https://user.github.io/psx/payloads/kstuff.elf',
  );
  assert.equal(
    payloadStoreUrl('kstuff-lite.elf', 'kstuff.elf', true, 'https://user.github.io/psx/'),
    'https://user.github.io/psx/api/payload/fetch?file=kstuff-lite.elf&save=kstuff.elf&refresh=1',
  );

  const site = readFileSync(new URL('./src/site.js', import.meta.url), 'utf8');
  const loader = readFileSync(new URL('./src/payload_loader.js', import.meta.url), 'utf8');
  assert.doesNotMatch(site, /new Function|\beval\s*\(/);
  assert.doesNotMatch(site, /catalogPayloadUrl/);
  assert.doesNotMatch(loader, /catalogPayloadUrl/);
  assert.match(site, /data-act="add"/);
  assert.match(site, /savePayloadToHost/);
  const startSh = readFileSync(new URL('./selfhost/start.sh', import.meta.url), 'utf8');
  assert.match(startSh, /proxy_pass http:\/\/45\.56\.67\.85\/payloads\/payload_map\.js/);
  assert.match(startSh, /proxy_pass http:\/\/127\.0\.0\.1:8765/);
  assert.match(startSh, /alias \/srv\/payload-library\//);
  const serve = readFileSync(new URL('./serve.py', import.meta.url), 'utf8');
  assert.match(serve, /CATALOG_MAP_URL = "http:\/\/45\.56\.67\.85\/payloads\/payload_map\.js"/);
  assert.match(serve, /\/api\/payload\/fetch/);
  assert.match(readFileSync(new URL('./scripts/payload_store.py', import.meta.url), 'utf8'), /http:\/\/45\.56\.67\.85\/payloads\/payloads\//);

  const previous = globalThis.localStorage;
  const store = new Map();
  globalThis.localStorage = {
    getItem: (key) => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => { store.set(key, value); },
    removeItem: (key) => { store.delete(key); },
  };
  try {
    const plan = loadPlan();
    assert.deepEqual(plan.order, ['kstuff', 'ftpsrv', 'panplay']);
    assert.equal(addExtra(plan, {file: 'kstuff.elf', name: '重复'}), null);
    const added = addExtra(plan, {
      file: 'etaHEN.elf', name: 'etaHEN', ver: '2', desc: 'HEN', author: 'lm', library: true,
    });
    assert.equal(added.id, 'ext:etaHEN.elf');
    assert.equal(added.library, true);
    assert.equal(itemById(added.id).library, true);
    assert.equal(plan.off.has(added.id), false);
    const kept = loadPlan();
    assert.equal(kept.off.has('ext:etaHEN.elf'), false);
    assert.ok(kept.order.includes('ext:etaHEN.elf'));
    const reset = resetPlan();
    assert.ok(reset.order.includes('ext:etaHEN.elf'));
    assert.equal(reset.off.has('ext:etaHEN.elf'), true);
    assert.ok(reset.order.indexOf('panplay') < reset.order.indexOf('ext:etaHEN.elf'));
    removeFromPlan(reset, added.id);
    assert.equal(loadPlan().order.includes('ext:etaHEN.elf'), false);
    const local = loadPlan();
    removeFromPlan(local, 'kstuff');
    assert.equal(loadPlan().order.includes('kstuff'), false);
    assert.equal(loadPlan().order.includes('ftpsrv'), true);
    const restored = resetPlan();
    assert.equal(restored.order.includes('kstuff'), true);
    removeFromPlan(restored, 'kstuff');
    const broughtBack = addCatalogEntry(loadPlan(), {file: 'kstuff.elf'});
    assert.equal(broughtBack.already, false);
    assert.equal(broughtBack.item.id, 'kstuff');
    assert.equal(broughtBack.item.library, undefined);
    const again = loadPlan();
    assert.equal(addCatalogEntry(again, {file: 'kstuff.elf'}).already, true);
    assert.equal(again.order.filter((id) => id === 'kstuff').length, 1);
    const extra = addCatalogEntry(again, {
      file: 'shadowmountplus.elf', name: 'ShadowMountPlus', ver: '1.7beta11', library: true,
    });
    assert.equal(extra.already, false);
    assert.equal(extra.item.id, 'ext:shadowmountplus.elf');
    assert.equal(
      payloadUrlForItem(extra.item, 'https://user.github.io/psx/'),
      'https://user.github.io/psx/payloads/library/shadowmountplus.elf',
    );
    const mixed = searchWithPinned(items, 'kstuff', '13.60');
    assert.equal(mixed[0].pinned, true);
    assert.equal(mixed[0].file, 'kstuff.elf');
    assert.equal(mixed.some((hit) => hit.file === 'kstuff-lite.elf'), false);
    assert.equal(mixed.some((hit) => hit.file === 'shadowmountplus.elf'), true);
    const ftp = searchWithPinned(items, 'ftpsrv', '13.60');
    assert.equal(ftp[0].file, 'ftpsrv.elf');
    assert.equal(ftp[0].pinned, true);
    assert.equal(ftp.some((hit) => hit.file === 'ftpsrv-ps5.elf'), false);
    assert.equal(ftp.some((hit) => hit.file === 'ftpsrv-drakmor_1.16-ng-stable.elf'), true);
    assert.equal(searchWithPinned(items, '', '13.60').length, 0);
  } finally {
    globalThis.localStorage = previous;
  }
});

test('搜索目录后可加入列表，描述按文本显示', async () => {
  const file = readFileSync(new URL('./src/site.js', import.meta.url), 'utf8');
  const source = file.slice(0, file.lastIndexOf('\nboot().catch('))
    .replace(/^import .*$/gm, '');
  const previous = globalThis.localStorage;
  const store = new Map();
  globalThis.localStorage = {
    getItem: (key) => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => { store.set(key, value); },
    removeItem: (key) => { store.delete(key); },
  };
  const nodes = {};
  const make = (id) => {
    let html = '';
    const el = {
      id,
      hidden: false,
      textContent: '',
      value: '',
      placeholder: '',
      disabled: false,
      open: false,
      dataset: {},
      className: '',
      children: [],
      classList: {add() {}, remove() {}, toggle() {}, contains() { return false; }},
      style: {},
      appendChild(child) { this.children.push(child); },
      addEventListener(type, fn) { (this._l || (this._l = {}))[type] = fn; },
      setAttribute() {},
      querySelector() { return null; },
      scrollIntoView() {},
      focus() {},
    };
    Object.defineProperty(el, 'innerHTML', {
      get() { return html; },
      set(v) { html = String(v); this.children = []; },
    });
    return el;
  };
  const getEl = (id) => nodes[id] || (nodes[id] = make(id));
  const saved = [];
  const sandbox = {
    navigator: {userAgent: 'PlayStation 5'},
    window: {firmware: {rejection: () => null}, fw_str: '13.60'},
    location: {search: '', hostname: '127.0.0.1', href: 'http://127.0.0.1/'},
    document: {
      body: {classList: {toggle() {}, add() {}, remove() {}}},
      getElementById: getEl,
      querySelector: () => null,
      createElement: () => make('li'),
      addEventListener() {},
    },
    URLSearchParams,
    fetch: async () => ({ok: false, text: async () => ''}),
    loadPlan, savePlan() {}, resetPlan, itemById,
    formatSize: () => '',
    addCatalogEntry, removeFromPlan,
    loadCatalog: async () => [{
      file: 'etaHEN.elf',
      name: 'etaHEN',
      desc: 'AIO <HEN>',
      author: 'lm',
      ver: '2.5',
      firmwares: [],
    }],
    searchWithPinned,
    savePayloadToHost: async (file) => {
      saved.push(file);
      return {file: 'library/' + file, size: 4};
    },
  };
  runInNewContext(source + '\nglobalThis.__boot = boot;\n', sandbox);
  try {
    await sandbox.__boot();
    const builtinRows = getEl('elf-rows').children.map((li) => li.innerHTML).join('\n');
    for (const ver of ['1.11', '0.21.1', '0.16.4']) {
      assert.match(builtinRows, new RegExp(`class="name-ver"><b>[^<]+</b><span class="ver-tag">${ver.replace(/[.]/g, '\\.')}</span>`));
    }
    assert.doesNotMatch(builtinRows, /1\.7beta11|websrv/);
    assert.doesNotMatch(builtinRows, />必选<|>挂载<|>:2121<|>:8734<|>:8080<|>目录</);
    assert.match(builtinRows, /移除/);
    const kstuff = getEl('elf-rows').children.find((li) => li.dataset.id === 'kstuff');
    const dropBtn = {
      dataset: {act: 'drop'},
      closest(sel) { return String(sel).includes('elf-row') ? kstuff : null; },
    };
    getEl('elf-rows')._l.click({
      target: {
        closest(sel) { return String(sel).includes('data-act') ? dropBtn : null; },
      },
    });
    assert.equal(getEl('elf-rows').children.some((li) => li.dataset.id === 'kstuff'), false);
    assert.equal(loadPlan().order.includes('kstuff'), false);
    const input = getEl('catalog-q');
    input.value = 'kstuff';
    input._l.input();
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.match(getEl('catalog-hits').innerHTML, /kstuff-lite/);
    assert.match(getEl('catalog-hits').innerHTML, />加入</);
    const pinBtn = {
      disabled: false,
      dataset: {file: 'kstuff.elf', act: 'add'},
      closest(sel) { return String(sel).includes('add') ? this : null; },
    };
    await getEl('catalog-hits')._l.click({target: pinBtn});
    assert.deepEqual(saved, []);
    assert.equal(getEl('elf-rows').children.some((li) => li.dataset.id === 'kstuff'), true);
    input.value = 'hen';
    input._l.input();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const hits = getEl('catalog-hits').innerHTML;
    assert.match(hits, /class="name-ver"><b>etaHEN<\/b><span class="ver-tag">2\.5<\/span>/);
    assert.match(hits, /AIO &lt;HEN&gt;/);
    assert.doesNotMatch(hits, /<HEN>/);
    assert.match(hits, />加入</);
    const button = {
      disabled: false,
      dataset: {file: 'etaHEN.elf', act: 'add'},
      closest(sel) { return String(sel).includes('add') ? this : null; },
    };
    await getEl('catalog-hits')._l.click({target: button});
    const row = getEl('elf-rows').children.map((li) => li.innerHTML).join('\n');
    assert.match(row, /data-send="ext:etaHEN.elf"/);
    assert.match(row, /移除/);
    assert.match(getEl('catalog-hits').innerHTML, /已加入/);
    assert.deepEqual(saved, ['etaHEN.elf']);
    assert.equal(getEl('catalog-clear').hidden, false);
    getEl('catalog-clear')._l.click();
    assert.equal(input.value, '');
    assert.equal(getEl('catalog-clear').hidden, true);
    assert.equal(getEl('catalog-hits').hidden, true);
  } finally {
    globalThis.localStorage = previous;
  }
});

test('一键更新把新版本下载到本站 library', async () => {
  const previous = globalThis.localStorage;
  const store = new Map();
  globalThis.localStorage = {
    getItem: (key) => (store.has(key) ? store.get(key) : null),
    setItem: (key, value) => { store.set(key, value); },
    removeItem: (key) => { store.delete(key); },
  };
  try {
    const text = readFileSync(new URL('./payloads/payload_map.js', import.meta.url), 'utf8');
    const items = parsePayloadMap(text);
    const listed = items.find((item) => item.file === 'kstuff-lite.elf');
    assert.match(listed.src, /EchoStretch\/kstuff-lite/);
    assert.deepEqual(planVersionUpdates(items), []);
    assert.equal(itemById('kstuff').library, undefined);
    assert.deepEqual(planVersionUpdates([{
      file: 'panplay.elf', ver: '9.9', src: 'https://github.com/cnwinds/pan-play',
    }]), []);
    assert.deepEqual(listedReleaseItems(['kstuff', 'ftpsrv']), []);
    assert.deepEqual(listedReleaseItems(['kstuff', 'ftpsrv', 'panplay']), [{
      id: 'panplay', repo: 'cnwinds/pan-play', asset: 'panplay-{tag}-ps5.elf',
    }]);
    assert.equal(planReleaseUpdate('panplay', {
      tag: 'v0.16.4', version: '0.16.4', assets: [{name: 'panplay-v0.16.4-ps5.elf'}],
    }), null);
    const newer = planReleaseUpdate('panplay', {
      tag: 'v0.17.0', version: 'v0.17.0', assets: [{name: 'panplay-v0.17.0-ps5.elf'}],
    });
    assert.equal(newer.to, '0.17.0');
    assert.equal(newer.saveAs, 'panplay.elf');
    assert.equal(newer.asset, 'panplay-v0.17.0-ps5.elf');
    assert.equal(newer.repo, 'cnwinds/pan-play');
    assert.equal(newer.revert, false);
    assert.equal(planReleaseUpdate('panplay', {
      tag: 'v0.17.0', version: '0.17.0', assets: [],
    }).missing, true);
    let releaseUrl = '';
    const release = await loadGithubRelease('cnwinds/pan-play', async (url) => {
      releaseUrl = url;
      return {ok: true, json: async () => ({tag: 'v0.17.0', version: '0.17.0', assets: []})};
    }, 'https://psx.ai-news.top/index.html');
    assert.equal(release.tag, 'v0.17.0');
    assert.equal(releaseUrl, githubReleaseUrl('cnwinds/pan-play', 'https://psx.ai-news.top/index.html'));
    assert.equal(releaseUrl, 'https://psx.ai-news.top/api/payload/release?repo=cnwinds%2Fpan-play');

    const changes = planVersionUpdates([{
      file: 'kstuff-lite.elf',
      ver: 'v9.9',
      src: 'https://github.com/EchoStretch/kstuff-lite',
    }, {
      file: 'ftpsrv-drakmor_1.16-ng-stable.elf',
      ver: '1.16-ng-stable',
      src: 'https://github.com/drakmor/ftpsrv',
    }]);
    assert.equal(changes.length, 1);
    assert.equal(changes[0].id, 'kstuff');
    assert.equal(changes[0].from, '1.11');
    assert.equal(changes[0].to, '9.9');
    assert.equal(changes[0].remoteFile, 'kstuff-lite.elf');
    assert.equal(changes[0].saveAs, 'kstuff.elf');
    assert.equal(changes[0].revert, false);
    commitVersionUpdates(changes);
    const updated = itemById('kstuff');
    assert.equal(updated.ver, '9.9');
    assert.equal(updated.file, 'kstuff.elf');
    assert.equal(updated.library, true);
    assert.equal(
      payloadUrlForItem(updated, 'https://user.github.io/psx/'),
      'https://user.github.io/psx/payloads/library/kstuff.elf',
    );
    assert.equal(itemById('ftpsrv').ver, '0.21.1');
    assert.deepEqual(planVersionUpdates([{
      file: 'kstuff-lite.elf',
      ver: '9.9',
      src: 'https://github.com/EchoStretch/kstuff-lite',
    }]), []);
    const revert = planVersionUpdates([{
      file: 'kstuff-lite.elf',
      ver: '1.11',
      src: 'https://github.com/EchoStretch/kstuff-lite',
    }]);
    assert.equal(revert.length, 1);
    assert.equal(revert[0].revert, true);
    commitVersionUpdates(revert);
    assert.equal(itemById('kstuff').ver, '1.11');
    assert.equal(itemById('kstuff').library, undefined);
    let seen = '';
    const stored = await savePayloadToHost('kstuff-lite.elf', 'kstuff.elf', true, async (url) => {
      seen = url;
      return {ok: true, json: async () => ({file: 'library/kstuff.elf', size: 4})};
    }, 'https://manuals.playstation.net/psx/index.html');
    assert.equal(seen, 'https://manuals.playstation.net/psx/api/payload/fetch?file=kstuff-lite.elf&save=kstuff.elf&refresh=1');
    assert.equal(stored.file, 'library/kstuff.elf');
    await assert.rejects(() => savePayloadToHost('etaHEN.elf', '', false, async () => ({
      ok: false,
      json: async () => ({}),
    }), 'http://127.0.0.1/'));
  } finally {
    globalThis.localStorage = previous;
  }
});

