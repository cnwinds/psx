import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {test} from 'node:test';
import {elfldrGetRequest, initializePayloadSender, payloadFetchUrl, runAutoChain} from './src/payload_loader.js';

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
    'plan-mode', 'elf-rows',
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
  assert.doesNotMatch(site, /jb-retry|textarea|autorun-opt|!payloadPanelReady && act/);
  const ready = site.slice(site.indexOf('function enterReady'), site.indexOf('function startMatrixRain'));
  assert.match(ready, /id="jb-start"/);
  assert.match(ready, /if \(rejection\)/);
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

