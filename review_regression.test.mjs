import assert from 'node:assert/strict';
import {existsSync, readFileSync} from 'node:fs';
import {runInNewContext} from 'node:vm';
import {test} from 'node:test';
import {initializePayloadSender, runAutoChain} from './src/payload_loader.js';

test('启动状态：8080-only 不自动重跑，缺少 ports 时不自动重跑', async () => {
  const file = readFileSync(new URL('./src/site.js', import.meta.url), 'utf8');
  const source = file.slice(0, file.lastIndexOf('\nboot().catch('))
    .replace(/^import .* from ['"]\.\/elfplan\.js['"];/m, '');
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
  assert.deepEqual(events, ['partial']);
  response = {ip: '192.168.1.2'};
  await sandbox.runBoot();
  assert.deepEqual(events, ['partial', 'unknown']);
  response = {ip: '192.168.1.2', ports: {}};
  await sandbox.runBoot();
  assert.deepEqual(events, ['partial', 'unknown', 'ready']);
});

test('发送链按勾选顺序运行，首个 ELF 失败即停止且按钮恢复', async () => {
  const requested = [];
  const button = {disabled: false, addEventListener() {}};
  globalThis.localStorage = {
    getItem: () => JSON.stringify({order: ['kstuff', 'smp'], off: ['websrv']}),
  };
  globalThis.window = {writeLog() {}, setElfRowState() {}};
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
  assert.equal(requested.filter(url => url.startsWith('payloads/')).length, 1);
  assert.match(requested[1], /kstuff\.elf/);
  assert.equal(button.disabled, false);
});

test('自动加载探测端口期间忽略手动发送，不会中断自动队列', async () => {
  const requested = [];
  const messages = [];
  const listeners = new Map();
  let finishProbe;
  globalThis.localStorage = {
    getItem: () => JSON.stringify({order: ['kstuff'], off: ['smp', 'websrv']}),
  };
  globalThis.window = {writeLog: message => messages.push(message), setElfRowState() {}};
  globalThis.document = {
    getElementById: () => ({disabled: false, checked: false, addEventListener() {}}),
    querySelectorAll: () => [{
      dataset: {file: 'kstuff.elf'},
      addEventListener: (_, callback) => listeners.set('send', callback),
    }],
  };
  globalThis.fetch = async url => {
    requested.push(url);
    if (url === '/api/jbstate')
      return new Promise(resolve => { finishProbe = resolve; });
    return {ok: false, status: 503};
  };
  initializePayloadSender({}, {});
  const auto = runAutoChain();
  listeners.get('send')();
  assert.equal(requested.filter(url => url.startsWith('payloads/')).length, 0);
  finishProbe({json: async () => ({ports: {}})});
  await auto;
  assert.equal(requested.filter(url => url.startsWith('payloads/')).length, 1);
  assert.doesNotMatch(messages.join('\n'), /已有 payload 正在发送/);
});

test('首页保留脚本依赖的 DOM，且不包含 FTP 中转页', () => {
  const home = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  const css = readFileSync(new URL('./ui.css', import.meta.url), 'utf8');
  const homeIds = [
    'st-device', 'st-jb', 'st-ldr', 'exploit-status', 'status-title',
    'status-body', 'status-actions', 'rail', 'stage-webkit', 'stage-kernel',
    'stage-elfldr', 'console', 'act-payloads', 'btn-runplan', 'btn-resetplan',
    'autorun-opt', 'plan-mode', 'elf-rows', 'pcsend', 'pcsend-cmd', 'pcsend-ps',
    'service-panplay', 'qr-panplay', 'url-panplay',
    'service-websrv', 'qr-websrv', 'url-websrv',
  ];
  assert.match(home, /href="\.\/ui\.css"/);
  const actual = [...home.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
  assert.equal(new Set(actual).size, actual.length, '静态 id 不得重复');
  for (const id of homeIds) assert.ok(actual.includes(id), `缺少 #${id}`);
  assert.equal(existsSync(new URL('./ftp.html', import.meta.url)), false);
  assert.doesNotMatch(home, /ftp\.html/);
  assert.doesNotMatch(readFileSync(new URL('./serve.py', import.meta.url), 'utf8'), /ftp_relay/);
  assert.match(css, /\[hidden\].*display: none !important/);
  assert.match(css, /#console div:last-child:not\(\.e\):not\(\.g\)/);
});

test('新版工作区保留键盘入口、表单标签与日志语义', () => {
  const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
  assert.match(html, /class="skip-link" href="#workspace"/);
  assert.match(html, /<main id="workspace"[^>]*tabindex="-1"/);
  assert.match(html, /id="console" role="log" aria-live="off"/);
  assert.equal((html.match(/aria-current="page"/g) || []).length, 1);
  const css = readFileSync(new URL('./ui.css', import.meta.url), 'utf8');
  assert.match(css, /prefers-reduced-motion: reduce/);
  assert.doesNotMatch(css, /@import|url\(["']?https?:/);
});

test('部分在线时只推荐确实在线的服务', () => {
  const file = readFileSync(new URL('./src/site.js', import.meta.url), 'utf8');
  const source = file.slice(0, file.lastIndexOf('\nboot().catch('))
    .replace(/^import .* from ['"]\.\/elfplan\.js['"];/m, '');
  const sandbox = {
    navigator: {userAgent: 'PlayStation 5'},
    window: {firmware: {rejection: () => null}, fw_str: '13.60'},
    document: {getElementById: () => ({addEventListener() {}, hidden: false})},
    loadPlan: () => ({order: [], off: new Set()}),
    savePlan() {}, resetPlan() {}, itemById() {}, formatSize() {},
  };
  runInNewContext(source + `
    refreshPills = () => {};
    applyElfState = () => {};
    updatePlanMode = () => {};
    updatePcsend = () => {};
    setBar = () => {};
    setStatus = (_tone, _title, body) => { globalThis.bodyText = body; };
    globalThis.renderPartial = enterPartial;
  `, sandbox);
  sandbox.renderPartial({ip: '192.168.1.2', ports: {'8080': true}});
  assert.match(sandbox.bodyText, /href="http:\/\/192\.168\.1\.2:8080"/);
  sandbox.renderPartial({ip: '192.168.1.2', ports: {'9021': true, '8080': false}});
  assert.doesNotMatch(sandbox.bodyText, /:8080/);
});

test('离线二维码生成与全部流程完成后自动折叠并突出展示二维码', async () => {
  const {renderQRSvg, encodeQRMatrix} = await import('./src/qrcode.js');
  const svg = renderQRSvg('http://192.168.1.88:8080');
  assert.match(svg, /^<svg class="qr-svg"/);
  assert.match(svg, /<path d="M/);
  const mat = encodeQRMatrix('http://192.168.1.88:8080');
  assert.ok(mat.size >= 25);

  const file = readFileSync(new URL('./src/site.js', import.meta.url), 'utf8');
  const source = file.slice(0, file.lastIndexOf('\nboot().catch('))
    .replace(/^import .* from ['"]\.\/elfplan\.js['"];/m, '');

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
    renderQRSvg,
  };
  runInNewContext(source, sandbox);

  // 触发全部流程完成回调
  sandbox.window.onFlowComplete({
    ip: '192.168.1.88',
    host_ip: '192.168.1.10',
    http_port: 80,
    ports: {'9021': true, '8080': true},
  });

  // 验证次要内容（Intro、01 破解详情、02 加载计划详情）均已自动折叠，且 body 标记为 flow-done
  assert.equal(bodyClasses.has('flow-done'), true);
  assert.equal(getEl('hero-intro').hidden, true);
  assert.equal(getEl('body-exploit').hidden, true);
  assert.equal(getEl('body-payloads').hidden, true);
  assert.equal(getEl('flow-complete-banner').hidden, false);

  // 验证 websrv 访问地址与二维码均已按真实 PS5 IP 生成
  assert.equal(getEl('url-websrv').textContent, 'http://192.168.1.88:8080');
  assert.match(getEl('qr-websrv').innerHTML, /<svg class="qr-svg"/);
});

