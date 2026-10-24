/*
 * iotscan GUI. Plain JavaScript with no dependencies. It never builds markup from
 * strings: every piece of device-supplied text goes through textContent, so a
 * hostile device cannot inject markup into this page.
 */
'use strict';

/* ---------- tiny DOM helpers ---------- */
const SVGNS = 'http://www.w3.org/2000/svg';

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'disabled') el.disabled = !!v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, kids);
  return el;
}

function append(el, kids) {
  for (const k of kids.flat(Infinity)) {
    if (k === null || k === undefined || k === false) continue;
    el.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
}

function svg(viewBox, parts, cls) {
  const s = document.createElementNS(SVGNS, 'svg');
  s.setAttribute('viewBox', viewBox);
  s.setAttribute('aria-hidden', 'true');
  s.setAttribute('fill', 'none');
  s.setAttribute('stroke', 'currentColor');
  s.setAttribute('stroke-width', '1.8');
  s.setAttribute('stroke-linecap', 'round');
  s.setAttribute('stroke-linejoin', 'round');
  if (cls) s.setAttribute('class', cls);
  for (const [tag, attrs] of parts) {
    const e = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    s.append(e);
  }
  return s;
}

const ICONS = {
  play: () => svg('0 0 16 16', [['path', { d: 'M4 2.8v10.4L13 8z', fill: 'currentColor', stroke: 'none' }]]),
  stop: () => svg('0 0 16 16', [['rect', { x: '3.5', y: '3.5', width: '9', height: '9', rx: '1.5', fill: 'currentColor', stroke: 'none' }]]),
  moon: () => svg('0 0 16 16', [['path', { d: 'M13.5 9.6A5.7 5.7 0 0 1 6.4 2.5a5.7 5.7 0 1 0 7.1 7.1z' }]]),
  sun: () => svg('0 0 16 16', [['circle', { cx: '8', cy: '8', r: '3' }], ['path', { d: 'M8 1.5v1.6M8 12.9v1.6M1.5 8h1.6M12.9 8h1.6M3.4 3.4l1.1 1.1M11.5 11.5l1.1 1.1M3.4 12.6l1.1-1.1M11.5 4.5l1.1-1.1' }]]),
  download: () => svg('0 0 16 16', [['path', { d: 'M8 2v8M4.8 7.2 8 10.4l3.2-3.2M2.5 13h11' }]]),
  close: () => svg('0 0 16 16', [['path', { d: 'M3.5 3.5l9 9M12.5 3.5l-9 9' }]]),
  sliders: () => svg('0 0 16 16', [['path', { d: 'M2 4.5h7M12 4.5h2M2 11.5h2M7 11.5h7' }], ['circle', { cx: '10.5', cy: '4.5', r: '1.5' }], ['circle', { cx: '5.5', cy: '11.5', r: '1.5' }]]),
  power: () => svg('0 0 16 16', [['path', { d: 'M8 2v5.5M4.6 4.4a5 5 0 1 0 6.8 0' }]]),
};

const MARKERS = {
  critical: () => svg('0 0 10 10', [['path', { d: 'M5 0l5 5-5 5-5-5z', fill: 'currentColor', stroke: 'none' }]]),
  high: () => svg('0 0 10 10', [['path', { d: 'M5 .5l5 9H0z', fill: 'currentColor', stroke: 'none' }]]),
  medium: () => svg('0 0 10 10', [['rect', { x: '1', y: '1', width: '8', height: '8', rx: '1.2', fill: 'currentColor', stroke: 'none' }]]),
  low: () => svg('0 0 10 10', [['circle', { cx: '5', cy: '5', r: '4.5', fill: 'currentColor', stroke: 'none' }]]),
  info: () => svg('0 0 10 10', [['circle', { cx: '5', cy: '5', r: '3.7', 'stroke-width': '1.6' }]]),
};

function logo() {
  return svg('0 0 26 26', [
    ['rect', { x: '2', y: '2', width: '22', height: '22', rx: '6', fill: 'var(--action)', stroke: 'none' }],
    ['rect', { x: '6', y: '6', width: '6', height: '14', rx: '1.6', fill: '#fff', stroke: 'none' }],
    ['rect', { x: '14', y: '6', width: '6', height: '14', rx: '1.6', fill: '#fff', opacity: '.55', stroke: 'none' }],
    ['rect', { x: '7.2', y: '8.2', width: '3.6', height: '4.4', rx: '.8', fill: 'var(--action)', stroke: 'none' }],
    ['rect', { x: '15.2', y: '13.4', width: '3.6', height: '4.4', rx: '.8', fill: 'var(--sev-high)', stroke: 'none' }],
  ]);
}

/* ---------- state ---------- */
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const sevRank = (s) => 4 - SEVS.indexOf(s); // critical = 4
const CONF_RANK = { possible: 0, likely: 1, confirmed: 2 };

const S = {
  server: null, // /api/state
  data: null, // { result, diff, saved_as }
  viewing: null, // history name being viewed, if not the latest
  history: [],
  selected: null, // device identity
  query: '',
  filter: 'all',
  sort: { key: 'risk', dir: 'desc' },
  target: '',
  opts: { active: false, fast: false, ports: '' },
  showOptions: false,
  showLow: false,
  modal: null,
  toast: null,
  seen: new Set(),
  wasRunning: false,
};

const $app = document.getElementById('app');
const $live = document.getElementById('live');
let pollTimer = null;
let toastTimer = null;

/* ---------- api ---------- */
async function api(path, body) {
  const init = body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
  let res;
  try {
    res = await fetch(path, init);
  } catch (e) {
    throw new Error('Lost contact with iotscan. Is it still running in the terminal?');
  }
  let json = null;
  try {
    json = await res.json();
  } catch (_) { /* non-JSON body */ }
  if (!res.ok) {
    const err = new Error((json && json.error) || `Request failed (${res.status})`);
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

/* ---------- formatting ---------- */
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const idOf = (d) => d.mac || d.ip;
const worst = (d) => (d.findings || []).filter((f) => !f.suppressed).sort(cmpFinding)[0] || null;
const cmpFinding = (a, b) => sevRank(b.severity) - sevRank(a.severity) || CONF_RANK[b.confidence] - CONF_RANK[a.confidence];
const activeFindings = (d) => (d.findings || []).filter((f) => !f.suppressed);

function ipKey(ip) {
  if (ip.includes(':')) return 1e12 + ip.charCodeAt(ip.length - 1);
  return ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
}

function tileIp(ip) {
  if (ip.includes(':')) return '…' + ip.split(':').pop();
  return '.' + ip.split('.').pop();
}

function fmtTime(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).format(d);
}

function say(msg) {
  $live.textContent = msg;
}

function toast(msg) {
  S.toast = msg;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    S.toast = null;
    render();
  }, 5000);
  render();
}

/* ---------- theme ---------- */
function effectiveTheme() {
  const t = document.documentElement.getAttribute('data-theme');
  if (t) return t;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyStoredTheme() {
  try {
    const t = localStorage.getItem('iotscan-theme');
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
  } catch (_) { /* storage unavailable */ }
}

function toggleTheme() {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  try {
    localStorage.setItem('iotscan-theme', next);
  } catch (_) { /* ignore */ }
  render();
}

/* ---------- actions ---------- */
async function refreshState() {
  try {
    S.server = await api('/api/state');
  } catch (e) {
    S.server = S.server || { running: false, networks: [] };
    toast(e.message);
    return;
  }
  if (S.server.running) {
    S.wasRunning = true;
    say(S.server.progress ? S.server.progress.phase : 'Scanning');
    schedulePoll(650);
  } else if (S.wasRunning) {
    S.wasRunning = false;
    await loadResult();
    say(S.server.error ? S.server.error : 'Scan finished');
  }
}

function schedulePoll(ms) {
  clearTimeout(pollTimer);
  pollTimer = setTimeout(async () => {
    await refreshState();
    render();
  }, ms);
}

async function loadResult() {
  try {
    S.data = await api('/api/result');
    S.viewing = null;
  } catch (e) {
    if (e.status !== 404) toast(e.message);
  }
  try {
    S.history = await api('/api/history');
  } catch (_) { /* history is optional */ }
}

async function startScan(allowPublic) {
  const targets = S.target.split(/[\s,]+/).filter(Boolean);
  try {
    await api('/api/scan', { targets, ports: S.opts.ports, active: S.opts.active, fast: S.opts.fast, allow_public: !!allowPublic });
    S.modal = null;
    S.seen = new Set();
    S.selected = null;
    S.wasRunning = true;
    await refreshState();
    render();
  } catch (e) {
    if (e.body && e.body.error === 'public') {
      S.modal = { kind: 'public', targets: e.body.targets || [] };
      render();
    } else {
      toast(e.message);
    }
  }
}

async function stopScan() {
  try {
    await api('/api/cancel', {});
    say('Stopping scan');
  } catch (e) {
    toast(e.message);
  }
}

async function quit() {
  try {
    await api('/api/quit', {});
  } catch (_) { /* server is going away */ }
  S.modal = { kind: 'bye' };
  render();
}

async function viewHistory(name) {
  if (!name) {
    await loadResult();
    render();
    return;
  }
  try {
    S.data = await api('/api/history/' + encodeURIComponent(name));
    S.viewing = name;
    S.selected = null;
    render();
  } catch (e) {
    toast(e.message);
  }
}

/* ---------- derived ---------- */
function devices() {
  return (S.data && S.data.result && S.data.result.devices) || [];
}

function isNew(d) {
  return !!(S.data && S.data.diff && S.data.diff.new_devices.some((n) => n.identity === idOf(d)));
}

function tileClass(d) {
  const w = worst(d);
  if (!w) return '';
  return w.severity + (sevRank(w.severity) >= sevRank('medium') ? ' tripped' : '');
}

function attentionDevices() {
  return devices().filter((d) => {
    const w = worst(d);
    return w && sevRank(w.severity) >= sevRank('medium');
  });
}

/* ---------- components ---------- */
function chip(sev, extra) {
  return h('span', { class: 'chip ' + sev }, MARKERS[sev](), sev, extra || null);
}

function confBadge(c) {
  const tips = {
    confirmed: 'Observed directly.',
    likely: 'Good evidence, with no sign the vendor back-ported a fix.',
    possible: 'A weak or indirect signal, for example a hidden version, or a distribution that may have back-ported the fix.',
  };
  return h('span', { class: 'conf ' + c, title: tips[c] || '' }, c);
}

function topbar() {
  const running = S.server && S.server.running;
  const nets = (S.server && S.server.networks) || [];
  const placeholder = nets.length ? 'Auto: ' + nets.map((n) => n.target).join(', ') : 'Auto-detect my network';
  const prog = S.server && S.server.progress;
  const pct = prog && prog.total ? Math.min(100, Math.round((prog.done / prog.total) * 100)) : 0;

  const bar = h('div', { class: 'progress' + (running && !(prog && prog.total) ? ' indeterminate' : ''), role: 'progressbar', 'aria-label': 'Scan progress', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': running ? pct : 0 }, h('i', {}));
  bar.firstChild.style.width = (running ? pct : 0) + '%';
  if (!running) bar.style.visibility = 'hidden';

  const input = h('input', {
    type: 'text', class: 'target', id: 'target', placeholder, value: S.target, 'aria-label': 'Target network', autocomplete: 'off', spellcheck: 'false',
    disabled: running || (S.server && S.server.demo),
    oninput: (e) => { S.target = e.target.value; },
    onkeydown: (e) => { if (e.key === 'Enter' && !running) startScan(false); },
  });

  const exportBtns = S.data && !S.viewing ? [
    h('a', { class: 'btn quiet', href: '/api/report.html', download: 'iotscan-report.html', title: 'Download a shareable HTML report' }, ICONS.download(), 'Report'),
  ] : [];

  const el = h('div', { class: 'bar' },
    h('div', { class: 'wrap bar-inner' },
      h('div', { class: 'brand' }, logo(), 'iotscan'),
      h('div', { class: 'bar-fields' },
        input,
        running
          ? h('button', { class: 'btn', onclick: stopScan }, ICONS.stop(), 'Stop scan')
          : h('button', { class: 'btn primary', onclick: () => startScan(false), disabled: S.server && S.server.demo, title: S.server && S.server.demo ? 'Demo mode: scanning is off' : '' }, ICONS.play(), 'Scan network'),
        h('button', { class: 'btn quiet', 'aria-expanded': S.showOptions ? 'true' : 'false', onclick: () => { S.showOptions = !S.showOptions; render(); } }, ICONS.sliders(), 'Options'),
      ),
      h('div', { class: 'bar-end' },
        exportBtns,
        h('button', { class: 'btn quiet', onclick: toggleTheme, 'aria-label': effectiveTheme() === 'dark' ? 'Switch to light theme' : 'Switch to dark theme' }, effectiveTheme() === 'dark' ? ICONS.sun() : ICONS.moon()),
        h('button', { class: 'btn quiet', onclick: quit, title: 'Stop iotscan and close this page' }, ICONS.power(), 'Quit'),
      ),
    ),
    S.showOptions ? optionsRow(running) : null,
    bar,
  );
  el.style.position = 'sticky';
  return el;
}

function optionsRow(running) {
  const sw = (label, key, hint) =>
    h('label', { class: 'switch', title: hint },
      h('input', { type: 'checkbox', checked: S.opts[key], disabled: running, onchange: (e) => { S.opts[key] = e.target.checked; } }),
      h('span', { class: 'track' }), label);
  return h('div', { class: 'wrap' },
    h('div', { class: 'settings' },
      sw('Active probes', 'active', 'Also request well-known paths such as /phpinfo.php to reveal hidden versions. Never sends exploit payloads.'),
      sw('Fast', 'fast', 'More parallelism, no rate limit. Quicker, but harder on fragile devices.'),
      h('label', { class: 'f' }, 'Ports',
        h('input', { type: 'text', placeholder: 'default', value: S.opts.ports, disabled: running, 'aria-label': 'Ports', oninput: (e) => { S.opts.ports = e.target.value; } })),
      S.server && !S.server.raw_arp ? h('span', { class: 'conf', title: 'Run: sudo setcap cap_net_raw+ep $(command -v iotscan)' }, 'Raw ARP off') : h('span', { class: 'conf confirmed' }, 'Raw ARP on'),
    ),
  );
}

function hero() {
  const running = S.server && S.server.running;
  const prog = S.server && S.server.progress;
  if (running) {
    const live = (S.server.live || []).length;
    return h('header', { class: 'hero' },
      h('div', {},
        h('h1', {}, live ? [h('span', { class: 'n' }, live), ` ${live === 1 ? 'device' : 'devices'} so far`] : 'Looking around…'),
        h('p', {}, prog ? `${prog.phase}${prog.total ? ` (${prog.done} of ${prog.total})` : ''} · ${Math.round(prog.elapsed_secs)}s` : 'Starting'),
        prog && prog.log.length ? h('p', { class: 'mono' }, prog.log[prog.log.length - 1]) : null,
      ));
  }
  if (!S.data) {
    const err = S.server && S.server.error;
    return h('header', { class: 'hero' },
      h('div', {},
        h('h1', {}, 'Find out what is on your network.'),
        h('p', {}, 'iotscan looks for your smart-home devices and checks them for known problems, including the October 2026 PHP2Shell flaws. It only reads what devices volunteer; it never sends exploit code.'),
        err ? h('div', { class: 'notice err' }, err) : null,
        h('p', { class: 'gap' }, h('button', { class: 'btn primary', onclick: () => startScan(false) }, ICONS.play(), 'Scan my network')),
      ));
  }
  const r = S.data.result;
  const devs = devices();
  const att = attentionDevices();
  const headline = devs.length === 0
    ? 'No devices found.'
    : att.length === 0
      ? [h('span', { class: 'n' }, devs.length), ` ${devs.length === 1 ? 'device' : 'devices'}. Nothing needs attention.`]
      : [h('span', { class: 'n' }, devs.length), ` ${devs.length === 1 ? 'device' : 'devices'}. `, h('span', { class: 'n' }, att.length), ` ${att.length === 1 ? 'needs' : 'need'} attention.`];

  const top = devs.flatMap((d) => activeFindings(d).map((f) => ({ d, f }))).sort((a, b) => cmpFinding(a.f, b.f))[0];
  const tally = h('div', { class: 'tally' },
    SEVS.map((s, i) => (r.stats.findings[i] > 0 ? chip(s, ' ' + r.stats.findings[i]) : null)));

  const diff = S.data.diff;
  const delta = diff && !S.viewing ? h('div', { class: 'delta' }, diffSummary(diff)) : null;

  return h('header', { class: 'hero' },
    h('div', {},
      S.viewing ? h('div', { class: 'notice' }, `Viewing a saved scan from ${fmtTime(r.started)}. `, h('button', { class: 'btn quiet', onclick: () => viewHistory('') }, 'Back to latest')) : null,
      h('h1', {}, headline),
      h('p', {}, `Scanned ${r.summary.targets.join(', ')} · ${fmtTime(r.started)} · ${Math.round(r.stats.duration_secs)}s${r.summary.active ? ' · active probes' : ''}.`,
        top && sevRank(top.f.severity) >= sevRank('medium') ? ` Most urgent: ${top.f.title.split(':')[0]} on ${top.d.label || top.d.ip} (${top.d.ip}).` : ''),
      delta,
      S.server && S.server.error ? h('div', { class: 'notice err' }, S.server.error) : null,
      (r.warnings || []).slice(0, 3).map((w) => h('div', { class: 'notice' }, w)),
    ),
    h('div', {}, tally,
      S.history.length > 1 ? h('p', { class: 'gap' },
        h('select', { 'aria-label': 'Saved scans', onchange: (e) => viewHistory(e.target.value) },
          h('option', { value: '' }, 'Saved scans…'),
          S.history.map((e) => h('option', { value: e.name, selected: e.name === S.viewing }, `${fmtTime(e.started)} · ${plural(e.devices, 'device', 'devices')}`)))) : null,
    ),
  );
}

function diffSummary(d) {
  const parts = [];
  if (d.new_devices.length) parts.push(plural(d.new_devices.length, 'new device', 'new devices'));
  if (d.missing_devices.length) parts.push(plural(d.missing_devices.length, 'device', 'devices') + ' gone');
  const nf = d.changed.reduce((a, c) => a + c.new_findings.length, 0);
  const rf = d.changed.reduce((a, c) => a + c.resolved_findings.length, 0);
  const op = d.changed.reduce((a, c) => a + c.opened_ports.length, 0);
  if (nf) parts.push(plural(nf, 'new finding', 'new findings'));
  if (rf) parts.push(plural(rf, 'resolved finding', 'resolved findings'));
  if (op) parts.push(plural(op, 'port', 'ports') + ' newly open');
  return parts.length ? 'Since the previous scan: ' + parts.join(', ') + '.' : 'No changes since the previous scan.';
}

function tile(d, live) {
  const isLive = !!live;
  const w = isLive ? d.worst : (worst(d) || {}).severity;
  const count = isLive ? d.findings : activeFindings(d).length;
  const cls = w ? w + (sevRank(w) >= sevRank('medium') ? ' tripped' : '') : '';
  const key = isLive ? (d.mac || d.ip) : idOf(d);
  const entering = !S.seen.has(key);
  S.seen.add(key);
  const label = d.label || 'Unidentified device';
  const el = h('button', {
    class: `tile ${cls}${entering ? ' enter' : ''}`,
    'aria-pressed': S.selected === key ? 'true' : 'false',
    'aria-label': `${d.ip}, ${label}, ${count ? plural(count, 'finding', 'findings') + (w ? ', worst ' + w : '') : 'no findings'}`,
    title: `${d.ip}${d.mac ? ' · ' + d.mac : ''}`,
    disabled: isLive,
    onclick: () => { S.selected = key; render(); },
  }, h('span', { class: 'lever' }), h('span', { class: 'ip' }, tileIp(d.ip)), h('span', { class: 'name' }, label), count ? h('span', { class: 'badge' }, count) : null, !isLive && isNew(d) ? h('span', { class: 'tag-new' }, 'new') : null);
  return el;
}

function board() {
  const running = S.server && S.server.running;
  const list = running ? (S.server.live || []) : devices();
  return h('section', { class: 'board', 'aria-label': 'Devices' },
    h('div', { class: 'board-head' },
      h('h2', {}, 'Your network'),
      h('div', { class: 'legend' },
        h('span', {}, h('span', { class: 'chip ok' }, 'ok'), 'no findings'),
        h('span', {}, 'Lever down = needs attention'),
        h('span', {}, 'Badge = number of findings'))),
    list.length
      ? h('div', { class: 'rail' }, list.map((d) => tile(d, running)))
      : h('div', { class: 'empty' }, h('strong', {}, running ? 'Listening for devices…' : 'Nothing here yet'), running ? 'Devices appear as they answer.' : 'Run a scan to fill the panel.'));
}

function attention() {
  const rows = devices().flatMap((d) => activeFindings(d).map((f) => ({ d, f }))).filter((x) => S.showLow || sevRank(x.f.severity) >= sevRank('medium')).sort((a, b) => cmpFinding(a.f, b.f));
  const lows = devices().flatMap((d) => activeFindings(d)).filter((f) => sevRank(f.severity) < sevRank('medium')).length;
  return h('section', { class: 'sec', 'aria-labelledby': 'att-h' },
    h('header', {}, h('h2', { id: 'att-h' }, 'Needs attention'),
      lows ? h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked: S.showLow, onchange: (e) => { S.showLow = e.target.checked; render(); } }), h('span', { class: 'track' }), `Show low and info (${lows})`) : null),
    rows.length
      ? h('ul', { class: 'att' }, rows.map(({ d, f }) =>
        h('li', {}, h('button', { onclick: () => { S.selected = idOf(d); render(); } },
          h('span', { class: 'who' }, chip(f.severity), h('strong', {}, d.label || 'Unidentified device'), h('span', { class: 'mono' }, d.ip + (f.port ? ':' + f.port : ''))),
          h('span', { class: 't' }, f.title, confBadge(f.confidence))))))
      : h('div', { class: 'empty' }, h('strong', {}, devices().length ? 'All clear' : 'No scan yet'), devices().length ? 'No medium, high or critical findings.' : 'Scan to see what needs fixing.'));
}

function deviceTable() {
  let rows = devices().slice();
  const q = S.query.trim().toLowerCase();
  if (q) {
    rows = rows.filter((d) => [d.ip, d.mac, d.label, d.vendor, d.hostname, d.kind].filter(Boolean).join(' ').toLowerCase().includes(q));
  }
  if (S.filter === 'attention') rows = rows.filter((d) => { const w = worst(d); return w && sevRank(w.severity) >= sevRank('medium'); });
  if (S.filter === 'new') rows = rows.filter(isNew);
  const dir = S.sort.dir === 'asc' ? 1 : -1;
  rows.sort((a, b) => {
    if (S.sort.key === 'ip') return (ipKey(a.ip) - ipKey(b.ip)) * dir;
    if (S.sort.key === 'name') return (a.label || '').localeCompare(b.label || '') * dir;
    const wa = worst(a), wb = worst(b);
    const ra = wa ? sevRank(wa.severity) * 3 + CONF_RANK[wa.confidence] : -1;
    const rb = wb ? sevRank(wb.severity) * 3 + CONF_RANK[wb.confidence] : -1;
    return (ra - rb) * dir || ipKey(a.ip) - ipKey(b.ip);
  });
  const th = (key, label) => h('th', { scope: 'col', 'aria-sort': S.sort.key === key ? (S.sort.dir === 'asc' ? 'ascending' : 'descending') : 'none' },
    h('button', { onclick: () => { S.sort = { key, dir: S.sort.key === key && S.sort.dir === 'desc' ? 'asc' : 'desc' }; render(); } }, label + (S.sort.key === key ? (S.sort.dir === 'asc' ? ' ↑' : ' ↓') : '')));

  const search = h('input', { type: 'search', id: 'search', placeholder: 'Search devices  ( / )', value: S.query, 'aria-label': 'Search devices', oninput: (e) => { S.query = e.target.value; renderKeepFocus('search'); } });
  const filter = h('select', { 'aria-label': 'Filter devices', onchange: (e) => { S.filter = e.target.value; render(); } },
    [['all', 'All devices'], ['attention', 'Needs attention'], ['new', 'New since last scan']].map(([v, t]) => h('option', { value: v, selected: S.filter === v }, t)));

  return h('section', { class: 'sec', 'aria-labelledby': 'dev-h' },
    h('header', {}, h('h2', { id: 'dev-h' }, 'Devices ', h('span', { class: 'conf' }, rows.length)), h('div', { class: 'tools' }, search, filter)),
    rows.length
      ? h('div', { class: 'tablewrap' }, h('table', {},
        h('thead', {}, h('tr', {}, th('name', 'Device'), th('risk', 'Risk'), h('th', { scope: 'col' }, 'Open ports'))),
        h('tbody', {}, rows.map((d) => {
          const w = worst(d);
          const key = idOf(d);
          const open = (d.services || []).map((s) => s.port);
          return h('tr', { tabindex: 0, 'aria-selected': S.selected === key ? 'true' : 'false', onclick: () => { S.selected = key; render(); }, onkeydown: (e) => { if (e.key === 'Enter') { S.selected = key; render(); } } },
            h('td', { class: 'dev' }, h('strong', {}, d.label || 'Unidentified device'), h('span', { class: 'mono' }, d.ip), d.vendor && !(d.label || '').includes(d.vendor.split(' ')[0]) ? h('span', {}, d.vendor) : null),
            h('td', {}, w ? [chip(w.severity), ' ', confBadge(w.confidence)] : h('span', { class: 'chip ok' }, 'ok')),
            h('td', {}, h('div', { class: 'ports' }, open.length ? open.map((p) => h('span', { class: 'port' }, p)) : h('span', { class: 'conf' }, 'none'))));
        }))))
      : h('div', { class: 'empty' }, h('strong', {}, devices().length ? 'No matches' : 'No devices yet'), devices().length ? 'Try a different search or filter.' : 'Run a scan to list devices.'));
}

function findingCard(f) {
  return h('article', { class: `fcard ${f.severity}${f.suppressed ? ' suppressed' : ''}` },
    h('div', { class: 'row' }, chip(f.severity), confBadge(f.confidence), f.port ? h('span', { class: 'port' }, 'port ' + f.port) : null, (f.cves || []).map((c) => h('span', { class: 'port' }, c))),
    h('h4', {}, f.title),
    h('p', {}, f.summary),
    f.suppressed ? h('p', {}, h('strong', {}, 'Suppressed: '), f.suppressed) : null,
    f.evidence && f.evidence.length ? h('ul', {}, f.evidence.map((e) => h('li', {}, e))) : null,
    f.remediation ? h('div', { class: 'fix' }, h('b', {}, 'What to do'), f.remediation) : null,
    f.references && f.references.length ? h('div', { class: 'refs' }, f.references.map((u) => (/^https?:\/\//.test(u) ? h('a', { href: u, target: '_blank', rel: 'noopener noreferrer' }, u) : h('span', {}, u)))) : null);
}

function drawer() {
  const d = devices().find((x) => idOf(x) === S.selected);
  if (!d) return null;
  const close = () => { S.selected = null; render(); };
  const kv = [];
  const row = (k, v) => { if (v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length)) kv.push(h('dt', {}, k), h('dd', {}, v)); };
  row('Type', d.kind && d.kind !== 'unknown' ? d.kind : '');
  row('Vendor', d.vendor);
  row('Hostname', d.hostname);
  row('Other addresses', (d.other_ips || []).join(', '));
  row('Found by', (d.discovered_via || []).join(', '));
  if (d.ssdp) {
    row('UPnP', [d.ssdp.friendly_name, d.ssdp.manufacturer, d.ssdp.model].filter(Boolean).join(' · '));
    row('UPnP server', d.ssdp.server);
  }
  for (const m of d.mdns || []) row('Announces', `${m.instance} (${m.service}, port ${m.port})`);
  for (const s of d.services || []) {
    let t = s.kind;
    if (s.http) {
      t += ` · HTTP ${s.http.status}`;
      if (s.http.tls) t += ` · ${s.http.tls_version || 'TLS'}`;
      if (s.http.server) t += ` · ${s.http.server}`;
      if (s.http.title) t += ` · “${s.http.title}”`;
    }
    if (s.banner) t += ` · ${s.banner}`;
    row(`Port ${s.port}`, t);
  }
  const fs = (d.findings || []).slice().sort((a, b) => (a.suppressed ? 1 : 0) - (b.suppressed ? 1 : 0) || cmpFinding(a, b));
  const scrim = h('div', { class: 'scrim', onclick: close });
  const panel = h('aside', { class: 'drawer', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'drawer-h' },
    h('header', {},
      h('div', {}, h('h2', { id: 'drawer-h' }, d.label || 'Unidentified device'), h('div', { class: 'sub mono' }, d.ip + (d.mac ? ' · ' + d.mac : ''))),
      h('button', { class: 'btn quiet', id: 'drawer-close', onclick: close, 'aria-label': 'Close details' }, ICONS.close())),
    h('div', { class: 'inner' },
      h('h3', {}, fs.length ? `Findings (${fs.length})` : 'Findings'),
      fs.length ? fs.map(findingCard) : h('p', { class: 'conf' }, 'No findings for this device.'),
      h('h3', {}, 'Details'),
      h('dl', { class: 'kv' }, kv)));
  return [scrim, panel];
}

function modal() {
  if (!S.modal) return null;
  if (S.modal.kind === 'public') {
    return h('div', { class: 'modal', role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'm-h' },
      h('div', { class: 'card' },
        h('h2', { id: 'm-h' }, 'This is not a private network'),
        h('p', {}, `${S.modal.targets.join(', ')} ${S.modal.targets.length === 1 ? 'is' : 'are'} outside private address space. Scanning networks you do not own or are not authorised to test may be illegal.`),
        h('div', { class: 'actions' },
          h('button', { class: 'btn', onclick: () => { S.modal = null; render(); } }, 'Cancel'),
          h('button', { class: 'btn danger', onclick: () => startScan(true) }, 'I am authorised, scan anyway'))));
  }
  if (S.modal.kind === 'bye') {
    return h('div', { class: 'modal' }, h('div', { class: 'card' }, h('h2', {}, 'iotscan has stopped'), h('p', {}, 'You can close this tab. Start it again with `iotscan gui`.')));
  }
  return null;
}

function changes() {
  const d = S.data && S.data.diff;
  if (!d || S.viewing || !(d.new_devices.length || d.missing_devices.length || d.changed.length)) return null;
  const items = [];
  d.new_devices.forEach((n) => items.push(h('li', {}, 'New device ', h('span', { class: 'mono' }, n.ip), ' ' + (n.label || ''))));
  d.missing_devices.forEach((n) => items.push(h('li', {}, 'Gone: ', h('span', { class: 'mono' }, n.ip), ' ' + (n.label || ''))));
  d.changed.forEach((c) => {
    c.new_findings.forEach((f) => items.push(h('li', {}, 'New on ', h('span', { class: 'mono' }, c.device.ip), ': ', f.title)));
    c.resolved_findings.forEach((f) => items.push(h('li', {}, 'Resolved on ', h('span', { class: 'mono' }, c.device.ip), ': ', f.title)));
    c.opened_ports.forEach((p) => items.push(h('li', {}, `Port ${p} opened on `, h('span', { class: 'mono' }, c.device.ip))));
    c.closed_ports.forEach((p) => items.push(h('li', {}, `Port ${p} closed on `, h('span', { class: 'mono' }, c.device.ip))));
    if (c.previous_ip) items.push(h('li', {}, h('span', { class: 'mono' }, c.device.ip), ` moved from ${c.previous_ip}`));
  });
  return h('details', { class: 'sec' },
    h('summary', { class: 'no-print' }, h('span', {}, 'Changes since the previous scan')),
    h('ul', { class: 'changes' }, items));
}

/* ---------- render ---------- */
function render() {
  const keepScroll = window.scrollY;
  const focusId = document.activeElement && document.activeElement.id;
  const body = h('div', {},
    topbar(),
    h('main', { class: 'wrap stack' },
      hero(),
      board(),
      h('div', { class: 'cols' }, attention(), deviceTable()),
      changes(),
      h('p', { class: 'foot' }, `iotscan ${S.server ? S.server.version : ''} · Confidence levels: confirmed = observed directly · likely = good evidence · possible = weak or indirect signal.`,
        S.server && S.server.demo ? ' Demo data: nothing was scanned.' : '')),
    drawer(),
    modal(),
    S.toast ? h('div', { class: 'toast', role: 'status' }, S.toast) : null);
  $app.replaceChildren(body);
  window.scrollTo(0, keepScroll);
  if (S.selected && document.getElementById('drawer-close') && focusId !== 'drawer-close') document.getElementById('drawer-close').focus({ preventScroll: true });
  else if (focusId && document.getElementById(focusId)) document.getElementById(focusId).focus({ preventScroll: true });
}

function renderKeepFocus(id) {
  const el = document.getElementById(id);
  const pos = el ? el.selectionStart : null;
  render();
  const again = document.getElementById(id);
  if (again) {
    again.focus({ preventScroll: true });
    if (pos !== null) again.setSelectionRange(pos, pos);
  }
}

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (S.modal && S.modal.kind === 'public') S.modal = null;
    else S.selected = null;
    render();
  } else if (e.key === '/' && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLSelectElement)) {
    const s = document.getElementById('search');
    if (s) { e.preventDefault(); s.focus(); }
  }
});

(async function init() {
  applyStoredTheme();
  render();
  await refreshState();
  if (S.server && S.server.has_result) await loadResult();
  render();
})();
