'use strict';
/*
 * NetPulse – Weboberfläche (ohne Build-Schritt, ohne externe Bibliotheken).
 * Aufteilung: app.js (Grundfunktionen, Navigation, Dashboard), devices.js (Geräte),
 * admin.js (Alarme, Netze, Zugangsdaten, Benachrichtigungen, Benutzer, Konto).
 *
 * Sicherheit:
 * - Alle Daten aus der API werden mit esc() maskiert, bevor sie ins HTML kommen (XSS-Schutz).
 *   Hostnamen stammen z. B. aus DNS/SNMP und sind damit nicht vertrauenswürdig.
 * - Keine Inline-Skripte oder -Styles (die Content-Security-Policy verbietet sie).
 * - Jede Anfrage schickt den Header X-NetPulse-Csrf mit (CSRF-Schutz).
 */

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c]);
const icon = (name, cls = '') => `<svg class="i ${cls}"><use href="icons.svg?v=0.7.2#i-${name}"/></svg>`;

const state = { user: null, refreshTimer: null, globalTimer: null, summary: null, liveStops: [] };

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch('/api' + path, {
    method,
    headers: { 'Content-Type': 'application/json', 'X-NetPulse-Csrf': '1' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  });
  const isJson = (res.headers.get('content-type') || '').includes('application/json');
  const data = isJson ? await res.json() : null;
  if (res.status === 401 && path !== '/login') {
    showLogin();
    throw new Error('Sitzung abgelaufen – bitte neu anmelden');
  }
  if (!res.ok) throw new Error((data && data.error) || `Fehler ${res.status}`);
  return data;
}

const view = () => $('#view');
const isAdmin = () => state.user && state.user.role === 'admin';

function toast(message, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  el.innerHTML = `${icon(isError ? 'alert-triangle' : 'circle-check')}<span></span>`;
  el.querySelector('span').textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

/** Führt eine Aktion aus und zeigt Fehler als Hinweis an */
async function attempt(fn, successMessage) {
  try {
    await fn();
    if (successMessage) toast(successMessage);
    return true;
  } catch (e) {
    toast(e.message, true);
    return false;
  }
}

/** Breiten von Balken setzen (per JavaScript, weil die CSP Inline-Styles verbietet) */
function applyWidths(root = document) {
  $$('[data-w]', root).forEach((el) => { el.style.width = `${Math.max(0, Math.min(100, Number(el.dataset.w)))}%`; });
}

/** Modaler Dialog; liefert das <dialog>-Element */
function openModal(title, bodyHtml) {
  const dialog = $('#modal');
  dialog.className = '';
  dialog.innerHTML = `<div class="dlg-head"><h2>${esc(title)}</h2>
    <button class="icon-btn" type="button" data-close title="Schließen">${icon('x')}</button></div>
    <div class="dlg-body">${bodyHtml}</div>`;
  dialog.querySelector('[data-close]').addEventListener('click', () => dialog.close());
  dialog.showModal();
  return dialog;
}

// ---------------------------------------------------------------------------
// Formatierung
// ---------------------------------------------------------------------------

const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString('de-DE') : '–');
function fmtAgo(iso) {
  if (!iso) return '–';
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'gerade eben';
  if (s < 3600) return `vor ${Math.floor(s / 60)} Min.`;
  if (s < 86400) return `vor ${Math.floor(s / 3600)} Std.`;
  const days = Math.floor(s / 86400);
  return days === 1 ? 'vor 1 Tag' : `vor ${days} Tagen`;
}
function fmtMs(v) {
  if (v == null) return '–';
  if (v < 1) return `${v.toFixed(2)} ms`;
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ms`;
}
function fmtBytes(b) {
  if (b == null || Number.isNaN(b)) return '–';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  let v = Number(b);
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}
function fmtBps(b) {
  if (b == null) return '–';
  const units = ['bit/s', 'kbit/s', 'Mbit/s', 'Gbit/s'];
  let i = 0;
  let v = Number(b);
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i += 1; }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}
function fmtDuration(seconds) {
  if (seconds == null) return '–';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d} T. ${h} Std.`;
  if (h > 0) return `${h} Std. ${m} Min.`;
  return `${m} Min.`;
}
const fmtPct = (v) => (v == null ? '–' : `${Math.round(v)} %`);
const pct = (part, total) => (total ? Math.round((part / total) * 1000) / 10 : 0);

// ---------------------------------------------------------------------------
// Gerätetypen, Status, Ports
// ---------------------------------------------------------------------------

const TYPES = {
  router: { label: 'Router', icon: 'router', tone: 't-network' },
  switch: { label: 'Switch', icon: 'switch-horizontal', tone: 't-network' },
  access_point: { label: 'Access Point', icon: 'access-point', tone: 't-network' },
  firewall: { label: 'Firewall', icon: 'wall', tone: 't-network' },
  network: { label: 'Netzwerkgerät', icon: 'network', tone: 't-network' },
  server: { label: 'Server', icon: 'server', tone: 't-server' },
  hypervisor: { label: 'Hypervisor', icon: 'stack-2', tone: 't-server' },
  linux: { label: 'Linux', icon: 'server-2', tone: 't-server' },
  nas: { label: 'NAS', icon: 'database', tone: 't-storage' },
  raspberry_pi: { label: 'Raspberry Pi', icon: 'cpu', tone: 't-server' },
  windows: { label: 'Windows-PC', icon: 'brand-windows', tone: 't-client' },
  apple: { label: 'Mac', icon: 'brand-apple', tone: 't-client' },
  computer: { label: 'Computer', icon: 'device-desktop', tone: 't-client' },
  printer: { label: 'Drucker', icon: 'printer', tone: 't-media' },
  camera: { label: 'Kamera', icon: 'device-cctv', tone: 't-media' },
  phone: { label: 'Smartphone', icon: 'device-mobile', tone: 't-mobile' },
  tablet: { label: 'Tablet', icon: 'device-tablet', tone: 't-mobile' },
  tv: { label: 'TV / Streaming', icon: 'device-tv', tone: 't-media' },
  speaker: { label: 'Lautsprecher / Assistent', icon: 'device-speaker', tone: 't-media' },
  console: { label: 'Spielekonsole', icon: 'device-gamepad-2', tone: 't-mobile' },
  ups: { label: 'USV', icon: 'battery-charging', tone: 't-power' },
  iot: { label: 'Smart Home / IoT', icon: 'bulb', tone: 't-iot' },
  unknown: { label: 'Unbekannt', icon: 'help-circle', tone: 't-unknown' },
};
const typeInfo = (t) => TYPES[t] || TYPES.unknown;
const devIcon = (d, size = '') => {
  const t = typeInfo(d.device_type);
  return `<span class="dev-icon ${size} ${t.tone}" title="${esc(t.label)}">${icon(t.icon)}</span>`;
};

const STATUS_LABEL = { up: 'online', down: 'offline', unknown: 'unbekannt' };
const statusBadge = (d) =>
  d.monitored === false
    ? '<span class="badge plain">nicht überwacht</span>'
    : `<span class="badge st-${esc(d.status)}"><span class="dot ${esc(d.status)}"></span>${esc(STATUS_LABEL[d.status] || d.status)}</span>`;
const EVENT_LABEL = { up: 'online', down: 'offline', discovered: 'neu', mac_changed: 'MAC geändert', ssh_key_changed: 'SSH-Schlüssel',
  check_down: 'Dienst aus', check_up: 'Dienst ok', check_warn: 'Dienst-Warnung' };
const eventBadge = (kind) => `<span class="badge ev-${esc(kind)}">${esc(EVENT_LABEL[kind] || kind)}</span>`;
const deviceLabel = (d) => d.name || d.reported_name || d.hostname || d.ip;

const PORT_NAMES = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 139: 'NetBIOS',
  143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 548: 'AFP', 554: 'RTSP', 631: 'IPP', 993: 'IMAPS', 1883: 'MQTT',
  3306: 'MySQL', 3389: 'RDP', 5000: 'NAS/UPnP', 5001: 'NAS-HTTPS', 5432: 'PostgreSQL', 5900: 'VNC',
  5985: 'WinRM', 5986: 'WinRM-TLS', 8006: 'Proxmox', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9100: 'Drucker', 11443: 'UniFi OS',
};
const portLabel = (p) => (PORT_NAMES[p] ? `${p} ${PORT_NAMES[p]}` : String(p));
const portChips = (list) => (list && list.length ? list.map((p) => `<span class="chip">${esc(portLabel(p))}</span>`).join('') : '<span class="muted">–</span>');
const empty = (text, iconName = 'circle-check') => `<div class="empty">${icon(iconName)}<span>${esc(text)}</span></div>`;

function meter(value, { warn = 80, crit = 90 } = {}) {
  const cls = value >= crit ? 'crit' : value >= warn ? 'warn' : '';
  return `<div class="meter ${cls}"><span data-w="${Number(value) || 0}"></span></div>`;
}

// ---------------------------------------------------------------------------
// Diagramme (SVG, ohne Bibliothek)
// ---------------------------------------------------------------------------

/**
 * Liniendiagramm. `series`: [{ key, label }] – Farbe über CSS-Klasse c0…c4.
 * `outages`: optional, markiert Zeitfenster mit Verfügbarkeit < 100 % rot.
 */
function lineChart(points, { series, format = (v) => String(Math.round(v)), height = 180, width = 680, maxValue = null, outages = false } = {}) {
  const usable = points.filter((p) => series.some((s) => p[s.key] != null));
  if (!usable.length) return empty('Noch keine Messwerte vorhanden', 'activity');
  const W = width;
  const H = height;
  const P = { l: 58, r: 10, t: 12, b: 24 };
  const times = points.map((p) => new Date(p.bucket).getTime());
  const t0 = times[0];
  const t1 = Math.max(times[times.length - 1], t0 + 60000);
  const values = points.flatMap((p) => series.map((s) => p[s.key])).filter((v) => v != null);
  const max = maxValue ?? Math.max(1e-9, ...values) * 1.15;
  const x = (t) => P.l + ((t - t0) / (t1 - t0)) * (W - P.l - P.r);
  const y = (v) => P.t + (1 - Math.min(v, max) / max) * (H - P.t - P.b);
  const fmtT = (t) => new Date(t).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });

  let svg = '';
  for (let i = 0; i <= 3; i += 1) {
    const v = (max / 3) * i;
    svg += `<line class="grid-line" x1="${P.l}" x2="${W - P.r}" y1="${y(v).toFixed(1)}" y2="${y(v).toFixed(1)}"/>
      <text class="lbl" x="${P.l - 8}" y="${(y(v) + 4).toFixed(1)}" text-anchor="end">${esc(format(v))}</text>`;
  }
  if (outages) {
    const slot = Math.max(3, (W - P.l - P.r) / points.length);
    points.forEach((p, i) => {
      if (p.availability != null && p.availability < 1) {
        svg += `<rect class="outage" x="${(x(times[i]) - slot / 2).toFixed(1)}" y="${P.t}" width="${slot.toFixed(1)}" height="${H - P.t - P.b}" opacity="${(0.2 + 0.6 * (1 - p.availability)).toFixed(2)}"><title>Ausfall ${Math.round((1 - p.availability) * 100)} %</title></rect>`;
      }
    });
  }
  series.forEach((s, si) => {
    let path = '';
    let pen = false;
    points.forEach((p, i) => {
      const v = p[s.key];
      if (v == null) { pen = false; return; }
      path += `${pen ? 'L' : 'M'}${x(times[i]).toFixed(1)},${y(v).toFixed(1)} `;
      pen = true;
    });
    svg += `<path class="line c${si}" d="${path}"/>`;
  });
  svg += `<line class="axis" x1="${P.l}" y1="${H - P.b}" x2="${W - P.r}" y2="${H - P.b}"/>
    <text class="lbl" x="${P.l}" y="${H - 6}">${esc(fmtT(t0))}</text>
    <text class="lbl" x="${W - P.r}" y="${H - 6}" text-anchor="end">${esc(fmtT(t1))}</text>`;
  const legend = series.length > 1
    ? `<div class="legend">${series.map((s, i) => `<span><i class="bgc${i}"></i>${esc(s.label)}</span>`).join('')}</div>`
    : '';
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img">${svg}</svg>${legend}`;
}

function availability(points) {
  const values = points.map((p) => p.availability).filter((v) => v != null);
  if (!values.length) return null;
  return Math.round((values.reduce((a, b) => a + b, 0) / values.length) * 10000) / 100;
}

// ---------------------------------------------------------------------------
// Live-Daten mit Animation
// ---------------------------------------------------------------------------

/**
 * Fragt alle 2 s die Live-Datenraten eines Geräts ab und merkt sich pro Schnittstelle
 * die letzten 60 Werte. `onData(data, history)` wird bei jedem Ergebnis aufgerufen.
 * Liefert eine Stopp-Funktion; beim Seitenwechsel werden alle Abfragen automatisch beendet.
 */
function startLive(deviceId, onData, onError, history = {}) {
  let stopped = false;
  let timer = null;
  const tick = async () => {
    if (document.hidden) { timer = setTimeout(tick, 3000); return; }
    try {
      const data = await api(`/devices/${deviceId}/live`);
      if (stopped) return;
      data.interfaces.forEach((i) => {
        const h = (history[i.name] ||= []);
        if (i.rx_bps != null || i.tx_bps != null) {
          h.push({ rx: i.rx_bps || 0, tx: i.tx_bps || 0 });
          if (h.length > 60) h.shift();
        }
      });
      onData(data, history);
      timer = setTimeout(tick, data.warming_up ? 1600 : 2000);
    } catch (e) {
      if (stopped) return;
      if (onError) onError(e);
      timer = setTimeout(tick, 10000);
    }
  };
  tick();
  const stop = () => { stopped = true; clearTimeout(timer); };
  state.liveStops.push(stop);
  return stop;
}

/** Zahl weich zum neuen Wert hochzählen lassen */
function tweenNumber(el, target, format) {
  if (!el) return;
  const from = Number(el.dataset.value || 0);
  const to = target ?? 0;
  el.dataset.value = to;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / 700);
    const eased = 1 - (1 - t) ** 3;
    el.textContent = target == null ? '–' : format(from + (to - from) * eased);
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/** Fließlinie: je höher die Datenrate, desto schneller wandern die Striche */
function flowLine(cls = '') {
  return `<svg class="flow ${cls}" viewBox="0 0 200 12" preserveAspectRatio="none" aria-hidden="true">
    <path class="flow-track" d="M2 6H198"/><path class="flow-dash" d="M2 6H198"/></svg>`;
}
function setFlow(svg, bps) {
  if (!svg) return;
  const dash = svg.querySelector('.flow-dash');
  if (!bps || bps < 1000) {
    dash.style.animationPlayState = 'paused';
    svg.classList.add('idle');
    return;
  }
  svg.classList.remove('idle');
  dash.style.animationPlayState = 'running';
  // 1 kbit/s → 4 s pro Durchlauf, 1 Gbit/s → 0,35 s
  const seconds = Math.max(0.35, Math.min(4, 4 - Math.log10(bps / 1000) * 0.6));
  dash.style.animationDuration = `${seconds.toFixed(2)}s`;
}

/** Mini-Verlauf der letzten 60 Werte (Empfang und Senden) */
function sparkline(points, height = 44) {
  if (!points || points.length < 3) return `<svg class="spark" viewBox="0 0 240 ${height}"></svg>`;
  const W = 240;
  const max = Math.max(1, ...points.map((p) => Math.max(p.rx, p.tx))) * 1.1;
  const x = (i) => (i / 59) * W;
  const y = (v) => height - 2 - (v / max) * (height - 4);
  const offset = 60 - points.length;
  const line = (key) => points.map((p, i) => `${i ? 'L' : 'M'}${x(i + offset).toFixed(1)},${y(p[key]).toFixed(1)}`).join(' ');
  const area = `${line('rx')} L${x(59).toFixed(1)},${height} L${x(offset).toFixed(1)},${height} Z`;
  return `<svg class="spark" viewBox="0 0 ${W} ${height}" preserveAspectRatio="none">
    <path class="spark-area c0" d="${area}"/><path class="line c0" d="${line('rx')}"/><path class="line c1" d="${line('tx')}"/></svg>`;
}

// ---------------------------------------------------------------------------
// Live-Stream: eine dauerhafte Verbindung (Server-Sent Events) für alle Seiten
// ---------------------------------------------------------------------------

const HISTORY_POINTS = 120;
const live = { es: null, devices: new Map(), total: null, history: [], perDevice: new Map(), listeners: new Set() };

function pushPoint(list, value) {
  list.push(value);
  if (list.length > HISTORY_POINTS) list.shift();
}

function setLiveDot(on) {
  const dot = $('#live-dot');
  if (!dot) return;
  dot.classList.toggle('on', on);
  dot.title = on ? 'Live-Verbindung aktiv' : 'Live-Verbindung getrennt – verbinde neu …';
}

function connectStream() {
  if (live.es || typeof EventSource === 'undefined') return;
  const es = new EventSource('/api/stream');
  live.es = es;
  es.onopen = () => setLiveDot(true);
  // Der Browser baut die Verbindung selbstständig neu auf
  es.onerror = () => setLiveDot(false);
  es.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    setLiveDot(true);
    if (msg.type === 'shelly') {
      if (msg.full) live.devices.clear();
      (msg.devices || []).forEach((d) => live.devices.set(d.id, d));
      live.total = msg.total_power_w;
      if (msg.total_power_w != null && !(msg.full && live.history.length)) pushPoint(live.history, msg.total_power_w);
      live.devices.forEach((d) => {
        if (!d.ok || d.power_w == null) return;
        if (!live.perDevice.has(d.id)) live.perDevice.set(d.id, []);
        pushPoint(live.perDevice.get(d.id), d.power_w);
      });
    } else if (msg.type === 'alert') {
      alertPopup(msg);
      refreshShell();
    } else if (msg.type === 'status' && msg.devices.length <= 3) {
      msg.devices.forEach((d) => toast(`${d.label} ist ${d.status === 'up' ? 'wieder erreichbar' : 'nicht erreichbar'}`, d.status !== 'up'));
    }
    live.listeners.forEach((fn) => { try { fn(msg); } catch (e) { console.error(e); } });
  };
}

const SEVERITY = {
  critical: { label: 'Kritisch', icon: 'alert-triangle' },
  warning: { label: 'Warnung', icon: 'alert-triangle' },
  info: { label: 'Hinweis', icon: 'info-circle' },
  resolved: { label: 'Behoben', icon: 'circle-check' },
};

/** Alarm als Hinweis oben rechts; kritische bleiben stehen, bis man sie schließt */
function alertPopup(a) {
  let stack = $('#alert-stack');
  if (!stack) {
    stack = document.createElement('div');
    stack.id = 'alert-stack';
    stack.setAttribute('aria-live', 'assertive');
    document.body.append(stack);
  }
  const sev = SEVERITY[a.severity] || SEVERITY.info;
  const el = document.createElement('div');
  el.className = `alert-pop sev-${a.severity}`;
  el.setAttribute('role', 'alert');
  el.innerHTML = `${icon(sev.icon)}<div class="alert-pop-body">
      <div class="alert-pop-head"><strong>${esc(a.title)}</strong><span class="badge plain">${esc(sev.label)}</span></div>
      <div>${esc(a.message)}</div>
      <div class="muted small">Regel „${esc(a.rule)}“ · ${esc(new Date().toLocaleTimeString('de-DE'))} · <a href="#/alerts">Alle Alarme</a></div></div>
    <button type="button" class="icon-btn" title="Schließen">${icon('x', 'i-sm')}</button>`;
  const close = () => { el.classList.add('out'); setTimeout(() => el.remove(), 250); };
  $('button', el).addEventListener('click', close);
  $('a', el).addEventListener('click', close);
  stack.prepend(el);
  while (stack.children.length > 5) stack.lastElementChild.remove();
  if (a.severity !== 'critical') setTimeout(close, 15000);
  // Tab im Hintergrund: Titel blinkt, bis man zurückkommt
  if (document.hidden) {
    const original = document.title;
    const blink = setInterval(() => { document.title = document.title === original ? `⚠ ${a.title}` : original; }, 1000);
    document.addEventListener('visibilitychange', () => { clearInterval(blink); document.title = original; }, { once: true });
  }
}

function disconnectStream() {
  if (live.es) live.es.close();
  live.es = null;
  live.devices.clear();
  setLiveDot(false);
}

/** Auf Live-Meldungen reagieren, solange die aktuelle Seite offen ist */
function onLive(fn) {
  live.listeners.add(fn);
  state.liveStops.push(() => live.listeners.delete(fn));
}

/** Verlauf eines Einzelwerts (z. B. Watt) als Fläche + Linie */
function valueSpark(values, height = 56) {
  if (!values || values.length < 3) return `<svg class="spark tall" viewBox="0 0 240 ${height}"></svg>`;
  const W = 240;
  // Anfangs weniger Punkte: Breite wächst mit, bis der Verlauf voll ist
  const slots = Math.max(values.length, 24);
  const max = Math.max(1, ...values) * 1.15;
  const x = (i) => ((i + slots - values.length) / (slots - 1)) * W;
  const y = (v) => height - 2 - (v / max) * (height - 4);
  const line = values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const area = `${line} L${W},${height} L${x(0).toFixed(1)},${height} Z`;
  return `<svg class="spark tall" viewBox="0 0 ${W} ${height}" preserveAspectRatio="none">
    <path class="spark-area c2" d="${area}"/><path class="line c2" d="${line}"/></svg>`;
}

const CHANNEL_ICON = { cover: 'arrows-exchange', light: 'bulb', em: 'gauge', em1: 'gauge', pm1: 'gauge' };
const CHANNEL_LABEL = { switch: 'Schalter', light: 'Licht', cover: 'Rollladen', em: 'Energiezähler', em1: 'Energiezähler', pm1: 'Strommesser' };

const linkLabel = (mbps) => (mbps ? (mbps >= 1000 ? `${mbps / 1000} Gbit/s` : `${Math.round(mbps)} Mbit/s`) : '');

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

const WIDGETS = {
  summary: { title: 'Übersicht', icon: 'gauge', render: wSummary },
  internet: { title: 'Internet', icon: 'world-www', render: wInternet },
  power: { title: 'Stromverbrauch live', icon: 'bolt', render: wPower },
  smarthome: { title: 'Smart Home live', icon: 'plug', render: wSmartHome },
  checks: { title: 'Dienste', icon: 'world-www', render: wChecks },
  alerts: { title: 'Offene Alarme', icon: 'bell', render: wAlerts },
  down: { title: 'Nicht erreichbar', icon: 'alert-triangle', render: wDown },
  types: { title: 'Gerätetypen', icon: 'category', render: wTypes },
  events: { title: 'Letzte Ereignisse', icon: 'list-details', render: wEvents },
  status_chart: { title: 'Verteilung', icon: 'activity', render: wStatusChart },
  services: { title: 'Dienste im Netz', icon: 'plug-connected', render: wServices },
  new: { title: 'Neu entdeckt (7 Tage)', icon: 'radar', render: wNew },
  slowest: { title: 'Langsamste Antwortzeiten', icon: 'clock', render: wSlowest },
  device: { title: 'Gerät', icon: 'activity', render: wDevice, perDevice: true },
};

function kpi(label, value, iconName, tone, href) {
  return `<a class="kpi" href="${href}"><span class="kpi-icon ${tone}">${icon(iconName)}</span>
    <span><div class="kpi-value">${esc(value)}</div><div class="kpi-label">${esc(label)}</div></span></a>`;
}

function wSummary({ summary }) {
  const s = summary.devices;
  return `<div class="kpis">
    ${kpi('Geräte', s.total, 'devices', 'tone-accent', '#/devices')}
    ${kpi('Online', s.up, 'circle-check', 'tone-up', '#/devices?status=up')}
    ${kpi('Offline', s.down, 'circle-x', 'tone-down', '#/devices?status=down')}
    ${kpi('Offene Alarme', summary.open_alerts, 'bell', summary.open_alerts ? 'tone-warn' : 'tone-muted', '#/alerts')}
    ${kpi('Neu (24 h)', s.new_24h, 'radar', 'tone-info', '#/devices?status=new')}
  </div>`;
}

/** Internet-Anschluss live: Download/Upload mit Fließanimation (Daten kommen per startLive) */
function wInternet({ summary }, widget) {
  const wan = (summary.wan_devices || []).find((w) => w.id === widget.device_id) || (summary.wan_devices || [])[0];
  if (!wan) {
    return empty('Noch kein Internet-Anschluss erkannt. Dem Router bzw. der Firewall (z. B. OPNsense) SNMP-Zugangsdaten '
      + 'zuordnen – die WAN-Schnittstelle wird dann automatisch erkannt oder lässt sich beim Gerät markieren.', 'world-www');
  }
  return `<div class="inet" data-live-wan="${wan.id}" data-iface="${esc(wan.interface)}">
    <div class="inet-path">
      <span class="inet-node">${icon('cloud')}<small>Internet</small></span>
      <div class="inet-flows">${flowLine('down')}${flowLine('up c1')}</div>
      <a class="inet-node" href="#/device/${wan.id}">${devIcon({ device_type: wan.device_type }, 'sm')}<small class="ellipsis">${esc(wan.label)}</small></a>
    </div>
    <div class="inet-values">
      <div><span class="inet-dir">${icon('arrow-down', 'i-sm')} Download</span><strong data-rx>–</strong></div>
      <div><span class="inet-dir up">${icon('arrow-up', 'i-sm')} Upload</span><strong data-tx>–</strong></div>
    </div>
    <div data-spark>${sparkline([])}</div>
    <p class="muted small" data-meta>Schnittstelle ${esc(wan.interface)} · verbinde …</p>
  </div>`;
}

const fmtWatt = (w) => (w == null ? '–' : w >= 1000 ? `${(w / 1000).toFixed(2)} kW` : `${Math.round(w)} W`);

/** Liste der aktuellen Verbraucher: live, sonst der letzte gespeicherte Stand */
function powerList(summary) {
  const fromLive = [...live.devices.values()].filter((d) => d.ok && d.power_w != null)
    .map((d) => ({ id: d.id, label: d.label, power_w: d.power_w }));
  const list = fromLive.length ? fromLive : [...((summary && summary.power) || [])];
  return list.sort((a, b) => b.power_w - a.power_w);
}

function powerBars(list) {
  const max = (list[0] && list[0].power_w) || 1;
  return list.slice(0, 8).map((p) => `<a href="#/device/${p.id}" class="ellipsis">${esc(p.label)}</a>
    <span class="bar" data-w="${pct(p.power_w, max)}"></span><span class="muted num">${esc(fmtWatt(p.power_w))}</span>`).join('');
}

/** Gesamtleistung aller Geräte mit Strommessung (z. B. Shelly) – live mit Verlauf */
function wPower({ summary }) {
  const list = powerList(summary);
  if (!list.length) return empty('Keine Geräte mit Strommessung. Shelly-Steckdosen und -Zähler werden automatisch erkannt.', 'bolt');
  const total = live.total ?? list.reduce((sum, p) => sum + p.power_w, 0);
  return `<div class="power-live" data-live-power>
    <div class="power-head"><span class="power-total" data-total data-value="${total}">${esc(fmtWatt(total))}</span>
      <span class="live-tag">LIVE</span></div>
    <div data-spark>${valueSpark(live.history)}</div>
    <div class="bars" data-bars>${powerBars(list)}</div></div>`;
}

function shellyTile(d) {
  const channels = d.channels || [];
  const on = channels.some((c) => c.on === true || c.state === 'opening' || c.state === 'closing');
  let main = '–';
  if (!d.ok) main = 'offline';
  else if (d.power_w != null) main = fmtWatt(d.power_w);
  else if (d.temp_c != null) main = `${d.temp_c} °C`;
  else if (channels.length) main = on ? 'an' : 'aus';
  const extra = d.ok
    ? [d.temp_c != null && d.power_w != null ? `${d.temp_c} °C` : null, d.humidity_pct != null ? `${d.humidity_pct} % rF` : null,
      d.battery_pct != null ? `Akku ${d.battery_pct} %` : null].filter(Boolean).join(' · ')
    : (d.error || '');
  const firstKind = (channels[0] || {}).kind;
  return `<a class="sh-tile${!d.ok ? ' off' : on ? ' on' : ''}" href="#/device/${d.id}" data-sh="${d.id}" title="${esc(d.label)}${d.model ? ` · ${esc(d.model)}` : ''}">
    <span class="sh-top">${icon(CHANNEL_ICON[firstKind] || 'plug', 'i-sm')}<span class="ellipsis">${esc(d.label)}</span></span>
    <span class="sh-val">${esc(main)}</span>
    <span class="sh-chans">${channels.map((c) => `<i class="sh-ch${c.on === true ? ' on' : ''}" title="${esc(CHANNEL_LABEL[c.kind] || c.kind)} ${Number(c.id) + 1}${c.position != null ? ` · ${c.position} %` : ''}"></i>`).join('')}</span>
    <span class="sh-extra ellipsis">${esc(extra)}</span></a>`;
}

function shellyGrid() {
  const list = [...live.devices.values()].sort((a, b) => (Number(b.ok) - Number(a.ok)) || String(a.label).localeCompare(String(b.label), 'de'));
  return `<div class="sh-grid">${list.map(shellyTile).join('')}</div>`;
}

/** Kacheln aller Smart-Home-Geräte (Shelly) mit Schaltzustand und Leistung – live */
function wSmartHome() {
  const body = live.devices.size ? shellyGrid()
    : empty('Warte auf Live-Daten … Shelly-Geräte werden automatisch erkannt und alle paar Sekunden abgefragt.', 'plug');
  return `<div data-live-smarthome>${body}</div>`;
}

/** Live-Widgets (Strom, Smart Home) an den Stream hängen */
function mountStreamWidgets(root) {
  $$('[data-live-power]', root).forEach((el) => {
    const bars = $('[data-bars]', el);
    bars.dataset.ids = powerList(state.summary).slice(0, 8).map((p) => p.id).join(',');
    onLive((msg) => {
      if (msg.type !== 'shelly') return;
      const list = powerList(null);
      tweenNumber($('[data-total]', el), live.total, fmtWatt);
      $('[data-spark]', el).innerHTML = valueSpark(live.history);
      const ids = list.slice(0, 8).map((p) => p.id).join(',');
      if (bars.dataset.ids === ids) {
        // Gleiche Reihenfolge: Balken nur verschieben (weiche Animation)
        const max = (list[0] && list[0].power_w) || 1;
        $$('.bar', bars).forEach((bar, i) => { bar.style.width = `${pct(list[i].power_w, max)}%`; });
        $$('.num', bars).forEach((num, i) => { num.textContent = fmtWatt(list[i].power_w); });
      } else {
        bars.innerHTML = powerBars(list);
        bars.dataset.ids = ids;
        applyWidths(bars);
      }
    });
  });
  $$('[data-live-smarthome]', root).forEach((el) => {
    onLive((msg) => {
      if (msg.type !== 'shelly') return;
      const changed = msg.devices || [];
      const missing = changed.some((d) => !$(`[data-sh="${d.id}"]`, el));
      if (msg.full || missing || !$('.sh-grid', el)) {
        if (live.devices.size) el.innerHTML = shellyGrid();
        return;
      }
      changed.forEach((d) => {
        $(`[data-sh="${d.id}"]`, el).outerHTML = shellyTile(d);
        $(`[data-sh="${d.id}"]`, el).classList.add('flash');
      });
    });
  });
}

/** Live-Aktualisierung aller Internet-Widgets auf der Seite */
function mountInternetWidgets(root, histories) {
  $$('[data-live-wan]', root).forEach((el) => {
    const id = Number(el.dataset.liveWan);
    const iface = el.dataset.iface;
    histories[id] ||= {};
    const [down, up] = $$('svg.flow', el);
    startLive(id, (data, history) => {
      const i = data.interfaces.find((x) => x.name === iface);
      if (!i) { $('[data-meta]', el).textContent = `Schnittstelle ${iface} nicht gefunden`; return; }
      tweenNumber($('[data-rx]', el), i.rx_bps, fmtBps);
      tweenNumber($('[data-tx]', el), i.tx_bps, fmtBps);
      setFlow(down, i.rx_bps);
      setFlow(up, i.tx_bps);
      $('[data-spark]', el).innerHTML = sparkline(history[iface]);
      $('[data-meta]', el).textContent = `Schnittstelle ${iface}${i.speed_mbps ? ` · ${linkLabel(i.speed_mbps)}` : ''} · live per ${data.source}`;
    }, (e) => { $('[data-meta]', el).textContent = e.message; }, histories[id]);
  });
}

/** Dienst-Checks mit Heartbeat-Balken */
async function wChecks() {
  const checks = await api('/checks');
  if (!checks.length) return empty('Noch keine Dienste – unter „Dienste“ z. B. die eigene Webseite oder ein Zertifikat überwachen.', 'world-www');
  return `<ul class="list">${checks.slice(0, 10).map((c) => `<li><a class="lead" href="#/checks"><span class="check-dot st-${esc(c.status)}"></span>
      <span class="ellipsis">${esc(c.name)}</span></a><span class="meta wbeats">${beats(c.beats, 20)}
      <span>${c.uptime_24h != null ? `${esc(c.uptime_24h)} %` : '–'}</span></span></li>`).join('')}</ul>`;
}

function deviceRow(d, meta) {
  return `<li><a class="lead" href="#/device/${d.id}">${devIcon(d, 'sm')}<span class="ellipsis">${esc(deviceLabel(d))}</span></a>
    <span class="meta">${meta}</span></li>`;
}

function wDown({ devices }) {
  const down = devices.filter((d) => d.monitored && d.status === 'down');
  if (!down.length) return empty('Alle überwachten Geräte sind erreichbar');
  return `<ul class="list">${down.map((d) => deviceRow(d, `${esc(d.ip)} · seit ${esc(fmtAgo(d.status_since))}`)).join('')}</ul>`;
}

function wAlerts({ alerts }) {
  if (!alerts.length) return empty('Keine offenen Alarme');
  return `<ul class="list">${alerts.slice(0, 8).map((a) => `
    <li><span class="lead">${icon('alert-triangle')}<span class="ellipsis">${a.device_id ? `<a href="#/device/${a.device_id}">${esc(a.message)}</a>` : esc(a.message)}</span></span>
    <span class="meta">${esc(fmtAgo(a.opened_at))}</span></li>`).join('')}</ul>`;
}

function eventList(events) {
  if (!events.length) return empty('Keine Ereignisse', 'list-details');
  return `<ul class="list">${events.map((e) => `
    <li><span class="lead">${eventBadge(e.kind)}<span class="ellipsis">${e.device_id ? `<a href="#/device/${e.device_id}">${esc(e.message)}</a>` : esc(e.message)}</span></span>
        <span class="meta" title="${esc(fmtTime(e.time))}">${esc(fmtAgo(e.time))}</span></li>`).join('')}</ul>`;
}

function wEvents({ events }) {
  return eventList(events.slice(0, 10));
}

function wStatusChart({ summary }) {
  const s = summary.devices;
  const parts = [['up', 'Online', s.up], ['down', 'Offline', s.down], ['unknown', 'Unbekannt', s.unknown], ['off', 'Nicht überwacht', s.unmonitored]];
  if (!s.total) return empty('Noch keine Geräte', 'devices');
  return `<div class="stack">${parts.map(([k, , v]) => (v ? `<span class="bg-${k}" data-w="${pct(v, s.total)}"></span>` : '')).join('')}</div>
    <div class="legend">${parts.map(([k, label, v]) => `<span><i class="bg-${k}"></i>${esc(label)}: ${v}</span>`).join('')}</div>`;
}

function wTypes({ summary }) {
  const types = summary.types || [];
  if (!types.length) return empty('Noch keine Geräte', 'devices');
  const max = Math.max(...types.map((t) => t.count));
  return `<ul class="list">${types.slice(0, 9).map((t) => `
    <li><a class="lead" href="#/devices?type=${esc(t.type)}">${devIcon({ device_type: t.type }, 'sm')}<span>${esc(typeInfo(t.type).label)}</span></a>
      <span class="meta">${t.count}</span></li>`).join('')}</ul>${max ? '' : ''}`;
}

function wServices({ devices }) {
  const counts = new Map();
  devices.forEach((d) => (d.open_ports || []).forEach((p) => counts.set(p, (counts.get(p) || 0) + 1)));
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (!top.length) return empty('Noch keine offenen Ports gefunden', 'plug-connected');
  const max = top[0][1];
  return `<div class="bars">${top.map(([port, n]) => `
    <span>${esc(portLabel(port))}</span><span class="bar" data-w="${pct(n, max)}"></span><span class="muted">${n}</span>`).join('')}</div>`;
}

function wNew({ devices }) {
  const limit = Date.now() - 7 * 86400000;
  const fresh = devices.filter((d) => new Date(d.first_seen).getTime() > limit)
    .sort((a, b) => new Date(b.first_seen) - new Date(a.first_seen)).slice(0, 8);
  if (!fresh.length) return empty('Keine neuen Geräte', 'radar');
  return `<ul class="list">${fresh.map((d) => deviceRow(d, esc(fmtAgo(d.first_seen)))).join('')}</ul>`;
}

function wSlowest({ devices }) {
  const slow = devices.filter((d) => d.monitored && d.status === 'up' && d.last_rtt_ms != null)
    .sort((a, b) => b.last_rtt_ms - a.last_rtt_ms).slice(0, 8);
  if (!slow.length) return empty('Keine Messwerte', 'clock');
  return `<ul class="list">${slow.map((d) => deviceRow(d, esc(fmtMs(d.last_rtt_ms)))).join('')}</ul>`;
}

/** Was das Geräte-Widget anzeigen kann (mehrere gleichzeitig wählbar) */
const DEVICE_METRICS = {
  rtt: { label: 'Antwortzeit & Verfügbarkeit', icon: 'activity' },
  cpu: { label: 'CPU-Auslastung', icon: 'cpu', key: 'cpu_pct', fmt: fmtPct, max: 100 },
  mem: { label: 'RAM-Auslastung', icon: 'gauge', key: 'mem_pct', fmt: fmtPct, max: 100 },
  disk: { label: 'Speicherbelegung', icon: 'database', key: 'disk_pct', fmt: fmtPct, max: 100 },
  temp: { label: 'Temperatur', icon: 'temperature', key: 'temp_c', fmt: (v) => (v == null ? '–' : `${Math.round(v)} °C`) },
  net: { label: 'Netzwerk (Verlauf ↓/↑)', icon: 'arrows-exchange' },
  internet: { label: 'Internet live (WAN)', icon: 'world-www' },
  live: { label: 'Datenraten live (alle Schnittstellen)', icon: 'activity' },
  power: { label: 'Stromverbrauch', icon: 'bolt', key: 'power_w', fmt: fmtWatt },
  clients: { label: 'Clients (z. B. WLAN)', icon: 'devices', key: 'clients', fmt: (v) => (v == null ? '–' : String(Math.round(v))) },
};

const lastValue = (list, key) => {
  for (let i = list.length - 1; i >= 0; i -= 1) if (list[i][key] != null) return list[i][key];
  return null;
};

async function wDevice(_ctx, widget) {
  const data = await api(`/devices/${encodeURIComponent(widget.device_id)}?hours=24`);
  const d = data.device;
  const metrics = (widget.metrics && widget.metrics.length ? widget.metrics : ['rtt']).filter((m) => DEVICE_METRICS[m]);
  const avail = availability(data.points);
  const width = 460 * Math.min(2, widget.size || 1);
  const parts = metrics.map((m) => {
    const def = DEVICE_METRICS[m];
    let head = '';
    let body = '';
    if (m === 'rtt') {
      head = `${esc(fmtMs(d.last_rtt_ms))}${avail != null ? ` · ${avail} %` : ''}`;
      body = lineChart(data.points, { series: [{ key: 'rtt_ms', label: 'Antwortzeit' }], format: fmtMs, height: 120, width, outages: true });
    } else if (m === 'net') {
      head = `↓ ${esc(fmtBps(lastValue(data.stats, 'rx_bps')))} · ↑ ${esc(fmtBps(lastValue(data.stats, 'tx_bps')))}`;
      body = lineChart(data.stats, { series: [{ key: 'rx_bps', label: 'Empfang' }, { key: 'tx_bps', label: 'Senden' }], format: fmtBps, height: 120, width });
    } else if (m === 'internet') {
      body = d.wan_interface ? wInternet({ summary: { wan_devices: [{ id: d.id, label: deviceLabel(d), interface: d.wan_interface, device_type: d.device_type }] } }, { device_id: d.id })
        : '<p class="muted small">Für dieses Gerät ist keine Internet-Schnittstelle erkannt (beim Gerät unter „Schnittstellen“ markieren).</p>';
    } else if (m === 'live') {
      body = `<div class="dev-live" data-dev-live="${d.id}"><p class="muted small">verbinde …</p></div>`;
    } else if (m === 'power' && d.integration === 'shelly') {
      const l = live.devices.get(d.id);
      head = `<span data-watt="${d.id}">${esc(l && l.ok && l.power_w != null ? fmtWatt(l.power_w) : fmtWatt(lastValue(data.stats, 'power_w')))}</span>`;
      body = lineChart(data.stats, { series: [{ key: 'power_w', label: 'Leistung' }], format: fmtWatt, height: 120, width });
    } else {
      head = esc(def.fmt(lastValue(data.stats, def.key)));
      body = lineChart(data.stats, { series: [{ key: def.key, label: def.label }], format: def.fmt, height: 120, width, maxValue: def.max ?? null });
      if (['cpu', 'mem', 'temp'].includes(m) && d.has_credentials) {
        // Aktueller Wert und Kurve der letzten Minuten kommen live (alle 2 s)
        head = `<span data-live-sys="${d.id}" data-key="${def.key}">${head}</span>`;
        body = `<div class="dw-live" data-live-spark="${d.id}" data-key="${def.key}"></div>${body}`;
      }
    }
    return `<div class="dw-part"><div class="dw-head">${icon(def.icon, 'i-sm')}<span>${esc(def.label)}</span><strong>${head}</strong></div>${body}</div>`;
  });
  return `<div class="cell-dev">${devIcon(d, 'sm')}<a href="#/device/${d.id}">${esc(deviceLabel(d))}</a> ${statusBadge(d)}
      <span class="muted small">${esc(d.ip)}</span></div>
    <div class="dw-parts">${parts.join('')}</div>`;
}

const SYS_FMT = { cpu_pct: fmtPct, mem_pct: fmtPct, temp_c: (v) => (v == null ? '–' : `${Math.round(v)} °C`) };

/** Live-Werte CPU/RAM/Temperatur in Geräte-Widgets (eine Abfrage je Gerät) */
function mountDeviceSystem(root) {
  const ids = [...new Set($$('[data-live-sys]', root).map((el) => Number(el.dataset.liveSys)))];
  ids.forEach((id) => {
    const series = {};
    const stop = startLive(id, (data) => {
      const sys = data.system || {};
      $$(`[data-live-sys="${id}"]`, root).forEach((el) => {
        const v = sys[el.dataset.key];
        if (v == null) return;
        el.textContent = SYS_FMT[el.dataset.key](v);
        el.closest('.dw-head')?.classList.add('is-live');
      });
      $$(`[data-live-spark="${id}"]`, root).forEach((el) => {
        const key = el.dataset.key;
        if (sys[key] == null) return;
        const list = (series[key] ||= []);
        list.push(sys[key]);
        if (list.length > HISTORY_POINTS) list.shift();
        el.innerHTML = valueSpark(list, 36);
      });
    }, () => stop());
  });
}

/** Live-Datenraten aller Schnittstellen eines Geräts im Widget */
function mountDeviceLive(root) {
  mountDeviceSystem(root);
  $$('[data-dev-live]', root).forEach((el) => {
    startLive(Number(el.dataset.devLive), (data) => {
      const list = data.interfaces.filter((i) => i.rx_bps != null || i.tx_bps != null)
        .sort((a, b) => ((b.rx_bps || 0) + (b.tx_bps || 0)) - ((a.rx_bps || 0) + (a.tx_bps || 0))).slice(0, 6);
      el.innerHTML = list.length ? `<div class="bars">${list.map((i) => `<span class="ellipsis mono small">${esc(i.alias || i.name)}</span>
        <span class="small">↓ ${esc(fmtBps(i.rx_bps))}</span><span class="small">↑ ${esc(fmtBps(i.tx_bps))}</span>`).join('')}</div>
        <p class="muted small">live per ${esc(data.source)}</p>` : '<p class="muted small">Noch keine Datenraten – kommt nach der zweiten Messung.</p>';
    }, (e) => { el.innerHTML = `<p class="muted small">${esc(e.message)}</p>`; });
  });
}

/** Auswahl, welches Gerät und welche Werte ein Widget zeigt */
function deviceWidgetDialog(devices, widget = {}) {
  return new Promise((resolve) => {
    const chosen = new Set(widget.metrics && widget.metrics.length ? widget.metrics : ['rtt', 'cpu', 'net']);
    const dlg = openModal('Geräte-Widget', `<form class="form" id="dw-form">
      <label>Gerät<select name="device">${devices.map((d) => `<option value="${d.id}"${d.id === widget.device_id ? ' selected' : ''}>${esc(deviceLabel(d))} – ${esc(d.ip)}</option>`).join('')}</select></label>
      <fieldset><legend>Anzeigen (mehrere möglich)</legend><div class="checks">
        ${Object.entries(DEVICE_METRICS).map(([k, m]) => `<label class="inline"><input type="checkbox" name="m" value="${k}"${chosen.has(k) ? ' checked' : ''}> ${esc(m.label)}</label>`).join('')}
      </div></fieldset>
      <p class="hint">CPU, RAM, Speicher, Temperatur und Clients gibt es bei Geräten mit SNMP-/SSH-Zugang oder aus dem UniFi-Controller,
        Strom bei Shellys, „Internet live“ beim Router/der Firewall mit erkannter WAN-Schnittstelle.</p>
      <div class="actions"><button type="submit">${icon('check')}Übernehmen</button></div></form>`);
    $('#dw-form', dlg).addEventListener('submit', (ev) => {
      ev.preventDefault();
      const metrics = $$('input[name="m"]:checked', dlg).map((c) => c.value);
      dlg.close();
      resolve({ device_id: Number(ev.target.elements.device.value), metrics: metrics.length ? metrics : ['rtt'] });
    });
    dlg.addEventListener('close', () => resolve(null), { once: true });
  });
}

function widgetTitle(widget, ctx) {
  if (widget.type !== 'device') return WIDGETS[widget.type].title;
  const d = ctx.devices.find((x) => x.id === widget.device_id);
  return d ? deviceLabel(d) : 'Gerät (gelöscht)';
}

function scanBanner(scan) {
  if (!scan || !scan.running) return '';
  return `<div class="notice info">${icon('radar')}<div>Scan läuft: <strong>${esc(scan.network)}</strong> –
    ${scan.done.toLocaleString('de-DE')} von ${scan.total.toLocaleString('de-DE')} Adressen, ${scan.found} Geräte gefunden
    ${scan.queued ? ` · ${scan.queued} weitere Netze in der Warteschlange` : ''}
    <div class="progress"><span data-w="${pct(scan.done, scan.total)}"></span></div></div></div>`;
}

function lastDiscoveryLine(summary) {
  const d = summary.last_discovery;
  if (!d) return '<p class="info-line">Noch kein Scan abgeschlossen.</p>';
  return `<p class="info-line">Letzter Scan ${esc(fmtAgo(d.time))}${d.network ? ` (${esc(d.network)})` : ''}: ${esc(d.found)} aktive Geräte in ${esc(Number(d.scanned).toLocaleString('de-DE'))} Adressen, ${esc(d.duration_s)} s</p>`;
}

async function viewDashboard() {
  let layout = await api('/dashboard');
  let ctx = null;
  let editing = false;
  const liveHistories = {};

  const load = async () => {
    const [summary, devices, events, alerts] = await Promise.all([
      api('/summary'), api('/devices'), api('/events?limit=15'), api('/alerts?open=true&limit=20'),
    ]);
    ctx = { summary, devices, events, alerts };
  };

  const render = async () => {
    const cards = await Promise.all(layout.map(async (widget, i) => {
      const def = WIDGETS[widget.type];
      if (!def) return '';
      let body;
      try { body = await def.render(ctx, widget); } catch (e) { body = `<p class="error">${esc(e.message)}</p>`; }
      const size = [1, 2, 3].includes(widget.size) ? widget.size : 1;
      const tools = editing ? `<div class="widget-tools">
          <button class="ghost" data-act="left" data-idx="${i}" title="Nach vorne">${icon('chevron-left', 'i-sm')}</button>
          <button class="ghost" data-act="right" data-idx="${i}" title="Nach hinten">${icon('chevron-right', 'i-sm')}</button>
          <button class="ghost" data-act="size" data-idx="${i}" title="Breite ändern">${size}/3</button>
          ${widget.type === 'device' ? `<button class="ghost" data-act="config" data-idx="${i}" title="Werte auswählen">${icon('settings', 'i-sm')}</button>` : ''}
          <button class="ghost" data-act="remove" data-idx="${i}" title="Entfernen">${icon('x', 'i-sm')}</button></div>` : '';
      return `<section class="card widget span-${size}" data-idx="${i}" draggable="${editing}">
          <header><h2>${icon(def.icon)}${esc(widgetTitle(widget, ctx))}</h2>${tools}</header>
          <div class="widget-body">${body}</div></section>`;
    }));

    const addOptions = `<option value="">+ Widget hinzufügen …</option>
      ${Object.entries(WIDGETS).filter(([, def]) => !def.perDevice).map(([key, def]) => `<option value="${key}">${esc(def.title)}</option>`).join('')}
      <optgroup label="Einzelnes Gerät (Werte frei wählbar)">
        ${ctx.devices.map((d) => `<option value="device:${d.id}">${esc(deviceLabel(d))} – ${esc(d.ip)}</option>`).join('')}
      </optgroup>`;
    const actions = editing
      ? `<select id="add-widget">${addOptions}</select>
         <button id="save-dash" type="button">${icon('check')}Speichern</button>
         <button id="cancel-dash" class="ghost" type="button">Abbrechen</button>`
      : `<button id="edit-dash" class="ghost" type="button">${icon('layout-grid')}Anpassen</button>`;

    view().innerHTML = `
      <div class="page-head"><div>${lastDiscoveryLine(ctx.summary)}</div><div class="actions">${actions}</div></div>
      ${scanBanner(ctx.summary.scan)}
      <div class="grid${editing ? ' editing' : ''}">${cards.join('') || empty('Keine Widgets – über „Anpassen“ hinzufügen.', 'layout-grid')}</div>`;
    applyWidths(view());
    bindEditing();
    // Live-Widgets neu starten (die alten Abfragen gehören zu den ersetzten Elementen)
    state.liveStops.forEach((stop) => stop());
    state.liveStops = [];
    mountInternetWidgets(view(), liveHistories);
    mountStreamWidgets(view());
    mountDeviceLive(view());
  };

  const move = (from, to) => {
    if (to < 0 || to >= layout.length) return;
    const [widget] = layout.splice(from, 1);
    layout.splice(to, 0, widget);
  };

  function bindEditing() {
    $('#edit-dash')?.addEventListener('click', () => { editing = true; render(); });
    $('#cancel-dash')?.addEventListener('click', async () => { editing = false; layout = await api('/dashboard'); render(); });
    $('#save-dash')?.addEventListener('click', () => attempt(async () => {
      layout = await api('/dashboard', { method: 'PUT', body: layout });
      editing = false;
      render();
    }, 'Dashboard gespeichert'));
    $('#add-widget')?.addEventListener('change', (ev) => {
      const value = ev.target.value;
      if (!value) return;
      if (value.startsWith('device:')) {
        const d = ctx.devices.find((x) => x.id === Number(value.slice(7)));
        deviceWidgetDialog(ctx.devices, { device_id: d && d.id }).then((cfg) => {
          if (cfg) { layout.push({ type: 'device', size: cfg.metrics.length > 2 ? 2 : 1, ...cfg }); render(); } else render();
        });
        return;
      }
      layout.push({ type: value, size: 1 });
      render();
    });
    $$('.widget-tools button').forEach((btn) => btn.addEventListener('click', () => {
      const i = Number(btn.dataset.idx);
      if (btn.dataset.act === 'left') move(i, i - 1);
      if (btn.dataset.act === 'right') move(i, i + 1);
      if (btn.dataset.act === 'size') layout[i].size = ((layout[i].size || 1) % 3) + 1;
      if (btn.dataset.act === 'remove') layout.splice(i, 1);
      if (btn.dataset.act === 'config') {
        deviceWidgetDialog(ctx.devices, layout[i]).then((cfg) => { if (cfg) Object.assign(layout[i], cfg); render(); });
        return;
      }
      render();
    }));
    if (!editing) return;
    let dragIdx = null;
    $$('.widget').forEach((card) => {
      card.addEventListener('dragstart', () => { dragIdx = Number(card.dataset.idx); });
      card.addEventListener('dragover', (ev) => { ev.preventDefault(); card.classList.add('drag-over'); });
      card.addEventListener('dragleave', () => card.classList.remove('drag-over'));
      card.addEventListener('drop', (ev) => {
        ev.preventDefault();
        const target = Number(card.dataset.idx);
        if (dragIdx !== null && dragIdx !== target) { move(dragIdx, target); render(); }
      });
    });
  }

  await load();
  await render();
  autoRefresh(async () => { if (editing) return; await load(); await render(); });
}

// ---------------------------------------------------------------------------
// Anmeldung, Navigation, Rahmen
// ---------------------------------------------------------------------------

function showLogin() {
  state.user = null;
  disconnectStream();
  clearInterval(state.refreshTimer);
  clearInterval(state.globalTimer);
  state.liveStops.forEach((stop) => stop());
  state.liveStops = [];
  $('#app').hidden = true;
  $('#login-view').innerHTML = `
    <div class="login-wrap"><form class="card login" id="login-form">
      <div class="brand"><img src="favicon.svg" alt="" width="36" height="36"><span>Net<b>Pulse</b></span></div>
      <p class="muted">Netzwerk-Monitoring</p>
      <label>Benutzername<input name="username" autocomplete="username" required autofocus></label>
      <label>Passwort<input name="password" type="password" autocomplete="current-password" required></label>
      <label id="code-field" hidden>Code aus der Authenticator-App<input name="code" inputmode="numeric" autocomplete="one-time-code"
        pattern="[0-9 ]{6,7}" maxlength="7" placeholder="123 456"></label>
      <button type="submit">Anmelden</button>
      <p class="error" id="login-error"></p>
    </form></div>`;
  $('#login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    try {
      const result = await api('/login', { method: 'POST', body: { username: f.get('username'), password: f.get('password'), code: f.get('code') || null } });
      if (result.totp_required) {
        // Passwort stimmt – jetzt noch den Code aus der Authenticator-App
        $('#code-field').hidden = false;
        $('#login-error').textContent = '';
        $('#login-form input[name=code]').focus();
        return;
      }
      state.user = result;
      startApp();
    } catch (e) {
      $('#login-error').textContent = e.message;
    }
  });
}

const ROUTES = {
  dashboard: { title: 'Dashboard', view: () => viewDashboard() },
  devices: { title: 'Geräte', view: (a, p) => viewDevices(a, p) },
  device: { title: 'Gerät', view: (a, p) => viewDevice(a, p), nav: 'devices' },
  alerts: { title: 'Alarme', view: (a, p) => viewAlerts(a, p) },
  events: { title: 'Ereignisse', view: () => viewEvents() },
  checks: { title: 'Dienste', view: () => viewChecks() },
  map: { title: 'Netzwerkkarte', view: () => viewMap() },
  syslog: { title: 'Protokolle', view: (a, p) => viewSyslog(a, p), admin: true },
  statuspage: { title: 'Statusseite', view: () => viewStatusPage(), admin: true },
  networks: { title: 'Netzwerke', view: () => viewNetworks(), admin: true },
  credentials: { title: 'Zugangsdaten', view: () => viewCredentials(), admin: true },
  channels: { title: 'Benachrichtigungen', view: () => viewChannels(), admin: true },
  users: { title: 'Benutzer', view: () => viewUsers(), admin: true },
  audit: { title: 'Audit-Log', view: () => viewAudit(), admin: true },
  logs: { title: 'System-Log', view: () => viewLogs(), admin: true },
  maintenance: { title: 'Wartung', view: () => viewMaintenance(), admin: true },
  account: { title: 'Mein Konto', view: () => viewAccount() },
};

function autoRefresh(fn, seconds = 30) {
  clearInterval(state.refreshTimer);
  // Im Hintergrund-Tab nicht nachladen – spart Last auf Server und Datenbank
  state.refreshTimer = setInterval(() => { if (!document.hidden) fn().catch(() => {}); }, seconds * 1000);
}

async function route() {
  if (!state.user) return;
  clearInterval(state.refreshTimer);
  state.liveStops.forEach((stop) => stop());
  state.liveStops = [];
  $('#sidebar').classList.remove('open');
  const [path, query] = location.hash.replace(/^#\/?/, '').split('?');
  const [name, arg] = path.split('/');
  const key = ROUTES[name] ? name : 'dashboard';
  const r = ROUTES[key];
  $('#page-title').textContent = r.title;
  document.title = `${r.title} · NetPulse`;
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.getAttribute('href') === `#/${r.nav || key}`));
  if (r.admin && !isAdmin()) {
    view().innerHTML = empty('Keine Berechtigung für diese Seite.', 'lock');
    return;
  }
  view().innerHTML = '<div class="empty">Lade …</div>';
  try {
    await r.view(arg, new URLSearchParams(query || ''));
  } catch (e) {
    if (state.user) view().innerHTML = `<div class="notice">${icon('alert-triangle')}<span>${esc(e.message)}</span></div>`;
  }
}

/** Alarm-Zähler und Scan-Fortschritt in der Seitenleiste aktualisieren */
async function refreshShell() {
  try {
    const summary = await api('/summary');
    state.summary = summary;
    const badge = $('#alert-badge');
    badge.hidden = !summary.open_alerts;
    badge.textContent = summary.open_alerts;
    const scan = summary.scan;
    const mini = $('#scan-mini');
    mini.hidden = !(scan && scan.running);
    if (scan && scan.running) {
      mini.innerHTML = `${icon('radar', 'i-sm')} Scan <strong>${esc(scan.network)}</strong><br>
        <span class="muted">${pct(scan.done, scan.total)} % · ${scan.found} Geräte</span>
        <div class="progress"><span data-w="${pct(scan.done, scan.total)}"></span></div>`;
      applyWidths(mini);
    }
  } catch { /* egal */ }
}

// ----- App-Installation -----
let installPrompt = null;
window.addEventListener('beforeinstallprompt', (ev) => {
  // Chrome/Edge/Android: eigenen Knopf zeigen statt der versteckten Browser-Leiste
  ev.preventDefault();
  installPrompt = ev;
  $$('[data-install]').forEach((b) => { b.hidden = false; });
});
window.addEventListener('appinstalled', () => {
  installPrompt = null;
  $$('[data-install]').forEach((b) => { b.hidden = true; });
  toast('NetPulse ist jetzt als App installiert');
});

const isStandalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

/** Hinweis passend zum Browser, wie NetPulse installiert wird */
function installHint() {
  const ua = navigator.userAgent;
  if (isStandalone()) return { ok: true, text: 'NetPulse läuft bereits als installierte App.' };
  if (location.protocol !== 'https:') {
    return { ok: false, text: 'Installieren geht nur über HTTPS mit gültigem Zertifikat – also über deine eigene Adresse (z. B. https://monitoring.buschehome.de), nicht über die IP-Adresse.' };
  }
  if (/iPhone|iPad/.test(ua)) return { ok: true, text: 'iPhone/iPad: in Safari unten auf „Teilen“ tippen → „Zum Home-Bildschirm“.' };
  if (/Firefox\//.test(ua) && !/Android/.test(ua)) {
    return { ok: false, text: 'Firefox am PC kann Web-Apps nicht installieren. Bitte die Seite in Chrome oder Edge öffnen – dort erscheint „App installieren“.' };
  }
  if (/Android/.test(ua)) return { ok: true, text: 'Android: Browser-Menü (⋮) → „App installieren“ bzw. „Zum Startbildschirm hinzufügen“.' };
  if (/Safari\//.test(ua) && !/Chrome\//.test(ua)) return { ok: true, text: 'Safari am Mac: Menü „Ablage“ → „Zum Dock hinzufügen“.' };
  return { ok: true, text: 'Chrome/Edge: Symbol „App installieren“ rechts in der Adressleiste oder Menü → „App installieren“.' };
}

async function installApp() {
  if (installPrompt) {
    installPrompt.prompt();
    const { outcome } = await installPrompt.userChoice;
    if (outcome === 'accepted') installPrompt = null;
    return;
  }
  toast(installHint().text, !installHint().ok);
}

/** Service Worker: macht NetPulse als App installierbar und empfängt Push-Nachrichten (nur über HTTPS) */
function registerServiceWorker() {
  if (!('serviceWorker' in navigator) || !window.isSecureContext) return;
  navigator.serviceWorker.register('/sw.js').catch(() => { /* z. B. selbst signiertes Zertifikat */ });
}

function applyTheme(theme) {
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  const dark = theme === 'dark' || (theme !== 'light' && matchMedia('(prefers-color-scheme: dark)').matches);
  $('#theme-toggle').innerHTML = icon(dark ? 'sun' : 'moon');
}

function startApp() {
  $('#login-view').innerHTML = '';
  $('#app').hidden = false;
  document.body.classList.toggle('is-admin', isAdmin());
  $('#user-name').textContent = state.user.username;
  refreshShell();
  connectStream();
  registerServiceWorker();
  clearInterval(state.globalTimer);
  // Alarme kommen sofort über den Live-Stream; die Seitenleiste reicht alle 30 s
  state.globalTimer = setInterval(() => { if (!document.hidden) refreshShell(); }, 30000);
  if (!location.hash || location.hash === '#/') location.hash = '#/dashboard';
  else route();
}

function init() {
  registerServiceWorker();
  $$('[data-install]').forEach((b) => b.addEventListener('click', () => installApp().catch(() => {})));
  let theme = null;
  try { theme = localStorage.getItem('np-theme'); } catch { /* privater Modus */ }
  applyTheme(theme);
  $('#theme-toggle').addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme === 'dark'
      || (!document.documentElement.dataset.theme && matchMedia('(prefers-color-scheme: dark)').matches);
    const next = dark ? 'light' : 'dark';
    try { localStorage.setItem('np-theme', next); } catch { /* egal */ }
    applyTheme(next);
  });
  $('#menu-toggle').addEventListener('click', () => $('#sidebar').classList.toggle('open'));
  $('#global-search').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') location.hash = `#/devices?q=${encodeURIComponent(ev.target.value.trim())}`;
  });
  window.addEventListener('hashchange', route);
  $('#logout').addEventListener('click', async () => {
    try { await api('/logout', { method: 'POST' }); } catch { /* lokal trotzdem abmelden */ }
    showLogin();
  });
  (async () => {
    try {
      state.user = await api('/me');
      startApp();
    } catch {
      showLogin();
    }
  })();
}

window.addEventListener('DOMContentLoaded', init);
