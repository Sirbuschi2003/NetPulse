'use strict';
/*
 * NetPulse – Weboberfläche (ohne Build-Schritt, ohne externe Bibliotheken).
 *
 * Sicherheit:
 * - Alle Daten aus der API werden mit esc() maskiert, bevor sie ins HTML kommen (XSS-Schutz).
 *   Hostnamen stammen z. B. aus DNS und sind damit nicht vertrauenswürdig.
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

const state = { user: null, refreshTimer: null };

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

function toast(message, isError = false) {
  const el = document.createElement('div');
  el.className = 'toast' + (isError ? ' error' : '');
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

/** Führt eine Aktion aus und zeigt Fehler als Hinweis an */
async function attempt(fn, successMessage) {
  try {
    await fn();
    if (successMessage) toast(successMessage);
  } catch (e) {
    toast(e.message, true);
  }
}

/** Breiten von Balken setzen (per JavaScript, weil die CSP Inline-Styles verbietet) */
function applyWidths(root = document) {
  $$('[data-w]', root).forEach((el) => { el.style.width = `${el.dataset.w}%`; });
}

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
const pct = (part, total) => (total ? Math.round((part / total) * 1000) / 10 : 0);

const STATUS_LABEL = { up: 'online', down: 'offline', unknown: 'unbekannt' };
const EVENT_LABEL = { up: 'online', down: 'offline', discovered: 'neu', mac_changed: 'MAC geändert' };
const statusBadge = (d) =>
  d.monitored === false
    ? '<span class="badge st-unknown">nicht überwacht</span>'
    : `<span class="badge st-${esc(d.status)}">${esc(STATUS_LABEL[d.status] || d.status)}</span>`;
const eventBadge = (kind) => `<span class="badge ev-${esc(kind)}">${esc(EVENT_LABEL[kind] || kind)}</span>`;
const deviceLabel = (d) => d.name || d.hostname || d.ip;

const PORT_NAMES = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 139: 'NetBIOS',
  143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 548: 'AFP', 554: 'RTSP', 631: 'IPP', 993: 'IMAPS', 1883: 'MQTT',
  3306: 'MySQL', 3389: 'RDP', 5000: 'NAS/UPnP', 5001: 'NAS-HTTPS', 5432: 'PostgreSQL', 5900: 'VNC',
  5985: 'WinRM', 5986: 'WinRM-TLS', 8006: 'Proxmox', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9100: 'Drucker',
};
const portLabel = (p) => (PORT_NAMES[p] ? `${p} ${PORT_NAMES[p]}` : String(p));
const portChips = (list) => (list && list.length ? list.map((p) => `<span class="chip">${esc(portLabel(p))}</span>`).join(' ') : '–');

function lastDiscoveryLine(summary) {
  const d = summary.last_discovery;
  if (!d) return '<p class="info-line">Noch kein Scan durchgeführt.</p>';
  return `<p class="info-line">Letzter Scan ${esc(fmtAgo(d.time))}: ${esc(d.found)} aktive Geräte in ${esc(d.scanned)} Adressen (${esc(d.duration_s)} s)</p>`;
}

// ---------------------------------------------------------------------------
// Latenz-Diagramm (SVG, ohne Bibliothek)
// ---------------------------------------------------------------------------

function latencyChart(points, height = 170) {
  if (!points.length) return '<p class="muted">Noch keine Messwerte vorhanden.</p>';
  const W = 640;
  const H = height;
  const P = { l: 46, r: 8, t: 10, b: 22 };
  const times = points.map((p) => new Date(p.bucket).getTime());
  const t0 = times[0];
  const t1 = Math.max(times[times.length - 1], t0 + 60000);
  const values = points.map((p) => p.rtt_ms).filter((v) => v != null);
  const max = Math.max(1, ...values) * 1.15;
  const x = (t) => P.l + ((t - t0) / (t1 - t0)) * (W - P.l - P.r);
  const y = (v) => P.t + (1 - v / max) * (H - P.t - P.b);

  // Linie unterbrechen, wo keine Werte vorliegen (Gerät offline)
  let path = '';
  let penDown = false;
  points.forEach((p, i) => {
    if (p.rtt_ms == null) { penDown = false; return; }
    path += `${penDown ? 'L' : 'M'}${x(times[i]).toFixed(1)},${y(p.rtt_ms).toFixed(1)} `;
    penDown = true;
  });
  const slot = Math.max(3, (W - P.l - P.r) / points.length);
  const outages = points
    .map((p, i) => (p.availability != null && p.availability < 1
      ? `<rect class="outage" x="${(x(times[i]) - slot / 2).toFixed(1)}" y="${P.t}" width="${slot.toFixed(1)}" height="${H - P.t - P.b}" opacity="${(0.25 + 0.6 * (1 - p.availability)).toFixed(2)}"><title>Ausfall ${Math.round((1 - p.availability) * 100)} %</title></rect>`
      : ''))
    .join('');
  const fmt = (t) => new Date(t).toLocaleString('de-DE', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' });
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Verlauf der Antwortzeit">
    ${outages}
    <line class="axis" x1="${P.l}" y1="${H - P.b}" x2="${W - P.r}" y2="${H - P.b}"/>
    <line class="axis" x1="${P.l}" y1="${P.t}" x2="${P.l}" y2="${H - P.b}"/>
    <text class="lbl" x="${P.l - 6}" y="${P.t + 9}" text-anchor="end">${max < 10 ? max.toFixed(1) : Math.round(max)} ms</text>
    <text class="lbl" x="${P.l - 6}" y="${H - P.b}" text-anchor="end">0</text>
    <text class="lbl" x="${P.l}" y="${H - 6}">${esc(fmt(t0))}</text>
    <text class="lbl" x="${W - P.r}" y="${H - 6}" text-anchor="end">${esc(fmt(t1))}</text>
    <path class="line" d="${path}"/>
  </svg>`;
}

function availability(points) {
  const values = points.map((p) => p.availability).filter((v) => v != null);
  if (!values.length) return null;
  return Math.round((values.reduce((a, b) => a + b, 0) / values.length) * 10000) / 100;
}

// ---------------------------------------------------------------------------
// Dashboard-Widgets. Jedes Widget bekommt die geladenen Daten (ctx) und seine Einstellungen.
// ---------------------------------------------------------------------------

const WIDGETS = {
  summary: { title: 'Status-Übersicht', render: wSummary },
  down: { title: 'Nicht erreichbar', render: wDown },
  events: { title: 'Letzte Ereignisse', render: wEvents },
  status_chart: { title: 'Verteilung', render: wStatusChart },
  services: { title: 'Dienste im Netz', render: wServices },
  new: { title: 'Neu entdeckt (7 Tage)', render: wNew },
  slowest: { title: 'Langsamste Antwortzeiten', render: wSlowest },
  device: { title: 'Gerät', render: wDevice, perDevice: true },
};

function wSummary({ summary }) {
  const s = summary.devices;
  const tile = (label, value, cls, href) =>
    `<a class="tile ${cls}" href="${href}"><span class="tile-value">${esc(value)}</span><span class="tile-label">${esc(label)}</span></a>`;
  return `<div class="tiles">
    ${tile('Geräte gesamt', s.total, '', '#/devices')}
    ${tile('Online', s.up, 'st-up', '#/devices?status=up')}
    ${tile('Offline', s.down, 'st-down', '#/devices?status=down')}
    ${tile('Unbekannt', s.unknown, 'st-unknown', '#/devices?status=unknown')}
    ${tile('Nicht überwacht', s.unmonitored, '', '#/devices?status=unmonitored')}
    ${tile('Neu (24 h)', s.new_24h, '', '#/devices?status=new')}
  </div>`;
}

function wDown({ devices }) {
  const down = devices.filter((d) => d.monitored && d.status === 'down');
  if (!down.length) return '<p class="muted">Alle überwachten Geräte sind erreichbar ✓</p>';
  return `<ul class="list">${down.map((d) => `
    <li><a href="#/device/${d.id}">${esc(deviceLabel(d))}</a>
        <span class="meta">${esc(d.ip)} · zuletzt ${esc(fmtAgo(d.last_seen))}</span></li>`).join('')}</ul>`;
}

function eventList(events) {
  if (!events.length) return '<p class="muted">Keine Ereignisse.</p>';
  return `<ul class="list">${events.map((e) => `
    <li><span>${eventBadge(e.kind)} ${e.device_id ? `<a href="#/device/${e.device_id}">${esc(e.message)}</a>` : esc(e.message)}</span>
        <span class="meta" title="${esc(fmtTime(e.time))}">${esc(fmtAgo(e.time))}</span></li>`).join('')}</ul>`;
}

function wEvents({ events }) {
  return eventList(events.slice(0, 12));
}

function wStatusChart({ summary }) {
  const s = summary.devices;
  const parts = [
    ['up', 'Online', s.up], ['down', 'Offline', s.down],
    ['unknown', 'Unbekannt', s.unknown], ['off', 'Nicht überwacht', s.unmonitored],
  ];
  if (!s.total) return '<p class="muted">Noch keine Geräte.</p>';
  return `<div class="stack">${parts.map(([k, , v]) => (v ? `<span class="bg-${k}" data-w="${pct(v, s.total)}"></span>` : '')).join('')}</div>
    <div class="legend">${parts.map(([k, label, v]) => `<span><i class="bg-${k}"></i>${esc(label)}: ${v} (${pct(v, s.total)} %)</span>`).join('')}</div>`;
}

function wServices({ devices }) {
  const counts = new Map();
  devices.forEach((d) => (d.open_ports || []).forEach((p) => counts.set(p, (counts.get(p) || 0) + 1)));
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  if (!top.length) return '<p class="muted">Noch keine offenen Ports gefunden.</p>';
  const max = top[0][1];
  return `<div class="bars">${top.map(([port, n]) => `
    <span>${esc(portLabel(port))}</span><span class="bar" data-w="${pct(n, max)}"></span><span class="muted">${n}</span>`).join('')}</div>`;
}

function wNew({ devices }) {
  const limit = Date.now() - 7 * 86400000;
  const fresh = devices
    .filter((d) => new Date(d.first_seen).getTime() > limit)
    .sort((a, b) => new Date(b.first_seen) - new Date(a.first_seen))
    .slice(0, 10);
  if (!fresh.length) return '<p class="muted">Keine neuen Geräte.</p>';
  return `<ul class="list">${fresh.map((d) => `
    <li><a href="#/device/${d.id}">${esc(deviceLabel(d))}</a><span class="meta">${esc(d.ip)} · ${esc(fmtAgo(d.first_seen))}</span></li>`).join('')}</ul>`;
}

function wSlowest({ devices }) {
  const slow = devices
    .filter((d) => d.monitored && d.status === 'up' && d.last_rtt_ms != null)
    .sort((a, b) => b.last_rtt_ms - a.last_rtt_ms)
    .slice(0, 8);
  if (!slow.length) return '<p class="muted">Keine Messwerte.</p>';
  return `<ul class="list">${slow.map((d) => `
    <li><a href="#/device/${d.id}">${esc(deviceLabel(d))}</a><span class="meta">${esc(fmtMs(d.last_rtt_ms))}</span></li>`).join('')}</ul>`;
}

async function wDevice(_ctx, widget) {
  const data = await api(`/devices/${encodeURIComponent(widget.device_id)}?hours=24`);
  const d = data.device;
  const avail = availability(data.points);
  return `<p>${statusBadge(d)} <a href="#/device/${d.id}">${esc(deviceLabel(d))}</a>
      <span class="muted">· ${esc(d.ip)} · ${esc(fmtMs(d.last_rtt_ms))}${avail != null ? ` · ${avail} % verfügbar (24 h)` : ''}</span></p>
    ${latencyChart(data.points, 140)}`;
}

function widgetTitle(widget, ctx) {
  if (widget.type !== 'device') return WIDGETS[widget.type].title;
  const d = ctx.devices.find((x) => x.id === widget.device_id);
  return d ? `Gerät: ${deviceLabel(d)}` : 'Gerät (gelöscht)';
}

// ---------------------------------------------------------------------------
// Ansichten
// ---------------------------------------------------------------------------

async function viewDashboard() {
  let layout = await api('/dashboard');
  let ctx = null;
  let editing = false;

  const load = async () => {
    const [summary, devices, events] = await Promise.all([api('/summary'), api('/devices'), api('/events?limit=15')]);
    ctx = { summary, devices, events };
  };

  const render = async () => {
    const cards = await Promise.all(layout.map(async (widget, i) => {
      const def = WIDGETS[widget.type];
      if (!def) return '';
      let body;
      try {
        body = await def.render(ctx, widget);
      } catch (e) {
        body = `<p class="error">${esc(e.message)}</p>`;
      }
      const size = [1, 2, 3].includes(widget.size) ? widget.size : 1;
      const tools = editing ? `<div class="widget-tools">
          <button class="ghost" data-act="left" data-idx="${i}" title="Nach vorne">◀</button>
          <button class="ghost" data-act="right" data-idx="${i}" title="Nach hinten">▶</button>
          <button class="ghost" data-act="size" data-idx="${i}" title="Breite ändern">${size}/3</button>
          <button class="ghost" data-act="remove" data-idx="${i}" title="Entfernen">✕</button></div>` : '';
      return `<section class="card widget span-${size}" data-idx="${i}" draggable="${editing}">
          <header><h2>${esc(widgetTitle(widget, ctx))}</h2>${tools}</header>
          <div class="widget-body">${body}</div></section>`;
    }));

    const addOptions = `<option value="">+ Widget hinzufügen …</option>
      ${Object.entries(WIDGETS).filter(([, def]) => !def.perDevice).map(([key, def]) => `<option value="${key}">${esc(def.title)}</option>`).join('')}
      <optgroup label="Einzelnes Gerät (Latenz-Verlauf)">
        ${ctx.devices.map((d) => `<option value="device:${d.id}">${esc(deviceLabel(d))} – ${esc(d.ip)}</option>`).join('')}
      </optgroup>`;
    const actions = editing
      ? `<select id="add-widget">${addOptions}</select>
         <button id="save-dash" type="button">Speichern</button>
         <button id="cancel-dash" class="ghost" type="button">Abbrechen</button>`
      : '<button id="edit-dash" class="ghost" type="button">Anpassen</button>';

    view().innerHTML = `
      <div class="page-head"><h1>Dashboard</h1><div class="actions">${actions}</div></div>
      ${lastDiscoveryLine(ctx.summary)}
      <div class="grid${editing ? ' editing' : ''}">${cards.join('') || '<p class="muted">Keine Widgets – über „Anpassen“ hinzufügen.</p>'}</div>`;
    applyWidths(view());
    bindEditing();
  };

  const move = (from, to) => {
    if (to < 0 || to >= layout.length) return;
    const [widget] = layout.splice(from, 1);
    layout.splice(to, 0, widget);
  };

  function bindEditing() {
    $('#edit-dash')?.addEventListener('click', () => { editing = true; render(); });
    $('#cancel-dash')?.addEventListener('click', async () => {
      editing = false;
      layout = await api('/dashboard');
      render();
    });
    $('#save-dash')?.addEventListener('click', () => attempt(async () => {
      layout = await api('/dashboard', { method: 'PUT', body: layout });
      editing = false;
      render();
    }, 'Dashboard gespeichert'));
    $('#add-widget')?.addEventListener('change', (ev) => {
      const value = ev.target.value;
      if (!value) return;
      if (value.startsWith('device:')) layout.push({ type: 'device', size: 1, device_id: Number(value.slice(7)) });
      else layout.push({ type: value, size: 1 });
      render();
    });
    $$('.widget-tools button').forEach((btn) => btn.addEventListener('click', () => {
      const i = Number(btn.dataset.idx);
      if (btn.dataset.act === 'left') move(i, i - 1);
      if (btn.dataset.act === 'right') move(i, i + 1);
      if (btn.dataset.act === 'size') layout[i].size = ((layout[i].size || 1) % 3) + 1;
      if (btn.dataset.act === 'remove') layout.splice(i, 1);
      render();
    }));
    // Ziehen & Ablegen zum Umsortieren
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
  autoRefresh(async () => {
    if (editing) return;
    await load();
    await render();
  });
}

async function viewDevices(_arg, params) {
  let devices = await api('/devices');
  const filters = { q: '', status: params.get('status') || '' };

  view().innerHTML = `
    <div class="page-head"><h1>Geräte</h1>
      <div class="actions">
        <input id="q" type="search" placeholder="Suchen: Name, IP, MAC, Port …" aria-label="Suchen">
        <select id="status-filter" aria-label="Status">
          <option value="">Alle</option><option value="up">Online</option><option value="down">Offline</option>
          <option value="unknown">Unbekannt</option><option value="unmonitored">Nicht überwacht</option>
          <option value="new">Neu (24 h)</option>
        </select>
      </div></div>
    <div class="card table-wrap"><table>
      <thead><tr><th>Status</th><th>Name</th><th>IP</th><th>MAC</th><th>Dienste</th><th>Antwortzeit</th><th>Zuletzt gesehen</th></tr></thead>
      <tbody id="rows"></tbody></table></div>
    <p class="muted" id="count"></p>`;
  $('#status-filter').value = filters.status;

  const matches = (d) => {
    if (filters.status === 'unmonitored' && d.monitored) return false;
    if (filters.status === 'new' && Date.now() - new Date(d.first_seen).getTime() > 86400000) return false;
    if (['up', 'down', 'unknown'].includes(filters.status) && (!d.monitored || d.status !== filters.status)) return false;
    if (!filters.q) return true;
    const haystack = [d.name, d.hostname, d.ip, d.mac, d.notes, ...(d.open_ports || []).map(portLabel)].join(' ').toLowerCase();
    return haystack.includes(filters.q);
  };

  const renderRows = () => {
    const shown = devices.filter(matches);
    $('#rows').innerHTML = shown.map((d) => `
      <tr class="clickable${d.monitored ? '' : ' unmonitored'}" data-id="${d.id}">
        <td>${statusBadge(d)}</td>
        <td>${esc(deviceLabel(d))}${d.name && d.hostname ? `<br><span class="muted">${esc(d.hostname)}</span>` : ''}</td>
        <td class="mono">${esc(d.ip)}</td>
        <td class="mono">${esc(d.mac || '–')}</td>
        <td>${portChips(d.open_ports)}</td>
        <td>${esc(fmtMs(d.last_rtt_ms))}</td>
        <td title="${esc(fmtTime(d.last_seen))}">${esc(fmtAgo(d.last_seen))}</td>
      </tr>`).join('') || '<tr><td colspan="7" class="muted">Keine Geräte gefunden.</td></tr>';
    $('#count').textContent = `${shown.length} von ${devices.length} Geräten`;
  };

  $('#q').addEventListener('input', (ev) => { filters.q = ev.target.value.trim().toLowerCase(); renderRows(); });
  $('#status-filter').addEventListener('change', (ev) => { filters.status = ev.target.value; renderRows(); });
  $('#rows').addEventListener('click', (ev) => {
    const row = ev.target.closest('tr[data-id]');
    if (row) location.hash = `#/device/${row.dataset.id}`;
  });
  renderRows();
  autoRefresh(async () => { devices = await api('/devices'); renderRows(); });
}

async function viewDevice(id) {
  let hours = 24;
  const isAdmin = state.user.role === 'admin';
  let data = await api(`/devices/${encodeURIComponent(id)}?hours=${hours}`);
  const d0 = data.device;

  view().innerHTML = `
    <div class="page-head">
      <h1 id="dev-title"></h1>
      <div class="actions"><a href="#/devices">← Alle Geräte</a></div>
    </div>
    <div class="grid">
      <section class="card span-1"><header><h2>Details</h2></header><div id="dev-details"></div></section>
      <section class="card span-2">
        <header><h2>Antwortzeit &amp; Verfügbarkeit</h2>
          <select id="range" aria-label="Zeitraum">
            <option value="24">24 Stunden</option><option value="168">7 Tage</option><option value="720">30 Tage</option><option value="2160">90 Tage</option>
          </select></header>
        <div id="dev-chart"></div>
      </section>
      ${isAdmin ? `<section class="card span-1"><header><h2>Bearbeiten</h2></header>
        <form class="form" id="dev-form">
          <label>Anzeigename<input name="name" maxlength="200" value="${esc(d0.name || '')}" placeholder="${esc(d0.hostname || d0.ip)}"></label>
          <label>Notizen<textarea name="notes" maxlength="5000">${esc(d0.notes || '')}</textarea></label>
          <label class="inline"><input type="checkbox" name="monitored"${d0.monitored ? ' checked' : ''}> Erreichbarkeit überwachen</label>
          <div class="actions"><button type="submit">Speichern</button>
            <button type="button" class="danger" id="dev-delete">Gerät löschen</button></div>
        </form></section>` : ''}
      <section class="card ${isAdmin ? 'span-2' : 'span-3'}"><header><h2>Ereignisse</h2></header><div id="dev-events"></div></section>
    </div>`;

  const update = () => {
    const d = data.device;
    const avail = availability(data.points);
    $('#dev-title').innerHTML = `${esc(deviceLabel(d))} ${statusBadge(d)}`;
    $('#dev-details').innerHTML = `<dl class="details">
      <dt>IP-Adresse</dt><dd class="mono">${esc(d.ip)}</dd>
      <dt>MAC-Adresse</dt><dd class="mono">${esc(d.mac || '–')}</dd>
      <dt>Hostname</dt><dd>${esc(d.hostname || '–')}</dd>
      <dt>Antwortzeit</dt><dd>${esc(fmtMs(d.last_rtt_ms))}</dd>
      <dt>Dienste</dt><dd>${portChips(d.open_ports)}</dd>
      <dt>Erstmals gesehen</dt><dd>${esc(fmtTime(d.first_seen))}</dd>
      <dt>Zuletzt gesehen</dt><dd>${esc(fmtTime(d.last_seen))}</dd>
      <dt>Letzte Prüfung</dt><dd>${esc(fmtTime(d.last_check))}</dd>
      ${d.notes ? `<dt>Notizen</dt><dd>${esc(d.notes)}</dd>` : ''}
    </dl>`;
    $('#dev-chart').innerHTML = `
      <p class="muted">${avail != null ? `Verfügbarkeit im Zeitraum: <strong>${avail} %</strong> · ` : ''}Auflösung ${esc(data.bucket_minutes)} Min.</p>
      ${latencyChart(data.points)}`;
    $('#dev-events').innerHTML = eventList(data.events);
  };

  const reload = async () => {
    data = await api(`/devices/${encodeURIComponent(id)}?hours=${hours}`);
    update();
  };

  $('#range').addEventListener('change', (ev) => { hours = Number(ev.target.value); reload(); });
  $('#dev-form')?.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    attempt(async () => {
      data.device = await api(`/devices/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: { name: f.get('name'), notes: f.get('notes'), monitored: f.get('monitored') === 'on' },
      });
      update();
    }, 'Gespeichert');
  });
  $('#dev-delete')?.addEventListener('click', () => {
    if (!confirm('Gerät mit allen Messwerten und Ereignissen löschen? Wird es beim nächsten Scan wieder gefunden, taucht es neu auf.')) return;
    attempt(async () => {
      await api(`/devices/${encodeURIComponent(id)}`, { method: 'DELETE' });
      location.hash = '#/devices';
    }, 'Gerät gelöscht');
  });
  update();
  autoRefresh(reload, 60);
}

async function viewEvents() {
  const render = async () => {
    const events = await api('/events?limit=300');
    view().innerHTML = `<div class="page-head"><h1>Ereignisse</h1></div>
      <div class="card table-wrap"><table>
        <thead><tr><th>Zeit</th><th>Art</th><th>Meldung</th></tr></thead>
        <tbody>${events.map((e) => `<tr>
          <td>${esc(fmtTime(e.time))}</td><td>${eventBadge(e.kind)}</td>
          <td>${e.device_id ? `<a href="#/device/${e.device_id}">${esc(e.message)}</a>` : esc(e.message)}</td></tr>`).join('')
          || '<tr><td colspan="3" class="muted">Keine Ereignisse.</td></tr>'}</tbody></table></div>`;
  };
  await render();
  autoRefresh(render);
}

async function viewNetworks() {
  const render = async () => {
    const [networks, summary] = await Promise.all([api('/networks'), api('/summary')]);
    view().innerHTML = `
      <div class="page-head"><h1>Netzwerke</h1>
        <div class="actions"><button id="scan-now" type="button">Jetzt scannen</button></div></div>
      ${lastDiscoveryLine(summary)}
      <div class="notice">Nur eigene oder ausdrücklich freigegebene Netze eintragen. Das Scannen fremder Netze
        kann strafbar sein (§§ 202a ff. StGB). Pro Eintrag höchstens /20 (4094 Adressen).</div>
      <div class="grid">
        <section class="card span-2"><header><h2>Freigegebene Netze</h2></header>
          <div class="table-wrap"><table><thead><tr><th>Netz</th><th>Name</th><th>Angelegt</th><th></th></tr></thead>
          <tbody>${networks.map((n) => `<tr><td class="mono">${esc(n.cidr)}</td><td>${esc(n.name)}</td>
            <td>${esc(fmtTime(n.created_at))}</td>
            <td><button class="ghost" data-del="${n.id}" data-cidr="${esc(n.cidr)}" type="button">Entfernen</button></td></tr>`).join('')
            || '<tr><td colspan="4" class="muted">Noch keine Netze – rechts eines hinzufügen.</td></tr>'}</tbody></table></div>
        </section>
        <section class="card span-1"><header><h2>Netz hinzufügen</h2></header>
          <form class="form" id="net-form">
            <label>Netz (CIDR)<input name="cidr" placeholder="192.168.178.0/24" required></label>
            <label>Name<input name="name" placeholder="Heimnetz" maxlength="100" required></label>
            <button type="submit">Hinzufügen &amp; scannen</button>
          </form></section>
      </div>`;

    $('#scan-now').addEventListener('click', () => attempt(() => api('/scan', { method: 'POST' }), 'Scan gestartet – Ergebnisse erscheinen in wenigen Minuten'));
    $('#net-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      attempt(async () => {
        await api('/networks', { method: 'POST', body: { cidr: f.get('cidr'), name: f.get('name') } });
        await render();
      }, 'Netz hinzugefügt, Scan läuft');
    });
    $$('[data-del]').forEach((btn) => btn.addEventListener('click', () => {
      if (!confirm(`Netz ${btn.dataset.cidr} entfernen? Bereits gefundene Geräte bleiben erhalten.`)) return;
      attempt(async () => { await api(`/networks/${btn.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Netz entfernt');
    }));
  };
  await render();
}

async function viewUsers() {
  const render = async () => {
    const users = await api('/users');
    view().innerHTML = `
      <div class="page-head"><h1>Benutzer</h1></div>
      <div class="grid">
        <section class="card span-2"><div class="table-wrap"><table>
          <thead><tr><th>Benutzer</th><th>Rolle</th><th>Angelegt</th><th>Letzte Anmeldung</th><th></th></tr></thead>
          <tbody>${users.map((u) => `<tr><td>${esc(u.username)}</td>
            <td>${u.role === 'admin' ? 'Administrator' : 'Nur lesen'}</td>
            <td>${esc(fmtTime(u.created_at))}</td><td>${esc(fmtTime(u.last_login))}</td>
            <td>${u.id === state.user.id ? '<span class="muted">(du)</span>' : `<button class="ghost" data-del="${u.id}" data-name="${esc(u.username)}" type="button">Löschen</button>`}</td></tr>`).join('')}
          </tbody></table></div></section>
        <section class="card span-1"><header><h2>Benutzer anlegen</h2></header>
          <form class="form" id="user-form">
            <label>Benutzername<input name="username" required minlength="3" maxlength="32" autocomplete="off"></label>
            <label>Passwort (mind. 12 Zeichen)<input name="password" type="password" required minlength="12" autocomplete="new-password"></label>
            <label>Rolle<select name="role"><option value="viewer">Nur lesen</option><option value="admin">Administrator</option></select></label>
            <button type="submit">Anlegen</button>
          </form></section>
      </div>`;
    $('#user-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      attempt(async () => {
        await api('/users', { method: 'POST', body: { username: f.get('username'), password: f.get('password'), role: f.get('role') } });
        await render();
      }, 'Benutzer angelegt');
    });
    $$('[data-del]').forEach((btn) => btn.addEventListener('click', () => {
      if (!confirm(`Benutzer „${btn.dataset.name}“ löschen?`)) return;
      attempt(async () => { await api(`/users/${btn.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Benutzer gelöscht');
    }));
  };
  await render();
}

const AUDIT_LABEL = {
  login: 'Anmeldung', login_failed: 'Fehlgeschlagene Anmeldung', password_change: 'Passwort geändert',
  device_update: 'Gerät geändert', device_delete: 'Gerät gelöscht', network_add: 'Netz hinzugefügt',
  network_delete: 'Netz entfernt', scan_trigger: 'Scan gestartet', user_add: 'Benutzer angelegt', user_delete: 'Benutzer gelöscht',
};

async function viewAudit() {
  const entries = await api('/audit?limit=500');
  view().innerHTML = `<div class="page-head"><h1>Audit-Log</h1></div>
    <div class="card table-wrap"><table>
      <thead><tr><th>Zeit</th><th>Benutzer</th><th>Aktion</th><th>Details</th></tr></thead>
      <tbody>${entries.map((e) => `<tr><td>${esc(fmtTime(e.time))}</td><td>${esc(e.username || '–')}</td>
        <td>${esc(AUDIT_LABEL[e.action] || e.action)}</td>
        <td class="mono">${Object.keys(e.detail || {}).length ? esc(JSON.stringify(e.detail)) : ''}</td></tr>`).join('')
        || '<tr><td colspan="4" class="muted">Keine Einträge.</td></tr>'}</tbody></table></div>`;
}

async function viewAccount() {
  view().innerHTML = `
    <div class="page-head"><h1>Mein Konto</h1></div>
    <div class="grid">
      <section class="card span-1"><header><h2>Angemeldet als</h2></header>
        <dl class="details"><dt>Benutzer</dt><dd>${esc(state.user.username)}</dd>
          <dt>Rolle</dt><dd>${state.user.role === 'admin' ? 'Administrator' : 'Nur lesen'}</dd></dl></section>
      <section class="card span-1"><header><h2>Passwort ändern</h2></header>
        <form class="form" id="pw-form">
          <label>Aktuelles Passwort<input name="old" type="password" required autocomplete="current-password"></label>
          <label>Neues Passwort (mind. 12 Zeichen)<input name="new" type="password" required minlength="12" autocomplete="new-password"></label>
          <label>Neues Passwort wiederholen<input name="repeat" type="password" required minlength="12" autocomplete="new-password"></label>
          <button type="submit">Passwort ändern</button>
          <p class="muted">Alle anderen Sitzungen werden dabei abgemeldet.</p>
        </form></section>
    </div>`;
  $('#pw-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    if (f.get('new') !== f.get('repeat')) { toast('Die neuen Passwörter stimmen nicht überein', true); return; }
    attempt(async () => {
      await api('/me/password', { method: 'POST', body: { old_password: f.get('old'), new_password: f.get('new') } });
      ev.target.reset();
    }, 'Passwort geändert');
  });
}

// ---------------------------------------------------------------------------
// Anmeldung & Navigation
// ---------------------------------------------------------------------------

function showLogin() {
  state.user = null;
  clearInterval(state.refreshTimer);
  $('#topbar').hidden = true;
  view().innerHTML = `
    <form class="card login" id="login-form">
      <h1>NetPulse</h1>
      <label>Benutzername<input name="username" autocomplete="username" required autofocus></label>
      <label>Passwort<input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit">Anmelden</button>
      <p class="error" id="login-error"></p>
    </form>`;
  $('#login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    try {
      state.user = await api('/login', { method: 'POST', body: { username: f.get('username'), password: f.get('password') } });
      startApp();
    } catch (e) {
      $('#login-error').textContent = e.message;
    }
  });
}

const ROUTES = {
  dashboard: viewDashboard,
  devices: viewDevices,
  device: viewDevice,
  events: viewEvents,
  networks: viewNetworks,
  users: viewUsers,
  audit: viewAudit,
  account: viewAccount,
};
const ADMIN_ROUTES = ['networks', 'users', 'audit'];

function autoRefresh(fn, seconds = 30) {
  clearInterval(state.refreshTimer);
  state.refreshTimer = setInterval(() => { fn().catch(() => {}); }, seconds * 1000);
}

async function route() {
  if (!state.user) return;
  clearInterval(state.refreshTimer);
  const [path, query] = location.hash.replace(/^#\/?/, '').split('?');
  const [name, arg] = path.split('/');
  const key = ROUTES[name] ? name : 'dashboard';
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.getAttribute('href') === `#/${key === 'device' ? 'devices' : key}`));
  if (ADMIN_ROUTES.includes(key) && state.user.role !== 'admin') {
    view().innerHTML = '<p class="error">Keine Berechtigung.</p>';
    return;
  }
  try {
    await ROUTES[key](arg, new URLSearchParams(query || ''));
  } catch (e) {
    if (state.user) view().innerHTML = `<p class="error">${esc(e.message)}</p>`;
  }
}

function startApp() {
  $('#topbar').hidden = false;
  document.body.classList.toggle('is-admin', state.user.role === 'admin');
  $('#user-name').textContent = state.user.username;
  if (!location.hash || location.hash === '#/') location.hash = '#/dashboard';
  else route();
}

window.addEventListener('hashchange', route);
$('#logout').addEventListener('click', async () => {
  try { await api('/logout', { method: 'POST' }); } catch { /* egal – lokal trotzdem abmelden */ }
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
