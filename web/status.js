'use strict';
/* Öffentliche Statusseite: zeigt nur die freigegebenen Einträge (Link: /status.html#<geheimer Schlüssel>) */

const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
const $ = (s) => document.querySelector(s);

const LABEL = { ok: 'Funktioniert', degraded: 'Eingeschränkt', down: 'Störung', unknown: 'Unbekannt' };
const OVERALL = { ok: 'Alle Systeme funktionieren', degraded: 'Einige Systeme sind eingeschränkt', down: 'Es liegt eine Störung vor' };

function days(list) {
  const cells = (list || []).map((v, i) => {
    const date = new Date(Date.now() - (29 - i) * 86400000).toLocaleDateString('de-DE');
    const cls = v == null ? '' : v >= 99.9 ? 'ok' : v >= 95 ? 'warn' : 'bad';
    return `<i class="${cls}" title="${esc(date)}: ${v == null ? 'keine Daten' : `${v} %`}"></i>`;
  });
  return `<div class="beats days">${cells.join('')}</div>`;
}

async function load() {
  const token = location.hash.slice(1);
  try {
    const res = await fetch(`/api/public/status/${encodeURIComponent(token)}`, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error('Diese Statusseite gibt es nicht (mehr).');
    const s = await res.json();
    document.title = s.title || 'Status';
    $('#st-title').textContent = s.title || 'Status';
    $('#st-desc').textContent = s.description || '';
    const overall = $('#st-overall');
    overall.className = `status-overall ${s.overall}`;
    overall.textContent = OVERALL[s.overall] || '';
    $('#st-items').innerHTML = s.items.length ? s.items.map((i) => `<div class="status-item">
        <div class="status-line"><span class="check-dot st-${i.status === 'ok' ? 'up' : i.status === 'degraded' ? 'warn' : i.status}"></span>
          <strong>${esc(i.name)}</strong><span class="status-label ${esc(i.status)}">${esc(LABEL[i.status] || '')}</span>
          <span class="muted small status-uptime">${i.uptime_30d != null ? `${esc(i.uptime_30d)} % (30 Tage)` : ''}</span></div>
        ${days(i.days)}</div>`).join('') : '<p class="muted">Keine Einträge.</p>';
    $('#st-updated').textContent = new Date(s.updated).toLocaleString('de-DE');
  } catch (e) {
    $('#st-overall').className = 'status-overall unknown';
    $('#st-overall').textContent = e.message;
    $('#st-items').innerHTML = '';
  }
}

load();
setInterval(load, 60000);
window.addEventListener('hashchange', load);
