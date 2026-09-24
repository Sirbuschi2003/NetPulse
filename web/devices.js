'use strict';
/* Geräteliste und Geräte-Detailseite */

function readPref(key, fallback) {
  try { return localStorage.getItem(key) || fallback; } catch { return fallback; }
}
function writePref(key, value) {
  try { localStorage.setItem(key, value); } catch { /* egal */ }
}

// ---------------------------------------------------------------------------
// Geräteliste
// ---------------------------------------------------------------------------

async function viewDevices(_arg, params) {
  let devices = await api('/devices');
  const filters = { q: (params.get('q') || '').toLowerCase(), status: params.get('status') || '', type: params.get('type') || '' };
  let mode = readPref('np-dev-view', 'cards');

  const typesPresent = [...new Set(devices.map((d) => d.device_type))].sort((a, b) => typeInfo(a).label.localeCompare(typeInfo(b).label));
  view().innerHTML = `
    <div class="page-head">
      <div class="actions">
        <input id="q" type="search" placeholder="Filtern: Name, IP, MAC, Hersteller, Port …" aria-label="Filtern">
        <select id="status-filter" aria-label="Status">
          <option value="">Alle Status</option><option value="up">Online</option><option value="down">Offline</option>
          <option value="unknown">Unbekannt</option><option value="unmonitored">Nicht überwacht</option><option value="new">Neu (24 h)</option>
        </select>
        <select id="type-filter" aria-label="Gerätetyp"><option value="">Alle Typen</option>
          ${typesPresent.map((t) => `<option value="${esc(t)}">${esc(typeInfo(t).label)}</option>`).join('')}</select>
      </div>
      <div class="actions"><span class="muted" id="count"></span>
        <div class="seg"><button type="button" data-mode="cards" title="Karten">${icon('layout-grid')}</button>
        <button type="button" data-mode="table" title="Tabelle">${icon('list')}</button></div></div>
    </div>
    <div id="dev-list"></div>`;
  $('#q').value = filters.q;
  $('#status-filter').value = filters.status;
  $('#type-filter').value = filters.type;

  const matches = (d) => {
    if (filters.type && d.device_type !== filters.type) return false;
    if (filters.status === 'unmonitored' && d.monitored) return false;
    if (filters.status === 'new' && Date.now() - new Date(d.first_seen).getTime() > 86400000) return false;
    if (['up', 'down', 'unknown'].includes(filters.status) && (!d.monitored || d.status !== filters.status)) return false;
    if (!filters.q) return true;
    const hay = [d.name, d.hostname, d.ip, d.mac, d.vendor, d.os, d.model, d.notes, typeInfo(d.device_type).label,
      ...(d.open_ports || []).map(portLabel)].join(' ').toLowerCase();
    return hay.includes(filters.q);
  };

  const card = (d) => `
    <a class="dev-card${d.monitored ? '' : ' off'}" href="#/device/${d.id}">
      <div class="top">${devIcon(d)}<div class="ellipsis"><div class="name">${esc(deviceLabel(d))}</div>
        <div class="sub mono">${esc(d.ip)}</div></div></div>
      <div class="sub">${esc([d.vendor, d.os || d.model].filter(Boolean).join(' · ') || typeInfo(d.device_type).label)}</div>
      <div class="meta">${statusBadge(d)}<span>${esc(fmtMs(d.last_rtt_ms))}</span>
        <span>${d.has_credentials ? icon('key', 'i-sm') : ''} ${(d.open_ports || []).length === 1 ? '1 Dienst' : `${(d.open_ports || []).length} Dienste`}</span></div>
    </a>`;

  const row = (d) => `
    <tr class="clickable${d.monitored ? '' : ' unmonitored'}" data-id="${d.id}">
      <td><div class="cell-dev">${devIcon(d, 'sm')}<div class="ellipsis"><div>${esc(deviceLabel(d))}</div>
        ${d.name && d.hostname ? `<div class="muted small">${esc(d.hostname)}</div>` : ''}</div></div></td>
      <td>${statusBadge(d)}</td>
      <td class="mono">${esc(d.ip)}</td>
      <td><div class="mono small">${esc(d.mac || '–')}</div><div class="muted small">${esc(d.vendor || '')}</div></td>
      <td class="small">${esc(d.os || typeInfo(d.device_type).label)}</td>
      <td>${portChips(d.open_ports)}</td>
      <td>${esc(fmtMs(d.last_rtt_ms))}</td>
      <td title="${esc(fmtTime(d.last_seen))}">${esc(fmtAgo(d.last_seen))}</td>
    </tr>`;

  const render = () => {
    const shown = devices.filter(matches);
    $$('.seg button').forEach((b) => b.classList.toggle('active', b.dataset.mode === mode));
    $('#count').textContent = `${shown.length} von ${devices.length} Geräten`;
    if (!shown.length) {
      $('#dev-list').innerHTML = `<div class="card">${empty(devices.length ? 'Keine Geräte passen zum Filter.' : 'Noch keine Geräte – unter „Netzwerke“ ein Netz freigeben.', 'devices')}</div>`;
    } else if (mode === 'cards') {
      $('#dev-list').innerHTML = `<div class="dev-grid">${shown.map(card).join('')}</div>`;
    } else {
      $('#dev-list').innerHTML = `<div class="card table-wrap"><table>
        <thead><tr><th>Gerät</th><th>Status</th><th>IP</th><th>MAC / Hersteller</th><th>System</th><th>Dienste</th><th>Antwort</th><th>Gesehen</th></tr></thead>
        <tbody>${shown.map(row).join('')}</tbody></table></div>`;
    }
  };

  $('#q').addEventListener('input', (ev) => { filters.q = ev.target.value.trim().toLowerCase(); render(); });
  $('#status-filter').addEventListener('change', (ev) => { filters.status = ev.target.value; render(); });
  $('#type-filter').addEventListener('change', (ev) => { filters.type = ev.target.value; render(); });
  $$('.seg button').forEach((b) => b.addEventListener('click', () => { mode = b.dataset.mode; writePref('np-dev-view', mode); render(); }));
  $('#dev-list').addEventListener('click', (ev) => {
    const tr = ev.target.closest('tr[data-id]');
    if (tr) location.hash = `#/device/${tr.dataset.id}`;
  });
  render();
  autoRefresh(async () => { devices = await api('/devices'); render(); });
}

// ---------------------------------------------------------------------------
// Geräte-Detailseite
// ---------------------------------------------------------------------------

async function viewDevice(id) {
  let hours = 24;
  let tab = 'overview';
  let data = await api(`/devices/${encodeURIComponent(id)}?hours=${hours}`);
  const credentials = isAdmin() ? await api('/credentials').catch(() => []) : [];

  const tabs = () => {
    const inv = data.inventory || {};
    const list = [['overview', 'Übersicht']];
    if (inv.ssh || inv.snmp) list.push(['system', 'System']);
    if ((inv.ssh && inv.ssh.interfaces && inv.ssh.interfaces.length) || (inv.snmp && inv.snmp.interfaces)) list.push(['interfaces', 'Schnittstellen']);
    if ((inv.ssh && inv.ssh.disks && inv.ssh.disks.length) || (inv.snmp && inv.snmp.storage && inv.snmp.storage.length)) list.push(['storage', 'Speicher']);
    list.push(['history', 'Verlauf']);
    list.push(['events', 'Ereignisse']);
    if (isAdmin()) list.push(['settings', 'Einstellungen']);
    return list;
  };

  const render = () => {
    const d = data.device;
    const t = typeInfo(d.device_type);
    view().innerHTML = `
      <div class="card">
        <div class="dev-hero">${devIcon(d, 'lg')}
          <div class="title"><h1>${esc(deviceLabel(d))} ${statusBadge(d)}</h1>
            <div class="badges"><span class="badge accent">${esc(t.label)}${d.device_type_manual ? ' (manuell)' : ''}</span>
              <span class="badge plain mono">${esc(d.ip)}</span>
              ${d.vendor ? `<span class="badge plain">${esc(d.vendor)}</span>` : ''}
              ${d.os ? `<span class="badge plain">${esc(d.os)}</span>` : ''}
              ${d.model ? `<span class="badge plain">${esc(d.model)}</span>` : ''}</div></div>
          <div class="actions"><a href="#/devices" class="btn ghost">${icon('chevron-left', 'i-sm')} Alle Geräte</a>
            ${isAdmin() ? `<button type="button" id="poll-now" class="ghost">${icon('refresh')}Jetzt abfragen</button>` : ''}</div>
        </div>
        <div class="tabs">${tabs().map(([k, label]) => `<button type="button" data-tab="${k}" class="${k === tab ? 'active' : ''}">${esc(label)}</button>`).join('')}</div>
        <div id="tab-body"></div>
      </div>`;
    $$('.tabs button').forEach((b) => b.addEventListener('click', () => { tab = b.dataset.tab; render(); }));
    $('#poll-now')?.addEventListener('click', () => attempt(async () => {
      await api(`/devices/${id}/poll`, { method: 'POST' });
      setTimeout(reload, 8000);
    }, 'Abfrage gestartet – Ergebnisse erscheinen in wenigen Sekunden'));
    const body = $('#tab-body');
    const renderers = { overview: tabOverview, system: tabSystem, interfaces: tabInterfaces, storage: tabStorage, history: tabHistory, events: tabEvents, settings: tabSettings };
    body.innerHTML = (renderers[tab] || tabOverview)();
    applyWidths(body);
    if (tab === 'settings') bindSettings();
    $('#range')?.addEventListener('change', (ev) => { hours = Number(ev.target.value); reload(); });
  };

  const reload = async () => {
    data = await api(`/devices/${encodeURIComponent(id)}?hours=${hours}`);
    if (tab !== 'settings') render();
  };

  // ----- Übersicht -----
  function tabOverview() {
    const d = data.device;
    const last = data.stats[data.stats.length - 1] || {};
    const avail = availability(data.points);
    const gauges = [['cpu', 'CPU', last.cpu_pct, '%'], ['gauge', 'RAM', last.mem_pct, '%'], ['database', 'Speicher', last.disk_pct, '%'], ['temperature', 'Temperatur', last.temp_c, '°C']]
      .filter((g) => g[2] != null);
    return `<div class="grid">
      <section class="span-1"><h3>Details</h3><dl class="details">
        <dt>IP-Adresse</dt><dd class="mono">${esc(d.ip)}</dd>
        <dt>MAC-Adresse</dt><dd class="mono">${esc(d.mac || '–')}</dd>
        <dt>Hersteller</dt><dd>${esc(d.vendor || '–')}</dd>
        <dt>Hostname</dt><dd>${esc(d.hostname || '–')}</dd>
        <dt>Antwortzeit</dt><dd>${esc(fmtMs(d.last_rtt_ms))}</dd>
        <dt>Status seit</dt><dd>${esc(fmtTime(d.status_since))}</dd>
        <dt>Erstmals gesehen</dt><dd>${esc(fmtTime(d.first_seen))}</dd>
        <dt>Zuletzt gesehen</dt><dd>${esc(fmtAgo(d.last_seen))}</dd>
        <dt>Dienste</dt><dd>${portChips(d.open_ports)}</dd>
        ${d.notes ? `<dt>Notizen</dt><dd>${esc(d.notes)}</dd>` : ''}
      </dl></section>
      <section class="span-2">
        ${gauges.length ? `<div class="gauges">${gauges.map(([ic, label, v, unit]) => `<div class="gauge"><div class="l">${icon(ic, 'i-sm')}${label}</div>
          <div class="v">${Math.round(v)} ${unit}</div>${unit === '%' ? meter(v) : meter(v, { warn: 70, crit: 85 })}</div>`).join('')}</div><br>` : ''}
        <h3>Antwortzeit ${avail != null ? `<span class="muted">· ${avail} % verfügbar (${hours} h)</span>` : ''}</h3>
        ${lineChart(data.points, { series: [{ key: 'rtt_ms', label: 'Antwortzeit' }], format: fmtMs, width: 760, outages: true })}
        ${inventoryStatus()}
      </section></div>`;
  }

  function inventoryStatus() {
    const d = data.device;
    if (d.inventory_error) {
      return `<div class="notice">${icon('alert-triangle')}<span>Tiefe Abfrage: ${esc(d.inventory_error)}</span></div>`;
    }
    if (d.inventory_at && data.inventory) {
      const via = [data.inventory.ssh && 'SSH', data.inventory.snmp && 'SNMP'].filter(Boolean).join(' + ');
      return `<p class="muted small">${icon('circle-check', 'i-sm')} Inventar per ${esc(via)} · ${esc(fmtAgo(d.inventory_at))}</p>`;
    }
    if (!d.has_credentials) {
      return `<div class="notice info">${icon('key')}<span>Für CPU, RAM, Festplatten, Schnittstellen & Co. unter
        ${isAdmin() ? '„Einstellungen“' : 'Einstellungen'} SNMP- oder SSH-Zugangsdaten zuordnen.</span></div>`;
    }
    return '';
  }

  // ----- System -----
  function tabSystem() {
    const ssh = (data.inventory || {}).ssh;
    const snmp = (data.inventory || {}).snmp;
    const rows = [];
    const add = (label, value) => { if (value != null && value !== '' && value !== false) rows.push(`<dt>${esc(label)}</dt><dd>${esc(value)}</dd>`); };
    if (ssh) {
      add('Betriebssystem', ssh.os);
      add('Version / Build', [ssh.version, ssh.build].filter(Boolean).join(' / '));
      add('Kernel', ssh.kernel);
      add('Architektur', ssh.arch);
      add('Laufzeit', ssh.uptime_s != null ? fmtDuration(ssh.uptime_s) : null);
      add('Hersteller', ssh.vendor);
      add('Modell / Board', ssh.model || ssh.board);
      add('Seriennummer', ssh.serial);
      add('BIOS', ssh.bios);
      add('Prozessor', ssh.cpu_model);
      add('Kerne', ssh.cpu_cores);
      add('Last (1/5/15 min)', ssh.load ? ssh.load.join(' / ') : null);
      add('Arbeitsspeicher', ssh.mem_total_kb ? fmtBytes(ssh.mem_total_kb * 1024) : null);
      add('Swap', ssh.swap_total_kb ? `${fmtBytes((ssh.swap_total_kb - (ssh.swap_free_kb || 0)) * 1024)} von ${fmtBytes(ssh.swap_total_kb * 1024)} belegt` : null);
      add('Domäne', ssh.domain);
      add('Letztes Windows-Update', ssh.last_hotfix);
      add('Gestoppte Autostart-Dienste', ssh.stopped_auto_services || null);
      add('Fehlgeschlagene Dienste (systemd)', ssh.failed_units || null);
      add('Laufende Container', ssh.containers);
      add('Neustart erforderlich', ssh.reboot_required ? 'ja' : null);
      add('Proxmox', ssh.proxmox);
      add('Synology-Modell', ssh.synology);
    }
    if (snmp) {
      add('Systembeschreibung (SNMP)', snmp.sys_descr);
      add('Systemname', snmp.sys_name);
      add('Standort', snmp.sys_location);
      add('Kontakt', snmp.sys_contact);
      if (!ssh) add('Laufzeit', snmp.uptime_s != null ? fmtDuration(snmp.uptime_s) : null);
      add('Modell', snmp.model);
      add('Seriennummer', snmp.serial);
      add('CPU-Last', snmp.cpu_pct != null ? `${Math.round(snmp.cpu_pct)} % (${snmp.cpu_cores} Kerne)` : null);
      add('LLDP-Nachbarn', snmp.lldp_neighbors ? snmp.lldp_neighbors.join(', ') : null);
    }
    let extra = '';
    if (snmp && snmp.printer && snmp.printer.length) {
      extra += `<section class="card"><header><h2>${icon('printer')}Verbrauchsmaterial</h2></header>
        ${snmp.printer.map((s) => `<div class="meter-row"><span class="ellipsis">${esc(s.descr || 'Material')}</span>
          ${s.pct != null ? `<div class="meter ${s.pct <= 10 ? 'crit' : s.pct <= 25 ? 'warn' : ''}"><span data-w="${s.pct}"></span></div>` : '<span class="muted small">Füllstand unbekannt</span>'}
          <span class="small">${s.pct != null ? `${s.pct} %` : ''}</span></div>`).join('')}</section>`;
    }
    if (snmp && snmp.ups) {
      const u = snmp.ups;
      extra += `<section class="card"><header><h2>${icon('battery-charging')}USV</h2></header><dl class="details">
        <dt>Modell</dt><dd>${esc([u.manufacturer, u.model].filter(Boolean).join(' ') || '–')}</dd>
        <dt>Ladung</dt><dd>${esc(fmtPct(u.charge_pct))}</dd>
        <dt>Restlaufzeit</dt><dd>${u.runtime_min != null ? `${esc(u.runtime_min)} Min.` : '–'}</dd>
        <dt>Akku</dt><dd>${esc(u.battery_status)}</dd>
        <dt>Stromversorgung</dt><dd>${u.on_battery ? '<span class="badge sev-critical">Akkubetrieb</span>' : '<span class="badge st-up">Netzbetrieb</span>'}</dd></dl></section>`;
    }
    if (snmp && snmp.synology) {
      const s = snmp.synology;
      extra += `<section class="card"><header><h2>${icon('database')}Synology</h2></header><dl class="details">
        <dt>Modell</dt><dd>${esc(s.model)}</dd><dt>DSM</dt><dd>${esc(s.version || '–')}</dd>
        <dt>Seriennummer</dt><dd>${esc(s.serial || '–')}</dd><dt>Temperatur</dt><dd>${s.temp_c != null ? `${esc(s.temp_c)} °C` : '–'}</dd>
        <dt>Systemstatus</dt><dd>${s.status_ok ? '<span class="badge st-up">normal</span>' : '<span class="badge sev-critical">Fehler</span>'}</dd></dl></section>`;
    }
    return `<div class="grid"><section class="span-2"><dl class="details">${rows.join('') || '<dd>Keine Angaben</dd>'}</dl></section>
      <div class="stack-v span-1">${extra}</div></div>`;
  }

  // ----- Schnittstellen -----
  function tabInterfaces() {
    const inv = data.inventory || {};
    const list = (inv.snmp && inv.snmp.interfaces) || (inv.ssh && inv.ssh.interfaces) || [];
    const ips = (inv.ssh && inv.ssh.ips) || [];
    const nics = (inv.ssh && inv.ssh.nics) || [];
    const rows = list.filter((i) => i.type !== 24).map((i) => `<tr>
      <td><div>${esc(i.name || i.descr)}</div>${i.alias ? `<div class="muted small">${esc(i.alias)}</div>` : ''}</td>
      <td>${i.oper === 'up' ? '<span class="badge st-up">verbunden</span>' : `<span class="badge plain">${esc(i.oper || '–')}</span>`}</td>
      <td>${i.speed_mbps ? (i.speed_mbps >= 1000 ? `${i.speed_mbps / 1000} Gbit/s` : `${Math.round(i.speed_mbps)} Mbit/s`) : '–'}</td>
      <td class="mono small">${esc(i.mac || '–')}</td>
      <td>${esc(fmtBytes(i.rx_bytes))}</td><td>${esc(fmtBytes(i.tx_bytes))}</td></tr>`).join('');
    const ipRows = ips.map((a) => `<li><span class="mono">${esc(a.addr)}</span><span class="meta">${esc(a.iface)}</span></li>`)
      .concat(nics.map((n) => `<li><span><div>${esc(n.name)}</div><div class="mono small muted">${esc((n.ips || []).join(', '))}</div></span><span class="meta mono">${esc(n.mac || '')}</span></li>`));
    return `${rows ? `<div class="table-wrap"><table><thead><tr><th>Schnittstelle</th><th>Status</th><th>Geschwindigkeit</th><th>MAC</th><th>Empfangen</th><th>Gesendet</th></tr></thead>
      <tbody>${rows}</tbody></table></div>` : ''}
      ${ipRows.length ? `<br><h3>Adressen</h3><ul class="list">${ipRows.join('')}</ul>` : ''}`;
  }

  // ----- Speicher -----
  function tabStorage() {
    const inv = data.inventory || {};
    let items = [];
    if (inv.ssh && inv.ssh.disks) items = inv.ssh.disks.map((d) => ({ name: d.mount, sub: [d.device, d.type].filter(Boolean).join(' · '), size: d.size_bytes, used: d.used_bytes, pct: d.pct }));
    else if (inv.snmp && inv.snmp.storage) items = inv.snmp.storage.filter((s) => s.kind === 'disk' || s.kind === 'ram').map((s) => ({ name: s.descr, sub: s.kind === 'ram' ? 'Arbeitsspeicher' : 'Datenträger', size: s.size_bytes, used: s.used_bytes, pct: s.pct }));
    if (!items.length) return empty('Keine Speicherangaben', 'database');
    return items.map((s) => `<div class="meter-row"><span class="ellipsis"><div>${esc(s.name)}</div><div class="muted small">${esc(s.sub)}</div></span>
      ${meter(s.pct)}<span class="small">${esc(fmtBytes(s.used))} / ${esc(fmtBytes(s.size))} · <b>${Math.round(s.pct)} %</b></span></div>`).join('');
  }

  // ----- Verlauf -----
  function tabHistory() {
    const s = data.stats;
    const has = (k) => s.some((p) => p[k] != null);
    const range = `<select id="range" aria-label="Zeitraum">${[[24, '24 Stunden'], [168, '7 Tage'], [720, '30 Tage'], [2160, '90 Tage']]
      .map(([h, l]) => `<option value="${h}"${h === hours ? ' selected' : ''}>${l}</option>`).join('')}</select>`;
    const pctSeries = [['cpu_pct', 'CPU'], ['mem_pct', 'RAM'], ['disk_pct', 'Speicher']].filter(([k]) => has(k)).map(([key, label]) => ({ key, label }));
    return `<div class="page-head"><h3>Messwerte</h3>${range}</div>
      <div class="grid">
        <section class="card span-3"><header><h2>${icon('clock')}Antwortzeit &amp; Ausfälle</h2></header>
          ${lineChart(data.points, { series: [{ key: 'rtt_ms', label: 'Antwortzeit' }], format: fmtMs, width: 1100, height: 200, outages: true })}</section>
        ${pctSeries.length ? `<section class="card span-3"><header><h2>${icon('gauge')}Auslastung</h2></header>
          ${lineChart(s, { series: pctSeries, format: (v) => `${Math.round(v)} %`, maxValue: 100, width: 1100, height: 200 })}</section>` : ''}
        ${has('rx_bps') ? `<section class="card span-2"><header><h2>${icon('arrows-exchange')}Datenverkehr</h2></header>
          ${lineChart(s, { series: [{ key: 'rx_bps', label: 'Empfangen' }, { key: 'tx_bps', label: 'Gesendet' }], format: fmtBps, width: 720 })}</section>` : ''}
        ${has('temp_c') ? `<section class="card span-1"><header><h2>${icon('temperature')}Temperatur</h2></header>
          ${lineChart(s, { series: [{ key: 'temp_c', label: 'Temperatur' }], format: (v) => `${Math.round(v)} °C`, width: 360 })}</section>` : ''}
      </div>
      ${!s.length ? `<p class="muted small">CPU-, RAM- und Netzwerkverläufe erscheinen, sobald das Gerät per SNMP oder SSH abgefragt wird.</p>` : ''}`;
  }

  const tabEvents = () => eventList(data.events);

  // ----- Einstellungen -----
  function tabSettings() {
    const d = data.device;
    const assigned = new Set(data.credential_ids);
    const kindLabel = { snmp_v2c: 'SNMP v2c', snmp_v3: 'SNMP v3', ssh_password: 'SSH (Passwort)', ssh_key: 'SSH (Schlüssel)' };
    return `<div class="grid">
      <section class="span-1"><h3>Allgemein</h3><form class="form" id="dev-form">
        <label>Anzeigename<input name="name" maxlength="200" value="${esc(d.name || '')}" placeholder="${esc(d.hostname || d.ip)}"></label>
        <label>Gerätetyp<select name="device_type">
          <option value="auto">Automatisch erkennen${d.device_type_manual ? '' : ` (${esc(typeInfo(d.device_type).label)})`}</option>
          ${Object.entries(TYPES).map(([k, t]) => `<option value="${k}"${d.device_type_manual && d.device_type === k ? ' selected' : ''}>${esc(t.label)}</option>`).join('')}
        </select></label>
        <label>Notizen<textarea name="notes" maxlength="5000">${esc(d.notes || '')}</textarea></label>
        <label class="inline"><input type="checkbox" name="monitored"${d.monitored ? ' checked' : ''}> Erreichbarkeit überwachen</label>
        <div class="actions"><button type="submit">${icon('check')}Speichern</button></div>
      </form></section>
      <section class="span-1"><h3>Zugangsdaten für tiefe Abfragen</h3>
        ${credentials.length ? `<form class="form" id="cred-form"><div class="stack-v">
          ${credentials.map((c) => `<label class="inline"><input type="checkbox" name="cred" value="${c.id}"${assigned.has(c.id) ? ' checked' : ''}>
            <span>${esc(c.name)} <span class="muted small">· ${esc(kindLabel[c.kind] || c.kind)}${c.username ? ` · ${esc(c.username)}` : ''}</span></span></label>`).join('')}
          </div><div class="actions"><button type="submit">${icon('key')}Zuordnen &amp; abfragen</button></div></form>`
          : `<p class="muted">Noch keine Zugangsdaten angelegt. <a href="#/credentials">Jetzt anlegen</a></p>`}
        ${inventoryStatus()}
        ${data.ssh_host_key ? `<h3>SSH-Host-Schlüssel</h3><p class="mono small">${esc(data.ssh_host_key)}</p>
          <button type="button" class="ghost sm" id="reset-key">${icon('refresh', 'i-sm')}Schlüssel vergessen</button>
          <p class="hint">Nur nach einer Neuinstallation des Geräts nötig.</p>` : ''}
      </section>
      <section class="span-1"><h3>Gerät entfernen</h3>
        <p class="muted small">Löscht das Gerät mit allen Messwerten und Ereignissen. Wird es beim nächsten Scan wieder gefunden, taucht es neu auf.</p>
        <button type="button" class="danger" id="dev-delete">${icon('trash')}Gerät löschen</button></section>
    </div>`;
  }

  function bindSettings() {
    $('#dev-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      attempt(async () => {
        data.device = await api(`/devices/${id}`, {
          method: 'PATCH',
          body: { name: f.get('name'), notes: f.get('notes'), monitored: f.get('monitored') === 'on', device_type: f.get('device_type') },
        });
        render();
      }, 'Gespeichert');
    });
    $('#cred-form')?.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const ids = $$('input[name="cred"]:checked', ev.target).map((i) => Number(i.value));
      attempt(async () => {
        await api(`/devices/${id}/credentials`, { method: 'PUT', body: { ids } });
        data.credential_ids = ids;
        setTimeout(async () => { data = await api(`/devices/${id}?hours=${hours}`); render(); }, 10000);
      }, 'Zugeordnet – das Gerät wird jetzt abgefragt');
    });
    $('#reset-key')?.addEventListener('click', () => {
      if (!confirm('Gespeicherten SSH-Host-Schlüssel vergessen? Beim nächsten Kontakt wird der dann gesendete Schlüssel übernommen.')) return;
      attempt(async () => { await api(`/devices/${id}/ssh-key`, { method: 'DELETE' }); await reload(); render(); }, 'Schlüssel zurückgesetzt');
    });
    $('#dev-delete').addEventListener('click', () => {
      if (!confirm('Gerät mit allen Messwerten und Ereignissen löschen?')) return;
      attempt(async () => { await api(`/devices/${id}`, { method: 'DELETE' }); location.hash = '#/devices'; }, 'Gerät gelöscht');
    });
  }

  render();
  autoRefresh(reload, 60);
}
