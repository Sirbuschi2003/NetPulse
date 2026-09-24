'use strict';
/* Alarme, Ereignisse, Netzwerke, Zugangsdaten, Benachrichtigungen, Benutzer, Audit-Log, Konto */

// ---------------------------------------------------------------------------
// Alarme & Regeln
// ---------------------------------------------------------------------------

const RULE_KINDS = {
  device_down: { label: 'Gerät offline', icon: 'circle-x', unit: null, hint: 'Alarm, wenn ein Gerät länger als die angegebene Zeit nicht erreichbar ist.' },
  new_device: { label: 'Neues Gerät im Netz', icon: 'radar', unit: null, hint: 'Meldet jedes neu entdeckte Gerät – praktisch, um Fremdgeräte zu bemerken.' },
  mac_changed: { label: 'Sicherheitshinweis (MAC/SSH-Schlüssel geändert)', icon: 'shield-lock', unit: null, hint: 'Geänderte MAC-Adressen oder SSH-Host-Schlüssel können auf einen Angriff hindeuten.' },
  disk_usage: { label: 'Speicher fast voll', icon: 'database', unit: '%', hint: 'Höchste Belegung eines Datenträgers (SNMP/SSH nötig).' },
  cpu_usage: { label: 'CPU-Auslastung hoch', icon: 'cpu', unit: '%', hint: 'Durchschnittliche CPU-Last (SNMP/SSH nötig).' },
  mem_usage: { label: 'RAM-Auslastung hoch', icon: 'gauge', unit: '%', hint: 'Belegter Arbeitsspeicher (SNMP/SSH nötig).' },
  temperature: { label: 'Temperatur hoch', icon: 'temperature', unit: '°C', hint: 'Höchste gemeldete Temperatur (SSH/Synology-SNMP).' },
};

async function viewAlerts(_arg, params) {
  let tab = params.get('tab') || 'open';
  const render = async () => {
    const tabs = [['open', 'Aktiv'], ['history', 'Verlauf']];
    if (isAdmin()) tabs.push(['rules', 'Regeln']);
    let body = '';
    if (tab === 'rules') body = await renderRules();
    else {
      const alerts = await api(`/alerts?${tab === 'open' ? 'open=true&' : ''}limit=300`);
      body = alerts.length ? `<div class="table-wrap"><table>
        <thead><tr><th>Status</th><th>Meldung</th><th>Regel</th><th>Ausgelöst</th><th>Behoben</th></tr></thead>
        <tbody>${alerts.map((a) => `<tr>
          <td>${a.resolved_at ? '<span class="badge sev-resolved">behoben</span>' : '<span class="badge sev-critical">aktiv</span>'}</td>
          <td>${a.device_id ? `<a href="#/device/${a.device_id}">${esc(a.message)}</a>` : esc(a.message)}</td>
          <td class="small">${esc(a.rule_name)}</td>
          <td class="small" title="${esc(fmtTime(a.opened_at))}">${esc(fmtAgo(a.opened_at))}</td>
          <td class="small">${a.resolved_at ? esc(fmtTime(a.resolved_at)) : '–'}</td></tr>`).join('')}</tbody></table></div>`
        : empty(tab === 'open' ? 'Keine aktiven Alarme – alles im grünen Bereich.' : 'Noch keine Alarme ausgelöst.');
    }
    view().innerHTML = `<div class="card">
      <div class="tabs">${tabs.map(([k, l]) => `<button type="button" data-tab="${k}" class="${k === tab ? 'active' : ''}">${esc(l)}</button>`).join('')}</div>
      ${body}</div>`;
    $$('.tabs button').forEach((b) => b.addEventListener('click', () => { tab = b.dataset.tab; render(); }));
    if (tab === 'rules') bindRules();
  };

  async function renderRules() {
    const [rules, channels] = await Promise.all([api('/alert-rules'), api('/channels')]);
    state.rulesCache = { rules, channels };
    const chName = (id) => (channels.find((c) => c.id === id) || {}).name || '?';
    const condition = (r) => {
      const k = RULE_KINDS[r.kind] || {};
      if (r.kind === 'device_down') return `länger als ${r.duration_min} Min.`;
      if (k.unit) return `über ${r.threshold} ${k.unit}${r.duration_min ? ` für ${r.duration_min} Min.` : ''}`;
      return 'sofort';
    };
    return `<div class="page-head"><p class="muted">Regeln bestimmen, wann du benachrichtigt wirst.
      ${channels.length ? '' : ' <b>Lege zuerst unter „Benachrichtigungen“ einen Kanal an.</b>'}</p>
      <button type="button" id="rule-add">${icon('plus')}Regel anlegen</button></div>
      ${rules.length ? `<div class="table-wrap"><table><thead><tr><th>Regel</th><th>Typ</th><th>Gerät</th><th>Bedingung</th><th>Kanäle</th><th>Aktiv</th><th></th></tr></thead>
      <tbody>${rules.map((r) => `<tr>
        <td>${esc(r.name)}</td>
        <td><span class="cell-dev">${icon((RULE_KINDS[r.kind] || {}).icon || 'bell', 'i-sm')}${esc((RULE_KINDS[r.kind] || {}).label || r.kind)}</span></td>
        <td class="small">${esc(r.device_label || 'Alle Geräte')}</td>
        <td class="small">${esc(condition(r))}</td>
        <td class="small">${r.channel_ids.length ? r.channel_ids.map((c) => `<span class="chip">${esc(chName(c))}</span>`).join('') : '<span class="error">keiner</span>'}</td>
        <td><input type="checkbox" data-toggle="${r.id}"${r.enabled ? ' checked' : ''} aria-label="Aktiv"></td>
        <td class="actions"><button type="button" class="ghost sm" data-edit="${r.id}">${icon('edit', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-del="${r.id}">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Regeln. Tipp: „Gerät offline“ für wichtige Geräte wie Router, NAS und Server.', 'bell')}`;
  }

  function ruleToBody(r) {
    return { name: r.name, kind: r.kind, device_id: r.device_id, threshold: r.threshold, duration_min: r.duration_min,
      channel_ids: r.channel_ids, notify_recovery: r.notify_recovery, enabled: r.enabled };
  }

  function bindRules() {
    const { rules } = state.rulesCache;
    $('#rule-add').addEventListener('click', () => ruleDialog(null));
    $$('[data-edit]').forEach((b) => b.addEventListener('click', () => ruleDialog(rules.find((r) => r.id === Number(b.dataset.edit)))));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      if (!confirm('Regel löschen?')) return;
      attempt(async () => { await api(`/alert-rules/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Regel gelöscht');
    }));
    $$('[data-toggle]').forEach((c) => c.addEventListener('change', () => {
      const r = rules.find((x) => x.id === Number(c.dataset.toggle));
      attempt(async () => { await api(`/alert-rules/${r.id}`, { method: 'PATCH', body: { ...ruleToBody(r), enabled: c.checked } }); });
    }));
  }

  async function ruleDialog(rule) {
    const { channels } = state.rulesCache;
    const devices = await api('/devices');
    const r = rule || { kind: 'device_down', duration_min: 5, channel_ids: channels.map((c) => c.id), notify_recovery: true, enabled: true };
    const dlg = openModal(rule ? 'Regel bearbeiten' : 'Regel anlegen', `<form class="form" id="rule-form">
      <label>Art der Regel<select name="kind"${rule ? ' disabled' : ''}>${Object.entries(RULE_KINDS).map(([k, v]) => `<option value="${k}"${k === r.kind ? ' selected' : ''}>${esc(v.label)}</option>`).join('')}</select></label>
      <p class="hint" id="kind-hint"></p>
      <label>Name<input name="name" value="${esc(r.name || '')}" placeholder="z. B. NAS offline"></label>
      <label>Gerät<select name="device_id"><option value="">Alle Geräte</option>
        ${devices.map((d) => `<option value="${d.id}"${d.id === r.device_id ? ' selected' : ''}>${esc(deviceLabel(d))} – ${esc(d.ip)}</option>`).join('')}</select></label>
      <div class="form-row">
        <label id="f-threshold"><span>Schwellwert <span id="unit"></span></span><input name="threshold" type="number" step="any" value="${r.threshold ?? ''}"></label>
        <label id="f-duration">Dauer in Minuten<input name="duration_min" type="number" min="0" max="10080" value="${r.duration_min ?? 0}"></label>
      </div>
      <fieldset><legend>Benachrichtigen über</legend><div class="checks">
        ${channels.length ? channels.map((c) => `<label class="inline"><input type="checkbox" name="ch" value="${c.id}"${r.channel_ids.includes(c.id) ? ' checked' : ''}>${esc(c.name)}</label>`).join('')
          : '<span class="muted">Noch keine Kanäle – unter „Benachrichtigungen“ anlegen.</span>'}</div></fieldset>
      <label class="inline" id="f-recovery"><input type="checkbox" name="notify_recovery"${r.notify_recovery ? ' checked' : ''}> Entwarnung senden, wenn behoben</label>
      <label class="inline"><input type="checkbox" name="enabled"${r.enabled ? ' checked' : ''}> Regel aktiv</label>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    const form = $('#rule-form', dlg);
    const update = () => {
      const k = form.kind.value;
      const def = RULE_KINDS[k];
      $('#kind-hint', dlg).textContent = def.hint;
      $('#f-threshold', dlg).hidden = !def.unit;
      $('#unit', dlg).textContent = def.unit ? `(${def.unit})` : '';
      $('#f-duration', dlg).hidden = !(k === 'device_down' || def.unit);
      $('#f-recovery', dlg).hidden = !(k === 'device_down' || def.unit);
      if (!rule && def.unit && !form.threshold.value) form.threshold.value = k === 'temperature' ? 70 : 90;
    };
    form.kind.addEventListener('change', update);
    update();
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const body = {
        name: form.elements.name.value.trim() || RULE_KINDS[form.kind.value].label,
        kind: form.kind.value,
        device_id: form.device_id.value ? Number(form.device_id.value) : null,
        threshold: form.threshold.value === '' ? null : Number(form.threshold.value),
        duration_min: Number(form.duration_min.value || 0),
        channel_ids: $$('input[name="ch"]:checked', form).map((c) => Number(c.value)),
        notify_recovery: form.notify_recovery.checked,
        enabled: form.enabled.checked,
      };
      attempt(async () => {
        if (rule) await api(`/alert-rules/${rule.id}`, { method: 'PATCH', body });
        else await api('/alert-rules', { method: 'POST', body });
        dlg.close();
        await render();
      }, 'Regel gespeichert');
    });
  }

  await render();
  autoRefresh(async () => { if (tab !== 'rules' && !$('#modal').open) await render(); });
}

// ---------------------------------------------------------------------------
// Ereignisse
// ---------------------------------------------------------------------------

async function viewEvents() {
  const render = async () => {
    const events = await api('/events?limit=300');
    view().innerHTML = `<div class="card table-wrap">${events.length ? `<table>
        <thead><tr><th>Zeit</th><th>Art</th><th>Meldung</th></tr></thead>
        <tbody>${events.map((e) => `<tr>
          <td class="small">${esc(fmtTime(e.time))}</td><td>${eventBadge(e.kind)}</td>
          <td>${e.device_id ? `<a href="#/device/${e.device_id}">${esc(e.message)}</a>` : esc(e.message)}</td></tr>`).join('')}</tbody></table>`
      : empty('Noch keine Ereignisse.', 'list-details')}</div>`;
  };
  await render();
  autoRefresh(render);
}

// ---------------------------------------------------------------------------
// Netzwerke
// ---------------------------------------------------------------------------

async function viewNetworks() {
  // Nur die Netzliste wird laufend aktualisiert – die Formulare darunter bleiben beim Tippen unberührt
  view().innerHTML = '<div id="net-area"></div><div class="grid" id="sched-area"></div>';
  const render = async () => {
    const [networks, scan] = await Promise.all([api('/networks'), api('/scan/status')]);
    $('#net-area').innerHTML = `
      <div class="notice">${icon('shield-lock')}<span>Nur eigene oder ausdrücklich freigegebene Netze eintragen – das Scannen fremder
        Netze kann strafbar sein (§§ 202a ff. StGB). Pro Eintrag höchstens /16; kleinere Netze (z. B. /24) sind deutlich schneller.</span></div>
      ${scanBanner(scan)}
      <div class="grid">
        <section class="card span-2"><header><h2>${icon('topology-star-3')}Freigegebene Netze</h2>
          <button type="button" class="ghost sm" id="scan-all">${icon('radar', 'i-sm')}Alle scannen</button></header>
          ${networks.length ? `<div class="table-wrap"><table><thead><tr><th>Netz</th><th>Geräte</th><th>Letzter Scan</th><th></th></tr></thead>
          <tbody>${networks.map((n) => {
            const running = scan.running && scan.network === n.cidr;
            return `<tr><td><div class="mono">${esc(n.cidr)}</div><div class="muted small">${esc(n.name)}</div></td>
            <td>${n.device_count}</td>
            <td class="small">${running ? `<span class="badge accent">läuft · ${pct(scan.done, scan.total)} %</span>`
              : n.last_scan_at ? `${esc(fmtAgo(n.last_scan_at))} · ${n.last_scan_found} aktiv · ${n.last_scan_duration_s} s` : '<span class="muted">noch nicht</span>'}</td>
            <td class="actions"><button class="ghost sm" data-scan="${n.id}" type="button" title="Jetzt scannen">${icon('refresh', 'i-sm')}</button>
              <button class="ghost sm" data-del="${n.id}" data-cidr="${esc(n.cidr)}" type="button" title="Entfernen">${icon('trash', 'i-sm')}</button></td></tr>`;
          }).join('')}</tbody></table></div>` : empty('Noch keine Netze – rechts eines hinzufügen.', 'topology-star-3')}
        </section>
        <section class="card span-1"><header><h2>${icon('plus')}Netz hinzufügen</h2></header>
          <form class="form" id="net-form">
            <label>Netz (CIDR)<input name="cidr" placeholder="192.168.178.0/24" required></label>
            <label>Name<input name="name" placeholder="Heimnetz" maxlength="100" required></label>
            <button type="submit">${icon('radar')}Hinzufügen &amp; sofort scannen</button>
            <p class="hint">Ein neues Netz wird sofort gescannt – auch wenn gerade ein anderer Scan läuft.</p>
          </form></section>
      </div>`;
    applyWidths(view());
    $('#scan-all').addEventListener('click', () => attempt(() => api('/scan', { method: 'POST' }), 'Scan aller Netze gestartet'));
    $('#net-form').addEventListener('submit', (ev) => {
      ev.preventDefault();
      const f = new FormData(ev.target);
      attempt(async () => {
        await api('/networks', { method: 'POST', body: { cidr: f.get('cidr'), name: f.get('name') } });
        setTimeout(render, 1500);
      }, 'Netz hinzugefügt – Scan startet');
    });
    $$('[data-scan]').forEach((b) => b.addEventListener('click', () => attempt(async () => {
      await api(`/networks/${b.dataset.scan}/scan`, { method: 'POST' });
      setTimeout(render, 1500);
    }, 'Scan gestartet')));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      if (!confirm(`Netz ${b.dataset.cidr} entfernen? Bereits gefundene Geräte bleiben erhalten.`)) return;
      attempt(async () => { await api(`/networks/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Netz entfernt');
    }));
  };
  await render();
  await renderSchedule();
  autoRefresh(render, 5);
}

const SCHEDULE_MODES = {
  daily: 'Täglich zu festen Uhrzeiten',
  interval: 'Regelmäßig im festen Abstand',
  manual: 'Nur manuell („Alle scannen“ bzw. neues Netz)',
};

/** Zeitplan der Geräte-Suche und Takt der Echtzeit-Abfrage */
async function renderSchedule() {
  const [disc, liveCfg] = await Promise.all([api('/settings/discovery'), api('/settings/live')]);
  const sch = disc.schedule;
  const nextLine = (d) => {
    const parts = [];
    parts.push(d.next_run ? `Nächste Suche: <b>${esc(fmtTime(d.next_run))}</b>` : 'Keine automatische Suche geplant');
    parts.push(d.last_run ? `letzte vollständige Suche ${esc(fmtAgo(d.last_run))}` : 'noch keine vollständige Suche');
    return `${parts.join(' · ')} <span class="muted">(Zeitzone ${esc(d.timezone)})</span>`;
  };
  $('#sched-area').innerHTML = `
    <section class="card span-2"><header><h2>${icon('calendar-time')}Zeitplan für die Geräte-Suche</h2></header>
      <form class="form" id="sched-form">
        <label>Automatisch nach neuen Geräten suchen<select name="mode">
          ${Object.entries(SCHEDULE_MODES).map(([k, label]) => `<option value="${k}"${k === sch.mode ? ' selected' : ''}>${esc(label)}</option>`).join('')}</select></label>
        <label data-mode="daily">Uhrzeiten (mehrere mit Komma trennen)<input name="times" value="${esc(sch.times.join(', '))}" placeholder="03:00, 13:30"></label>
        <label data-mode="interval">Abstand in Minuten (5 bis 10080)<input name="interval_min" type="number" min="5" max="10080" value="${sch.interval_min}"></label>
        <label class="inline"><input type="checkbox" name="on_start"${sch.on_start ? ' checked' : ''}> Zusätzlich bei jedem Start des Containers suchen</label>
        <p class="hint" id="sched-next">${nextLine(disc)}</p>
        <p class="hint">Die Suche (Ping-Sweep, Ports, Namen) belastet das Netz kurz. Die Überwachung bekannter Geräte läuft davon unabhängig ständig weiter.
          Ein verpasster Termin (Gerät war aus) wird beim nächsten Start einmal nachgeholt.</p>
        <div class="actions"><button type="submit">${icon('check')}Zeitplan speichern</button></div>
      </form></section>
    <section class="card span-1"><header><h2>${icon('bolt')}Echtzeit-Abfrage</h2></header>
      <form class="form" id="live-form">
        <label class="inline"><input type="checkbox" name="enabled"${liveCfg.enabled ? ' checked' : ''}> Shelly-Geräte live abfragen</label>
        <label>Takt in Sekunden (2 bis 300)<input name="interval_s" type="number" min="2" max="300" value="${liveCfg.interval_s}"></label>
        <p class="hint">Pro Gerät eine kleine Anfrage; die Werte gehen sofort an alle offenen Browser.
          In die Datenbank wird höchstens ein Messwert pro Minute geschrieben.</p>
        <div class="actions"><button type="submit">${icon('check')}Speichern</button></div>
      </form></section>`;
  const form = $('#sched-form');
  const syncMode = () => $$('[data-mode]', form).forEach((el) => { el.hidden = el.dataset.mode !== form.elements.mode.value; });
  form.elements.mode.addEventListener('change', syncMode);
  syncMode();
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = form.elements;
    attempt(async () => {
      const result = await api('/settings/discovery', {
        method: 'PUT',
        body: {
          mode: e.mode.value,
          interval_min: Number(e.interval_min.value) || 60,
          times: e.times.value.split(/[,;\s]+/).filter(Boolean),
          on_start: e.on_start.checked,
        },
      });
      $('#sched-next').innerHTML = nextLine(result);
      e.times.value = result.schedule.times.join(', ');
    }, 'Zeitplan gespeichert');
  });
  const liveForm = $('#live-form');
  liveForm.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const e = liveForm.elements;
    attempt(() => api('/settings/live', { method: 'PUT', body: { enabled: e.enabled.checked, interval_s: Number(e.interval_s.value) || 5 } }),
      'Echtzeit-Abfrage gespeichert');
  });
}

// ---------------------------------------------------------------------------
// Zugangsdaten
// ---------------------------------------------------------------------------

const CRED_KINDS = {
  snmp_v2c: { label: 'SNMP v2c', icon: 'network', port: 161 },
  snmp_v3: { label: 'SNMP v3 (empfohlen)', icon: 'shield-lock', port: 161 },
  ssh_key: { label: 'SSH mit Schlüssel (empfohlen)', icon: 'key', port: 22 },
  ssh_password: { label: 'SSH mit Passwort', icon: 'lock', port: 22 },
  http: { label: 'HTTP / Web-Anmeldung (z. B. Shelly)', icon: 'bolt', port: 80 },
  unifi: { label: 'UniFi-Controller (API-Schlüssel)', icon: 'access-point', port: '11443 / 443 / 8443' },
};

async function viewCredentials() {
  const render = async () => {
    const creds = await api('/credentials');
    view().innerHTML = `
      <div class="notice info">${icon('shield-lock')}<span>Zugangsdaten werden mit AES-256 verschlüsselt gespeichert und nie wieder angezeigt.
        Verwende auf den Geräten <b>eigene Konten mit reinen Leserechten</b> – NetPulse führt nur lesende Abfragen aus.
        Anleitungen für Router, NAS, Linux und Windows: <code>docs/ABFRAGEN.md</code>.</span></div>
      <div class="card"><header><h2>${icon('key')}Zugangsdaten</h2><button type="button" id="cred-add">${icon('plus')}Hinzufügen</button></header>
      ${creds.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Art</th><th>Benutzer</th><th>Port</th><th>Automatisch</th><th>Geräte</th><th></th></tr></thead>
      <tbody>${creds.map((c) => `<tr><td>${esc(c.name)}</td>
        <td><span class="cell-dev">${icon((CRED_KINDS[c.kind] || {}).icon || 'key', 'i-sm')}${esc((CRED_KINDS[c.kind] || {}).label || c.kind)}</span></td>
        <td>${esc(c.username || '–')}</td><td>${esc(c.port || (CRED_KINDS[c.kind] || {}).port)}</td>
        <td>${c.auto ? '<span class="badge accent">ja</span>' : '<span class="muted">nein</span>'}</td>
        <td>${c.device_count}</td>
        <td class="actions">
          <button type="button" class="ghost sm" data-test="${c.id}" title="An einem Gerät testen">${icon('player-play', 'i-sm')}Testen</button>
          <button type="button" class="ghost sm" data-assign="${c.id}" title="Geräte auswählen, testen und zuordnen">${icon('devices', 'i-sm')}Geräte</button>
          <button type="button" class="ghost sm" data-edit="${c.id}" title="Bearbeiten">${icon('edit', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-del="${c.id}" title="Löschen">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Zugangsdaten. Mit SNMP oder SSH liest NetPulse CPU, RAM, Festplatten, Schnittstellen, Toner und mehr aus.', 'key')}</div>`;
    $('#cred-add').addEventListener('click', () => credDialog(null));
    $$('[data-edit]').forEach((b) => b.addEventListener('click', () => credDialog(creds.find((c) => c.id === Number(b.dataset.edit)))));
    $$('[data-test]').forEach((b) => b.addEventListener('click', () => testDialog(creds.find((c) => c.id === Number(b.dataset.test)))));
    $$('[data-assign]').forEach((b) => b.addEventListener('click', () => assignDialog(creds.find((c) => c.id === Number(b.dataset.assign)))));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      if (!confirm('Zugangsdaten löschen? Zugeordnete Geräte werden dann nicht mehr tief abgefragt.')) return;
      attempt(async () => { await api(`/credentials/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Gelöscht');
    }));
  };

  function credDialog(cred) {
    const editing = !!cred;
    const keep = editing ? 'leer lassen = unverändert' : '';
    const dlg = openModal(editing ? 'Zugangsdaten bearbeiten' : 'Zugangsdaten hinzufügen', `<form class="form" id="cred-form">
      <label>Art<select name="kind"${editing ? ' disabled' : ''}>${Object.entries(CRED_KINDS).map(([k, v]) => `<option value="${k}"${cred && cred.kind === k ? ' selected' : ''}>${esc(v.label)}</option>`).join('')}</select></label>
      <label>Name<input name="name" required maxlength="100" value="${esc(cred ? cred.name : '')}" placeholder="z. B. Heimnetz SNMP"></label>
      <div class="form-row">
        <label data-for="snmp_v3 ssh_key ssh_password http unifi"><span id="user-label">Benutzername</span><input name="username" value="${esc(cred ? cred.username || '' : '')}" autocomplete="off"></label>
        <label>Port<input name="port" type="number" min="1" max="65535" value="${esc(cred ? cred.port || '' : '')}" placeholder="Standard"></label>
      </div>
      <label data-for="snmp_v2c">Community<input name="community" type="password" autocomplete="new-password" placeholder="${keep || 'z. B. public'}"></label>
      <div class="form-row" data-for="snmp_v3">
        <label>Authentifizierung<select name="auth_protocol"><option value="sha1">SHA-1</option><option value="sha256" selected>SHA-256</option>
          <option value="sha512">SHA-512</option><option value="md5">MD5 (veraltet)</option><option value="none">keine</option></select></label>
        <label>Auth-Passwort<input name="auth_password" type="password" autocomplete="new-password" placeholder="${keep}"></label>
      </div>
      <div class="form-row" data-for="snmp_v3">
        <label>Verschlüsselung<select name="priv_protocol"><option value="aes128" selected>AES-128</option><option value="aes256">AES-256</option>
          <option value="des">DES (veraltet)</option><option value="none">keine</option></select></label>
        <label>Verschlüsselungs-Passwort<input name="priv_password" type="password" autocomplete="new-password" placeholder="${keep}"></label>
      </div>
      <label data-for="ssh_password http unifi"><span id="pw-label">Passwort</span><input name="password" type="password" autocomplete="new-password" placeholder="${keep}"></label>
      <label data-for="ssh_key">Privater Schlüssel (OpenSSH-Format)<textarea name="private_key" class="mono" placeholder="${keep || '-----BEGIN OPENSSH PRIVATE KEY-----'}"></textarea></label>
      <label data-for="ssh_key">Passphrase (optional)<input name="passphrase" type="password" autocomplete="new-password" placeholder="${keep}"></label>
      <label class="inline" data-for="snmp_v2c snmp_v3 ssh_key http"><input type="checkbox" name="auto"${cred && cred.auto ? ' checked' : ''}> Automatisch bei allen passenden Geräten verwenden</label>
      <p class="hint" id="auto-hint"></p>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    const form = $('#cred-form', dlg);
    const update = () => {
      const kind = form.kind.value;
      $$('[data-for]', form).forEach((el) => { el.hidden = !el.dataset.for.split(' ').includes(kind); });
      $('#auto-hint', dlg).textContent = kind === 'snmp_v2c'
        ? 'Hinweis: Bei SNMP v2c wird die Community unverschlüsselt an jedes getestete Gerät gesendet. Für „automatisch“ besser SNMP v3.'
        : kind === 'ssh_password' ? 'SSH-Passwörter werden aus Sicherheitsgründen nie automatisch ausprobiert – bitte Geräte gezielt zuordnen.'
          : kind === 'http' ? 'Gilt für alle erkannten Shelly-Geräte (Benutzer bei Gen2+ immer „admin“). Das Passwort geht nur an Geräte, die sich '
            + 'vorher als Shelly ausgewiesen haben; bei Gen2+ wird es per Digest-Verfahren nie im Klartext übertragen.'
            : kind === 'unifi' ? 'Empfohlen: API-Schlüssel – funktioniert auch mit Zwei-Faktor-Anmeldung. Anlegen in UniFi Network unter '
              + 'Einstellungen → Control Plane → Integrations → „Create API Key“. Benutzername dann leer lassen. Alternativ ein lokales Konto '
              + 'ohne 2FA (Benutzer + Passwort). Port leer = 11443 (UniFi OS Server), 443 und 8443 werden probiert. Wird nur dem Controller zugeordnet.' : '';
      $('#user-label', dlg).textContent = kind === 'unifi' ? 'Benutzername (nur lokales Konto, sonst leer)' : 'Benutzername';
      $('#pw-label', dlg).textContent = kind === 'unifi' ? 'API-Schlüssel (oder Passwort des lokalen Kontos)' : 'Passwort';
      if (kind === 'http' && !form.elements.username.value) form.elements.username.value = 'admin';
    };
    form.kind.addEventListener('change', update);
    update();
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const kind = form.kind.value;
      const v = (n) => form.elements[n].value.trim();
      const secret = {};
      ['community', 'password', 'private_key', 'passphrase', 'auth_password', 'priv_password'].forEach((n) => { if (form.elements[n].value) secret[n] = form.elements[n].value; });
      if (kind === 'snmp_v3') { secret.auth_protocol = v('auth_protocol'); secret.priv_protocol = v('priv_protocol'); }
      const body = { name: v('name'), kind, username: v('username'), port: v('port') ? Number(v('port')) : null,
        auto: kind !== 'unifi' && form.auto.checked, secret };
      attempt(async () => {
        if (editing) {
          await api(`/credentials/${cred.id}`, { method: 'PATCH', body });
          dlg.close();
          await render();
        } else {
          const created = await api('/credentials', { method: 'POST', body });
          dlg.close();
          await render();
          assignDialog(created); // direkt Geräte auswählen und testen
        }
      }, 'Zugangsdaten gespeichert');
    });
  }

  /** Passt ein Gerät grundsätzlich zur Zugangsart? (für die Vorauswahl) */
  const suits = (cred, d) => {
    if (cred.kind === 'http') return d.integration === 'shelly';
    if (cred.kind === 'unifi') return (d.open_ports || []).some((p) => [11443, 8443].includes(p));
    if (cred.kind.startsWith('ssh')) return (d.open_ports || []).includes(cred.port || 22);
    return d.monitored && d.status === 'up';
  };

  const resultCell = (r) => (r
    ? `<span class="${r.ok ? 'ok' : 'error'} small">${icon(r.ok ? 'circle-check' : 'circle-x', 'i-sm')} ${esc(r.message)}</span>`
    : '');

  async function testDialog(cred) {
    const devices = (await api('/devices')).sort((a, b) => suits(cred, b) - suits(cred, a));
    const dlg = openModal(`Testen: ${cred.name}`, `<div class="form">
      <label>Gerät<select id="t-device">${devices.map((d) => `<option value="${d.id}">${esc(deviceLabel(d))} – ${esc(d.ip)}${suits(cred, d) ? '' : ' (passt vermutlich nicht)'}</option>`).join('')}</select></label>
      <div class="actions"><button type="button" id="t-run">${icon('player-play')}Jetzt testen</button></div>
      <div id="t-result"></div>
      <p class="hint">Der Test ordnet nichts zu. Zum Zuordnen „Geräte“ verwenden.</p></div>`);
    $('#t-run', dlg).addEventListener('click', async () => {
      const box = $('#t-result', dlg);
      box.innerHTML = '<p class="muted">Teste …</p>';
      try {
        const r = await api(`/credentials/${cred.id}/test`, { method: 'POST', body: { device_id: Number($('#t-device', dlg).value) } });
        box.innerHTML = `<div class="notice ${r.ok ? 'info' : ''}">${icon(r.ok ? 'circle-check' : 'alert-triangle')}<span>${esc(r.message)}</span></div>`;
      } catch (e) {
        box.innerHTML = `<div class="notice">${icon('alert-triangle')}<span>${esc(e.message)}</span></div>`;
      }
    });
  }

  async function assignDialog(cred) {
    const [devices, assignedIds, job] = await Promise.all([api('/devices'), api(`/credentials/${cred.id}/devices`), api(`/credentials/${cred.id}/scan`)]);
    const assigned = new Set(assignedIds);
    // Vorauswahl: bereits zugeordnete plus alle passenden Geräte – ein Klick auf „Testen & zuordnen“ genügt
    const selected = new Set([...assignedIds, ...devices.filter((d) => suits(cred, d)).map((d) => d.id)]);
    const results = new Map((job.results || []).map((r) => [r.device_id, r]));
    const filters = { q: '', type: '', onlySuitable: true };
    const types = [...new Set(devices.map((d) => d.device_type))];
    const dlg = openModal(`Geräte zuordnen: ${cred.name}`, `<div class="form">
      <p class="hint">Häkchen setzen und <b>„Testen &amp; zuordnen“</b> – zugeordnet wird nur, wo die Anmeldung klappt. Ergebnis je Gerät erscheint rechts.</p>
      <div class="form-row"><input id="a-q" type="search" placeholder="Filtern: Name, IP, Hersteller …">
        <select id="a-type"><option value="">Alle Typen</option>${types.map((t) => `<option value="${esc(t)}">${esc(typeInfo(t).label)}</option>`).join('')}</select></div>
      <div class="actions"><label class="inline small"><input type="checkbox" id="a-suit" checked> nur passende Geräte zeigen</label>
        <button type="button" class="ghost sm" id="a-all">Alle sichtbaren auswählen</button>
        <button type="button" class="ghost sm" id="a-none">Auswahl leeren</button></div>
      <div class="table-wrap" id="a-list"></div>
      <div id="a-progress"></div>
      <div class="actions"><button type="button" id="a-scan">${icon('player-play')}Testen &amp; zuordnen</button>
        <button type="button" class="ghost" id="a-save">Ohne Test speichern</button><span class="muted small" id="a-count"></span></div></div>`);
    dlg.classList.add('wide');

    const visible = () => devices.filter((d) => {
      if (filters.onlySuitable && !suits(cred, d) && !assigned.has(d.id)) return false;
      if (filters.type && d.device_type !== filters.type) return false;
      const hay = `${deviceLabel(d)} ${d.ip} ${d.vendor || ''} ${d.hostname || ''}`.toLowerCase();
      return !filters.q || hay.includes(filters.q);
    });
    const draw = () => {
      const list = visible();
      $('#a-list', dlg).innerHTML = list.length ? `<table><tbody>${list.map((d) => `<tr>
        <td><input type="checkbox" data-id="${d.id}"${selected.has(d.id) ? ' checked' : ''} aria-label="auswählen"></td>
        <td><div class="cell-dev">${devIcon(d, 'sm')}<span class="ellipsis">${esc(deviceLabel(d))}</span>${assigned.has(d.id) ? ' <span class="badge accent">zugeordnet</span>' : ''}</div></td>
        <td class="mono small">${esc(d.ip)}</td><td>${resultCell(results.get(d.id))}</td></tr>`).join('')}</tbody></table>`
        : empty('Keine Geräte – Filter anpassen oder „nur passende“ abschalten.', 'devices');
      $$('#a-list input[data-id]', dlg).forEach((c) => c.addEventListener('change', () => {
        if (c.checked) selected.add(Number(c.dataset.id)); else selected.delete(Number(c.dataset.id));
        $('#a-count', dlg).textContent = `${selected.size} ausgewählt`;
      }));
      $('#a-count', dlg).textContent = `${selected.size} ausgewählt`;
    };
    const progress = (j) => {
      $('#a-progress', dlg).innerHTML = j.total ? `<p class="small">${j.running ? 'Teste' : 'Fertig:'} ${j.done} von ${j.total} Geräten ·
        <b class="ok">${j.found} erfolgreich</b>${j.done - j.found ? ` · ${j.done - j.found} ohne Erfolg` : ''}</p>
        <div class="progress"><span data-w="${pct(j.done, j.total)}"></span></div>` : '';
      applyWidths($('#a-progress', dlg));
    };
    progress(job);

    $('#a-q', dlg).addEventListener('input', (ev) => { filters.q = ev.target.value.trim().toLowerCase(); draw(); });
    $('#a-type', dlg).addEventListener('change', (ev) => { filters.type = ev.target.value; draw(); });
    $('#a-suit', dlg).addEventListener('change', (ev) => { filters.onlySuitable = ev.target.checked; draw(); });
    $('#a-all', dlg).addEventListener('click', () => { visible().forEach((d) => selected.add(d.id)); draw(); });
    $('#a-none', dlg).addEventListener('click', () => { selected.clear(); draw(); });
    $('#a-save', dlg).addEventListener('click', () => attempt(async () => {
      await api(`/credentials/${cred.id}/devices`, { method: 'PUT', body: { device_ids: [...selected] } });
      dlg.close();
      await render();
    }, 'Zuordnung gespeichert'));
    $('#a-scan', dlg).addEventListener('click', async () => {
      if (!selected.size) { toast('Bitte mindestens ein Gerät auswählen', true); return; }
      $('#a-scan', dlg).disabled = true;
      try {
        let j = await api(`/credentials/${cred.id}/scan`, { method: 'POST', body: { device_ids: [...selected] } });
        results.clear();
        while (j.running && dlg.open) {
          progress(j);
          await new Promise((r) => setTimeout(r, 1000));
          j = await api(`/credentials/${cred.id}/scan`);
          j.results.forEach((r) => { results.set(r.device_id, r); if (r.ok) assigned.add(r.device_id); });
          draw();
        }
        progress(j);
        toast(`Suchlauf fertig: ${j.found} von ${j.total} Geräten zugeordnet`);
        render();
      } catch (e) {
        toast(e.message, true);
      } finally {
        $('#a-scan', dlg).disabled = false;
      }
    });
    draw();
  }

  await render();
}

// ---------------------------------------------------------------------------
// Benachrichtigungskanäle
// ---------------------------------------------------------------------------

const CHANNEL_KINDS = {
  ntfy: { label: 'ntfy (Push aufs Handy)', icon: 'device-mobile', fields: [['server', 'Server', 'https://ntfy.sh'], ['topic', 'Thema (Topic)', 'z. B. netpulse-a8f3k2'], ['token', 'Zugriffstoken (optional)', '', 'password']],
    hint: 'App „ntfy“ installieren, dasselbe Thema abonnieren – fertig. Tipp: ein langes, zufälliges Thema wählen oder einen eigenen ntfy-Server nutzen.' },
  email: { label: 'E-Mail (SMTP)', icon: 'send', fields: [['host', 'SMTP-Server', 'smtp.example.de'], ['port', 'Port', '587'], ['security', 'Verschlüsselung', '', 'select:starttls=STARTTLS (587),tls=TLS (465),none=keine (nur intern)'],
    ['username', 'Benutzername', ''], ['password', 'Passwort', '', 'password'], ['from', 'Absender', 'netpulse@example.de'], ['to', 'Empfänger (mehrere mit Komma)', 'du@example.de']] },
  telegram: { label: 'Telegram', icon: 'send', fields: [['bot_token', 'Bot-Token', '123456:ABC…', 'password'], ['chat_id', 'Chat-ID', '123456789']],
    hint: 'Bot über @BotFather anlegen, dem Bot schreiben und die Chat-ID z. B. über @userinfobot ermitteln.' },
  gotify: { label: 'Gotify', icon: 'bell', fields: [['url', 'Server-URL', 'https://gotify.example.de'], ['token', 'App-Token', '', 'password']] },
  discord: { label: 'Discord', icon: 'send', fields: [['webhook_url', 'Webhook-URL', 'https://discord.com/api/webhooks/…', 'password']] },
  teams: { label: 'Microsoft Teams', icon: 'users', fields: [['webhook_url', 'Workflow-Webhook-URL', 'https://…', 'password']],
    hint: 'In Teams: Kanal → Workflows → „Beim Empfang einer Webhookanforderung in einem Kanal posten“ und die URL hier einfügen.' },
  webhook: { label: 'Webhook (eigene Systeme)', icon: 'plug-connected', fields: [['url', 'URL', 'https://…', 'password'], ['secret', 'Geheimnis (Header X-NetPulse-Secret)', '', 'password']] },
};

async function viewChannels() {
  const render = async () => {
    const channels = await api('/channels');
    view().innerHTML = `
      <div class="card"><header><h2>${icon('send')}Benachrichtigungskanäle</h2><button type="button" id="ch-add">${icon('plus')}Kanal hinzufügen</button></header>
      ${channels.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Art</th><th>Aktiv</th><th></th></tr></thead>
      <tbody>${channels.map((c) => `<tr><td>${esc(c.name)}</td>
        <td><span class="cell-dev">${icon((CHANNEL_KINDS[c.kind] || {}).icon || 'send', 'i-sm')}${esc((CHANNEL_KINDS[c.kind] || {}).label || c.kind)}</span></td>
        <td>${c.enabled ? '<span class="badge st-up">aktiv</span>' : '<span class="badge plain">aus</span>'}</td>
        <td class="actions"><button type="button" class="ghost sm" data-test="${c.id}">${icon('player-play', 'i-sm')}Test</button>
          <button type="button" class="ghost sm" data-edit="${c.id}">${icon('edit', 'i-sm')}</button>
          <button type="button" class="ghost sm" data-del="${c.id}">${icon('trash', 'i-sm')}</button></td></tr>`).join('')}</tbody></table></div>`
      : empty('Noch keine Kanäle. Am einfachsten: ntfy (kostenlose Push-App) oder E-Mail.', 'send')}</div>
      <p class="muted small">Wann benachrichtigt wird, legst du unter <a href="#/alerts?tab=rules">Alarme → Regeln</a> fest.</p>`;
    $('#ch-add').addEventListener('click', () => channelDialog(null));
    $$('[data-edit]').forEach((b) => b.addEventListener('click', () => channelDialog(channels.find((c) => c.id === Number(b.dataset.edit)))));
    $$('[data-test]').forEach((b) => b.addEventListener('click', () => {
      b.disabled = true;
      attempt(() => api(`/channels/${b.dataset.test}/test`, { method: 'POST' }), 'Testnachricht gesendet').finally(() => { b.disabled = false; });
    }));
    $$('[data-del]').forEach((b) => b.addEventListener('click', () => {
      if (!confirm('Kanal löschen?')) return;
      attempt(async () => { await api(`/channels/${b.dataset.del}`, { method: 'DELETE' }); await render(); }, 'Kanal gelöscht');
    }));
  };

  function channelDialog(channel) {
    const editing = !!channel;
    const fieldsHtml = (kind, config = {}) => {
      const def = CHANNEL_KINDS[kind];
      return def.fields.map(([key, label, placeholder, type]) => {
        const value = config[key] ?? (key === 'server' && !editing ? 'https://ntfy.sh' : key === 'port' && !editing ? '587' : '');
        if (type && type.startsWith('select:')) {
          const opts = type.slice(7).split(',').map((o) => o.split('='));
          return `<label>${esc(label)}<select name="cfg_${key}">${opts.map(([v, l]) => `<option value="${v}"${value === v ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select></label>`;
        }
        return `<label>${esc(label)}<input name="cfg_${key}" type="${type === 'password' ? 'password' : 'text'}" autocomplete="off" value="${esc(value)}" placeholder="${esc(placeholder)}"></label>`;
      }).join('') + (def.hint ? `<p class="hint">${esc(def.hint)}</p>` : '');
    };
    const dlg = openModal(editing ? 'Kanal bearbeiten' : 'Kanal hinzufügen', `<form class="form" id="ch-form">
      <label>Art<select name="kind"${editing ? ' disabled' : ''}>${Object.entries(CHANNEL_KINDS).map(([k, v]) => `<option value="${k}"${channel && channel.kind === k ? ' selected' : ''}>${esc(v.label)}</option>`).join('')}</select></label>
      <label>Name<input name="name" required value="${esc(channel ? channel.name : '')}" placeholder="z. B. Handy"></label>
      <div class="form" id="ch-fields"></div>
      <label class="inline"><input type="checkbox" name="enabled"${!channel || channel.enabled ? ' checked' : ''}> Aktiv</label>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    const form = $('#ch-form', dlg);
    const update = () => { $('#ch-fields', dlg).innerHTML = fieldsHtml(form.kind.value, channel ? channel.config : {}); };
    form.kind.addEventListener('change', update);
    update();
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const config = {};
      $$('[name^="cfg_"]', form).forEach((el) => {
        const key = el.name.slice(4);
        config[key] = key === 'port' ? (el.value ? Number(el.value) : null) : el.value.trim();
      });
      const body = { name: form.elements.name.value.trim(), kind: form.kind.value, enabled: form.enabled.checked, config };
      attempt(async () => {
        if (editing) await api(`/channels/${channel.id}`, { method: 'PATCH', body });
        else await api('/channels', { method: 'POST', body });
        dlg.close();
        await render();
      }, 'Kanal gespeichert – jetzt mit „Test“ prüfen');
    });
  }

  await render();
}

// ---------------------------------------------------------------------------
// Benutzer, Audit-Log, Konto
// ---------------------------------------------------------------------------

async function viewUsers() {
  const render = async () => {
    const users = await api('/users');
    view().innerHTML = `
      <div class="grid">
        <section class="card span-2 table-wrap"><table>
          <thead><tr><th>Benutzer</th><th>Rolle</th><th>Angelegt</th><th>Letzte Anmeldung</th><th></th></tr></thead>
          <tbody>${users.map((u) => `<tr><td><span class="cell-dev">${icon('user', 'i-sm')}${esc(u.username)}</span></td>
            <td>${u.role === 'admin' ? '<span class="badge accent">Administrator</span>' : '<span class="badge plain">Nur lesen</span>'}</td>
            <td class="small">${esc(fmtTime(u.created_at))}</td><td class="small">${esc(fmtTime(u.last_login))}</td>
            <td>${u.id === state.user.id ? '<span class="muted small">(du)</span>' : `<button class="ghost sm" data-del="${u.id}" data-name="${esc(u.username)}" type="button">${icon('trash', 'i-sm')}</button>`}</td></tr>`).join('')}
          </tbody></table></section>
        <section class="card span-1"><header><h2>${icon('plus')}Benutzer anlegen</h2></header>
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
  device_update: 'Gerät geändert', device_delete: 'Gerät gelöscht', device_credentials: 'Zugangsdaten zugeordnet',
  ssh_key_reset: 'SSH-Schlüssel zurückgesetzt', network_add: 'Netz hinzugefügt', network_delete: 'Netz entfernt',
  scan_trigger: 'Scan gestartet', user_add: 'Benutzer angelegt', user_delete: 'Benutzer gelöscht',
  credential_add: 'Zugangsdaten angelegt', credential_update: 'Zugangsdaten geändert', credential_delete: 'Zugangsdaten gelöscht',
  channel_add: 'Kanal angelegt', channel_update: 'Kanal geändert', channel_delete: 'Kanal gelöscht',
  discovery_schedule: 'Such-Zeitplan geändert', live_settings: 'Echtzeit-Abfrage geändert',
  rule_add: 'Regel angelegt', rule_update: 'Regel geändert', rule_delete: 'Regel gelöscht',
};

async function viewAudit() {
  const entries = await api('/audit?limit=500');
  view().innerHTML = `<div class="card table-wrap"><table>
      <thead><tr><th>Zeit</th><th>Benutzer</th><th>Aktion</th><th>Details</th></tr></thead>
      <tbody>${entries.map((e) => `<tr><td class="small">${esc(fmtTime(e.time))}</td><td>${esc(e.username || '–')}</td>
        <td>${e.action === 'login_failed' ? `<span class="badge warn">${esc(AUDIT_LABEL[e.action])}</span>` : esc(AUDIT_LABEL[e.action] || e.action)}</td>
        <td class="mono small">${Object.keys(e.detail || {}).length ? esc(JSON.stringify(e.detail)) : ''}</td></tr>`).join('')
        || `<tr><td colspan="4">${empty('Keine Einträge.')}</td></tr>`}</tbody></table></div>`;
}

// ---------------------------------------------------------------------------
// System-Log
// ---------------------------------------------------------------------------

const LOG_LEVELS = { debug: 'Alles (inkl. Details)', info: 'Info und wichtiger', warn: 'Warnungen und Fehler', error: 'Nur Fehler' };

async function viewLogs() {
  const filters = { level: 'info', q: '' };
  let lines = [];
  view().innerHTML = `
    <div class="page-head"><div class="actions">
        <select id="log-level" aria-label="Stufe">${Object.entries(LOG_LEVELS).map(([k, l]) => `<option value="${k}"${k === filters.level ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select>
        <input id="log-q" type="search" placeholder="Suchen: IP, Gerätename, „Shelly“ …" aria-label="Suchen">
        <label class="inline"><input type="checkbox" id="log-auto" checked> live</label></div>
      <div class="actions"><span class="muted small" id="log-count"></span>
        <button type="button" class="ghost" id="log-save">${icon('cloud-download')}Als Datei speichern</button></div></div>
    <div class="notice info">${icon('file-text')}<span>Die letzten 5.000 Meldungen seit dem Start des Containers (nur im Speicher).
      Tipp: Für ein einzelnes Gerät zeigt der Tab „Diagnose“ auf der Geräteseite jeden Abfrageschritt.</span></div>
    <div class="card"><div class="log" id="log-body"><div class="empty">Lade …</div></div></div>`;

  const shortTarget = (t) => t.replace(/^netpulse::/, '');
  const render = async () => {
    lines = await api(`/logs?level=${encodeURIComponent(filters.level)}&q=${encodeURIComponent(filters.q)}&limit=1000`);
    $('#log-count').textContent = `${lines.length} Einträge`;
    $('#log-body').innerHTML = lines.length ? lines.map((l) => `<div class="log-line lvl-${esc(l.level)}">
        <span class="mono muted">${esc(new Date(l.time).toLocaleString('de-DE'))}</span>
        <span class="lvl">${esc(l.level.toUpperCase())}</span>
        <span class="mono muted small ellipsis" title="${esc(l.target)}">${esc(shortTarget(l.target))}</span>
        <span class="msg">${esc(l.message)}</span></div>`).join('') : empty('Keine passenden Meldungen.', 'file-text');
  };
  let debounce = null;
  $('#log-level').addEventListener('change', (ev) => { filters.level = ev.target.value; render(); });
  $('#log-q').addEventListener('input', (ev) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => { filters.q = ev.target.value.trim(); render(); }, 300);
  });
  const auto = () => { if ($('#log-auto').checked) autoRefresh(render, 3); else clearInterval(state.refreshTimer); };
  $('#log-auto').addEventListener('change', auto);
  $('#log-save').addEventListener('click', () => {
    const text = lines.slice().reverse().map((l) => `${l.time} ${l.level.toUpperCase().padEnd(5)} ${l.target}: ${l.message}`).join('\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `netpulse-log-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.txt`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  await render();
  auto();
}

async function viewAccount() {
  view().innerHTML = `
    <div class="grid">
      <section class="card span-1"><header><h2>${icon('user')}Angemeldet als</h2></header>
        <dl class="details"><dt>Benutzer</dt><dd>${esc(state.user.username)}</dd>
          <dt>Rolle</dt><dd>${isAdmin() ? 'Administrator' : 'Nur lesen'}</dd></dl></section>
      <section class="card span-1"><header><h2>${icon('lock')}Passwort ändern</h2></header>
        <form class="form" id="pw-form">
          <label>Aktuelles Passwort<input name="old" type="password" required autocomplete="current-password"></label>
          <label>Neues Passwort (mind. 12 Zeichen)<input name="new" type="password" required minlength="12" autocomplete="new-password"></label>
          <label>Neues Passwort wiederholen<input name="repeat" type="password" required minlength="12" autocomplete="new-password"></label>
          <button type="submit">Passwort ändern</button>
          <p class="hint">Alle anderen Sitzungen werden dabei abgemeldet.</p>
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
