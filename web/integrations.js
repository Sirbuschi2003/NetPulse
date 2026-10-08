'use strict';
/* Verbundene Programme: z. B. Docker Backup Manager pausiert die Überwachung während eines Backups */

const INTEGRATION_KINDS = {
  'docker-backup-manager': { label: 'Docker Backup Manager', icon: 'database' },
  generic: { label: 'Anderes Programm / Skript', icon: 'plug-connected' },
};

const REPORT_STATUS = { ok: ['erfolgreich', 'st-up'], failed: ['fehlgeschlagen', 'st-down'], cancelled: ['abgebrochen', 'plain'] };
const reportBadge = (r) => { const [label, cls] = REPORT_STATUS[r.status] || [r.status, 'plain']; return `<span class="badge ${cls}">${esc(label)}</span>`; };
const fmtClock = (iso) => new Date(iso).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });

/** Hinweis auf laufende Pausen (für Dienste-Seite und Dashboard) */
async function pauseNotice() {
  let pauses = [];
  try { pauses = await api('/pauses'); } catch { return ''; }
  if (!pauses.length) return '';
  return `<div class="notice info">${icon('player-pause')}<span><b>Überwachung teilweise pausiert:</b>
    ${pauses.map((p) => `${esc(p.reason)} von ${esc(p.subjects.join(', '))} (${esc(p.source)}) – ${p.finishing ? 'fertig, Nachlauf' : 'spätestens'} bis ${esc(fmtClock(p.until))}`).join(' · ')}.
    Betroffene Dienste und Geräte werden solange nicht geprüft und nicht gemeldet.</span></div>`;
}

async function viewIntegrations() {
  const [list, devices, checks] = await Promise.all([api('/integrations'), api('/devices'), api('/checks')]);
  const deviceName = (id) => { const d = devices.find((x) => x.id === id); return d ? `${deviceLabel(d)} (${d.ip})` : `#${id}`; };

  const subjectRow = (it, s) => {
    const sub = s.subject;
    const manual = s.link && (s.link.device_ids.length || s.link.check_ids.length || !s.link.auto);
    const chips = s.matches.length
      ? s.matches.map((m) => `<span class="chip" title="${esc(m.why)}">${icon(m.kind === 'device' ? 'devices' : 'world-www', 'i-sm')}${esc(m.label)}</span>`).join('')
      : '<span class="muted small">nichts zugeordnet – Ausfälle während des Backups würden gemeldet</span>';
    const r = s.last_report;
    return `<tr>
      <td><b>${esc(sub.name)}</b>${sub.running === false ? ' <span class="badge plain">gestoppt</span>' : ''}
        <div class="muted small">${[sub.project ? `Projekt ${sub.project}` : '', sub.ports.length ? `Ports ${sub.ports.join(', ')}` : '', sub.ips.length ? `IP ${sub.ips.join(', ')}` : '']
          .filter(Boolean).map(esc).join(' · ')}</div></td>
      <td><div class="chips">${chips}</div>${manual ? `<div class="muted small">${s.link.auto ? 'automatisch + von Hand' : 'nur von Hand'}</div>` : ''}</td>
      <td>${r ? `${reportBadge(r)} <span class="small">${esc(fmtAgo(r.time))}</span>
          <div class="muted small">${[r.size_bytes != null ? fmtBytes(r.size_bytes) : '', r.duration_s != null ? fmtDuration(r.duration_s) : '']
            .filter(Boolean).map(esc).join(' · ')}${r.status === 'failed' && r.message ? ` – ${esc(r.message)}` : ''}</div>`
        : `<span class="muted small">${sub.scheduled ? 'geplant, noch keine Meldung' : '–'}</span>`}
        ${s.last_ok && r && r.status !== 'ok' ? `<div class="muted small">zuletzt erfolgreich ${esc(fmtAgo(s.last_ok))}</div>` : ''}</td>
      <td class="actions"><button type="button" class="ghost sm" data-link="${it.id}" data-subject="${esc(sub.name)}" title="Zuordnung ändern">${icon('edit', 'i-sm')}</button></td></tr>`;
  };

  const card = (it) => {
    const kind = INTEGRATION_KINDS[it.kind] || INTEGRATION_KINDS.generic;
    const seen = it.last_seen_at ? (Date.now() - new Date(it.last_seen_at) < 2 * 3600 * 1000) : false;
    const active = it.pauses.filter((p) => p.active);
    return `<section class="card"><header><h2>${icon(kind.icon)}${esc(it.name)}</h2>
        <div class="actions">${!it.enabled ? '<span class="badge plain">ausgeschaltet</span>'
          : it.last_seen_at ? `<span class="badge ${seen ? 'st-up' : 'warn'}">${seen ? 'verbunden' : 'lange nicht gemeldet'}</span>` : '<span class="badge warn">noch nie gemeldet</span>'}
          <button type="button" class="ghost sm" data-edit="${it.id}">${icon('settings', 'i-sm')}Einstellungen</button></div></header>
      <p class="muted small">${esc(kind.label)} · Schlüssel ${esc(it.token_hint)}${it.last_seen_at ? ` · zuletzt gemeldet ${esc(fmtAgo(it.last_seen_at))}${it.last_ip ? ` von ${esc(it.last_ip)}` : ''}` : ''}
        · Docker-Host: ${it.host_device_id ? esc(deviceName(it.host_device_id)) : '<b>nicht gewählt</b>'}</p>
      ${!it.host_device_id ? `<div class="notice">${icon('info-circle')}<span>Wähle unter <i>Einstellungen</i> den Rechner, auf dem Docker läuft (z. B. dein NAS) –
        dann ordnet NetPulse Dienste auch über die veröffentlichten Ports zu (z. B. <code>http://NAS:2283</code> → Immich).</span></div>` : ''}
      ${active.length ? `<div class="notice info">${icon('player-pause')}<span>Gerade pausiert: ${active.map((p) => `${esc(p.reason)} – ${esc(p.subjects.join(', '))}
        (${p.ended_at ? 'Nachlauf' : 'spätestens'} bis ${esc(fmtClock(p.until))}) <button type="button" class="ghost sm" data-stop="${p.id}">Jetzt beenden</button>`).join('<br>')}</span></div>` : ''}
      ${it.subjects.length ? `<div class="table-wrap"><table><thead><tr><th>Container</th><th>Wird während des Backups pausiert</th><th>Letztes Backup</th><th></th></tr></thead>
        <tbody>${it.subjects.map((s) => subjectRow(it, s)).join('')}</tbody></table></div>
        <p class="hint">Zuordnung automatisch über die eigene IP des Containers, veröffentlichte Ports auf dem Docker-Host und passende Namen
          (Maus über einen Eintrag zeigt den Grund). Mit ${icon('edit', 'i-sm')} lässt sich das je Container ändern.
          ${it.inventory_at ? `Containerliste vom ${esc(fmtTime(it.inventory_at))}.` : ''}</p>`
        : empty('Das Programm hat noch keine Container gemeldet. Im Programm NetPulse-Adresse und Schlüssel eintragen und „Verbindung testen“ klicken.', 'plug-connected')}
      ${it.pauses.length || it.reports.length ? `<details class="sub"><summary>Verlauf (Pausen und Meldungen)</summary>
        <div class="grid">
          <div class="span-1"><h3 class="sub">Pausen</h3>${it.pauses.length ? `<ul class="plain-list small">${it.pauses.map((p) => `<li>${esc(fmtTime(p.started_at))} – ${esc(p.reason)}: ${esc(p.subjects.join(', '))}
            <span class="muted">(${p.device_ids.length} Geräte, ${p.check_ids.length} Dienste${p.active ? ', läuft' : p.ended_at ? `, ${fmtDuration((new Date(p.ended_at) - new Date(p.started_at)) / 1000)}` : ', von selbst beendet'})</span></li>`).join('')}</ul>`
            : '<p class="muted small">keine</p>'}</div>
          <div class="span-2"><h3 class="sub">Meldungen</h3>${it.reports.length ? `<ul class="plain-list small">${it.reports.map((r) => `<li>${reportBadge(r)} ${esc(fmtTime(r.time))} –
            ${esc(r.kind)} ${esc(r.subject)}${r.size_bytes != null ? ` · ${esc(fmtBytes(r.size_bytes))}` : ''}${r.message ? ` <span class="muted">${esc(r.message)}</span>` : ''}</li>`).join('')}</ul>`
            : '<p class="muted small">keine</p>'}</div></div></details>` : ''}
    </section>`;
  };

  view().innerHTML = `
    <div class="notice info">${icon('plug-connected')}<span>Andere Programme im Heimnetz greifen hier wie Zahnräder in NetPulse ein.
      Der <b>Docker Backup Manager</b> meldet z. B. vor dem Stoppen der Container für ein Backup eine <b>Pause</b>: Die zugehörigen Dienste und Geräte werden dann
      nicht geprüft – kein Alarm, kein Eintrag im Verlauf, kein Abzug bei der Verfügbarkeit. Danach (plus kurzer Nachlaufzeit zum Hochfahren) geht die
      Überwachung von selbst weiter; meldet sich das Programm nicht zurück, endet die Pause spätestens nach der angegebenen Höchstdauer.
      Backup-Ergebnisse landen ebenfalls hier – mit eigenen Alarm-Regeln „Backup fehlgeschlagen“ und „Backup überfällig“.</span></div>
    <div class="page-head"><div></div><div class="actions"><button type="button" id="int-add">${icon('plus')}Programm verbinden</button></div></div>
    ${list.length ? list.map(card).join('') : `<div class="card">${empty('Noch kein Programm verbunden.', 'plug-connected')}</div>`}
    <details class="card sub"><summary>${icon('file-text', 'i-sm')} Für eigene Skripte: die Schnittstelle</summary>
      <p class="small">Jedes Programm meldet sich mit <code>Authorization: Bearer npi_…</code>. Der Schlüssel erlaubt nur diese Aufrufe – keinen Zugriff auf Geräte, Zugangsdaten oder Einstellungen.</p>
      <pre class="code small">GET  /api/integration/v1/hello                         Verbindungstest
PUT  /api/integration/v1/inventory   {"subjects":[{"name":"nextcloud","project":"nextcloud","ports":[8080],"ips":[],"scheduled":true}]}
POST /api/integration/v1/pause       {"subjects":["nextcloud"],"minutes":120,"reason":"Backup"}   → {"id":17,…}
POST /api/integration/v1/pause/17/end {"grace_s":180}
POST /api/integration/v1/report      {"kind":"backup","subject":"nextcloud","status":"ok","size_bytes":123,"duration_s":60}</pre>
      <p class="small">Beispiel (Shell):<br><code>curl -X POST -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -d '{"subjects":["nextcloud"],"minutes":60}' ${esc(location.origin)}/api/integration/v1/pause</code></p>
    </details>`;

  $('#int-add').addEventListener('click', () => addDialog());
  $$('[data-edit]').forEach((b) => b.addEventListener('click', () => editDialog(list.find((i) => i.id === Number(b.dataset.edit)))));
  $$('[data-stop]').forEach((b) => b.addEventListener('click', () => attempt(async () => {
    await api(`/pauses/${b.dataset.stop}/end`, { method: 'POST' });
    await viewIntegrations();
  }, 'Pause beendet – Überwachung läuft wieder')));
  $$('[data-link]').forEach((b) => b.addEventListener('click', () => {
    const it = list.find((i) => i.id === Number(b.dataset.link));
    linkDialog(it, it.subjects.find((s) => s.subject.name === b.dataset.subject));
  }));
  autoRefresh(viewIntegrations, 30);

  const hostSelect = (selected) => `<label>Docker-Host (Rechner, auf dem die Container laufen)<select name="host">
      <option value="">– nicht gewählt –</option>${devices.map((d) => `<option value="${d.id}"${d.id === selected ? ' selected' : ''}>${esc(deviceLabel(d))} – ${esc(d.ip)}</option>`).join('')}</select></label>`;

  function showToken(name, token) {
    const dlg = openModal(`Schlüssel für ${name}`, `<div class="form">
      <p>Diesen Schlüssel im Programm eintragen. <b>Er wird nur jetzt angezeigt</b> – NetPulse speichert ihn nur verschlüsselt (als Hash).</p>
      <label>Schlüssel<input readonly id="tok" value="${esc(token)}"></label>
      <label>NetPulse-Adresse für das Programm<input readonly id="tok-url" value="${esc(location.origin)}"></label>
      <p class="hint">Läuft das Programm im selben Heimnetz, geht auch die interne Adresse, z. B. <code>http://10.10.10.15:18081</code> (Eingang für den Reverse-Proxy)
        oder <code>https://10.10.10.15:8443</code> (eigenes Zertifikat – dann im Programm „Zertifikat nicht prüfen“ wählen).</p>
      <div class="actions"><button type="button" id="tok-copy">${icon('check')}Schlüssel kopieren</button></div></div>`);
    $('#tok-copy', dlg).addEventListener('click', () => {
      const input = $('#tok', dlg);
      input.select();
      (navigator.clipboard ? navigator.clipboard.writeText(input.value) : Promise.reject()).then(() => toast('Kopiert'), () => { document.execCommand('copy'); toast('Kopiert'); });
    });
  }

  function addDialog() {
    const nas = devices.find((d) => /nas|ugreen|synology|qnap/i.test(`${d.device_type} ${deviceLabel(d)} ${d.model || ''}`));
    const dlg = openModal('Programm verbinden', `<form class="form" id="int-form">
      <label>Art<select name="kind">${Object.entries(INTEGRATION_KINDS).map(([k, v]) => `<option value="${k}">${esc(v.label)}</option>`).join('')}</select></label>
      <label>Name<input name="name" required maxlength="100" value="Docker Backup Manager"></label>
      ${hostSelect(nas ? nas.id : null)}
      <div class="actions"><button type="submit">${icon('key')}Schlüssel erzeugen</button></div></form>`);
    const form = $('#int-form', dlg);
    form.elements.kind.addEventListener('change', () => { form.elements.name.value = INTEGRATION_KINDS[form.elements.kind.value].label; });
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const e = form.elements;
      attempt(async () => {
        const r = await api('/integrations', { method: 'POST', body: { name: e.name.value.trim(), kind: e.kind.value, host_device_id: e.host.value ? Number(e.host.value) : null } });
        dlg.close();
        await viewIntegrations();
        showToken(e.name.value.trim(), r.token);
      });
    });
  }

  function editDialog(it) {
    const dlg = openModal(`${it.name} – Einstellungen`, `<form class="form" id="int-edit">
      <label>Name<input name="name" required maxlength="100" value="${esc(it.name)}"></label>
      ${hostSelect(it.host_device_id)}
      <label class="inline"><input type="checkbox" name="enabled"${it.enabled ? ' checked' : ''}> Eingeschaltet (aus = Schlüssel gesperrt)</label>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button>
        <button type="button" class="ghost" id="int-token">${icon('key')}Neuer Schlüssel</button>
        <button type="button" class="ghost" id="int-del">${icon('trash')}Trennen</button></div></form>`);
    const form = $('#int-edit', dlg);
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const e = form.elements;
      attempt(async () => {
        await api(`/integrations/${it.id}`, { method: 'PATCH', body: { name: e.name.value.trim(), enabled: e.enabled.checked, host_device_id: e.host.value ? Number(e.host.value) : null } });
        dlg.close();
        await viewIntegrations();
      }, 'Gespeichert');
    });
    $('#int-token', dlg).addEventListener('click', () => {
      if (!confirm('Neuen Schlüssel erzeugen? Der bisherige funktioniert sofort nicht mehr – im Programm muss der neue eingetragen werden.')) return;
      attempt(async () => { const r = await api(`/integrations/${it.id}/token`, { method: 'POST' }); dlg.close(); await viewIntegrations(); showToken(it.name, r.token); });
    });
    $('#int-del', dlg).addEventListener('click', () => {
      if (!confirm(`„${it.name}“ trennen? Schlüssel, Zuordnungen und Verlauf werden gelöscht.`)) return;
      attempt(async () => { await api(`/integrations/${it.id}`, { method: 'DELETE' }); dlg.close(); await viewIntegrations(); }, 'Getrennt');
    });
  }

  function linkDialog(it, s) {
    const link = s.link || { auto: true, device_ids: [], check_ids: [] };
    const autoOnly = s.matches.filter((m) => m.why !== 'von Hand zugeordnet');
    const pick = (name, items, chosen, label) => `<div class="pick-list">${items.map((x) => `<label class="inline"><input type="checkbox" name="${name}" value="${x.id}"${chosen.includes(x.id) ? ' checked' : ''}>
      <span class="ellipsis">${esc(label(x))}</span></label>`).join('') || '<span class="muted small">keine</span>'}</div>`;
    const dlg = openModal(`Zuordnung: ${s.subject.name}`, `<form class="form" id="link-form">
      <p class="small">Was soll NetPulse nicht prüfen, solange <b>${esc(s.subject.name)}</b> für ein Backup gestoppt ist?</p>
      <label class="inline"><input type="checkbox" name="auto"${link.auto ? ' checked' : ''}> Automatisch erkannte Zuordnung verwenden</label>
      <div class="muted small">${autoOnly.length ? `Automatisch: ${autoOnly.map((m) => `${esc(m.label)} <i>(${esc(m.why)})</i>`).join(', ')}` : 'Automatisch wurde nichts gefunden.'}</div>
      <h3 class="sub">Zusätzlich von Hand</h3>
      <input type="search" id="link-filter" placeholder="Geräte/Dienste filtern …">
      <div class="form-row"><div><div class="muted small">Dienste</div>${pick('chk', checks, link.check_ids, (c) => `${c.name} – ${c.target}`)}</div>
        <div><div class="muted small">Geräte</div>${pick('dev', devices, link.device_ids, (d) => `${deviceLabel(d)} – ${d.ip}`)}</div></div>
      <div class="actions"><button type="submit">${icon('check')}Speichern</button></div></form>`);
    dlg.classList.add('wide');
    const form = $('#link-form', dlg);
    $('#link-filter', dlg).addEventListener('input', (ev) => {
      const q = ev.target.value.toLowerCase();
      $$('.pick-list label', dlg).forEach((l) => { l.hidden = q && !l.textContent.toLowerCase().includes(q); });
    });
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const ids = (n) => $$(`input[name="${n}"]:checked`, form).map((c) => Number(c.value));
      attempt(async () => {
        await api(`/integrations/${it.id}/links`, { method: 'PUT', body: { subject: s.subject.name, auto: form.elements.auto.checked, device_ids: ids('dev'), check_ids: ids('chk') } });
        dlg.close();
        await viewIntegrations();
      }, 'Zuordnung gespeichert');
    });
  }
}
