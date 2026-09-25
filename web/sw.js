/* NetPulse – Service Worker: macht die Weboberfläche installierbar und empfängt Push-Nachrichten.
 * Bewusst ohne Offline-Zwischenspeicher für Daten: Monitoring-Werte sollen immer aktuell sein.
 * Nur wenn der Server gar nicht erreichbar ist, erscheint eine kleine Offline-Seite. */
const OFFLINE = `<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetPulse – offline</title><body style="font:16px system-ui;background:#0b1020;color:#e8edf7;display:grid;place-items:center;height:100vh;margin:0;text-align:center">
<div><h1 style="font-size:22px">NetPulse ist gerade nicht erreichbar</h1><p style="color:#8b97b3">Keine Verbindung zum Server (WLAN/VPN prüfen).</p>
<p><a style="color:#818cf8" href="/">Erneut versuchen</a></p></div></body></html>`;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  if (event.request.mode !== 'navigate') return;
  event.respondWith(fetch(event.request).catch(() => new Response(OFFLINE, { headers: { 'Content-Type': 'text/html; charset=utf-8' } })));
});

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch { data = { title: 'NetPulse', body: event.data ? event.data.text() : '' }; }
  const icons = { critical: '🔴 ', warning: '🟠 ', resolved: '🟢 ', info: '' };
  // Alarme sollen auffallen: nie „still“, mit Vibration (Android); kritische bleiben stehen, bis man sie wegtippt.
  // Ob Android zusätzlich ein Pop-up mit Ton zeigt, legt die Benachrichtigungs-Kategorie der App in den
  // Android-Einstellungen fest (siehe „Mein Konto“ bzw. Handbuch).
  const loud = data.severity === 'critical' || data.severity === 'warning';
  // Rückmeldung an NetPulse: angezeigt oder Fehler (für „Mein Konto“ – so sieht man, ob das Handy mitspielt)
  const ack = async (ok, error) => {
    try {
      const sub = await self.registration.pushManager.getSubscription();
      if (!sub) return;
      await fetch('/api/push/ack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-NetPulse-Csrf': '1' },
        body: JSON.stringify({ endpoint: sub.endpoint, ok, error: error || null }),
      });
    } catch { /* Rückmeldung ist nur eine Hilfe */ }
  };
  event.waitUntil(self.registration.showNotification(`${icons[data.severity] || ''}${data.title || 'NetPulse'}`, {
    body: data.body || '',
    icon: '/icon-192.png',
    badge: '/badge-96.png',
    tag: data.tag || undefined,
    renotify: !!data.tag,
    silent: false,
    vibrate: loud ? [400, 150, 400, 150, 400] : [200],
    timestamp: Date.now(),
    requireInteraction: data.severity === 'critical',
    data: { url: data.url || '/#/alerts' },
  }).then(() => ack(true), (e) => ack(false, `${e && e.name ? `${e.name}: ` : ''}${e && e.message ? e.message : e}`)));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  let target = new URL(event.notification.data && event.notification.data.url ? event.notification.data.url : '/', self.location.origin);
  if (target.origin !== self.location.origin) target = new URL('/', self.location.origin); // nie fremde Seiten öffnen
  const url = target.href;
  event.waitUntil((async () => {
    const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of windows) {
      if (new URL(w.url).origin === self.location.origin) {
        await w.focus();
        return w.navigate(url);
      }
    }
    return self.clients.openWindow(url);
  })());
});
