# NetPulse – agentenloses Netzwerk-Monitoring

NetPulse findet automatisch alle Geräte in deinen Netzen und prüft sie laufend auf Erreichbarkeit.
Die Ergebnisse zeigt ein konfigurierbares Web-Dashboard. Auf den Zielgeräten muss **nichts
installiert** werden. Alles läuft in Docker, z. B. auf einem NAS oder Raspberry Pi.

| Baustein | Technik |
|---|---|
| Backend, Scanner | Rust (tokio, axum, sqlx) |
| Datenbank | PostgreSQL 17 + TimescaleDB (Zeitreihen, Kompression, automatische Löschfristen) |
| Weboberfläche | HTML/CSS/JavaScript ohne Build-Schritt und ohne externe Abhängigkeiten |
| HTTPS | Caddy mit eigener lokaler Zertifizierungsstelle |

**Was Version 0.1 kann:** Geräteerkennung (Ping, TCP, ARP, Reverse-DNS, 28 typische Ports),
minütliche Erreichbarkeitsprüfung mit Antwortzeit, Ereignisse (neu, offline, wieder online,
MAC geändert), Verlaufsdiagramme bis 90 Tage, persönliches Dashboard mit Drag & Drop,
Benutzer mit Rollen (Admin / Nur lesen), Audit-Log.

Wie es weitergeht (SNMP, SSH, WinRM, Redfish, Alarme …): siehe [docs/ARCHITEKTUR.md](docs/ARCHITEKTUR.md).
Hinweise zu Datenschutz und Recht: [docs/DATENSCHUTZ.md](docs/DATENSCHUTZ.md).

---

## Installation mit Portainer (empfohlen)

GitHub baut bei jeder Änderung fertige Images für Intel/AMD und Raspberry Pi
(`ghcr.io/sirbuschi2003/netpulse`). Es muss also nichts kompiliert werden.

1. In Portainer: **Stacks → Add stack**, Name `netpulse`.
2. Build method **Repository** wählen:
   | Feld | Wert |
   |---|---|
   | Repository URL | `https://github.com/Sirbuschi2003/NetPulse` |
   | Repository reference | `refs/heads/main` |
   | Compose path | `deploy/portainer-stack.yml` |
3. Unter **Environment variables** eintragen:
   | Name | Beispiel | Hinweis |
   |---|---|---|
   | `DB_PASSWORD` | `a8f3…` (lang, zufällig) | nur Buchstaben und Ziffern, z. B. von `openssl rand -hex 24` |
   | `SITE_ADDRESS` | `https://192.168.178.10:8443` | IP deines NAS/Pi und Port |
   | `SCAN_NETWORKS` | `192.168.178.0/24` | dein Heimnetz |
   | `INITIAL_ADMIN_PASSWORD` | mind. 12 Zeichen | nach dem ersten Login ändern |
4. **Deploy the stack**. Nach etwa einer Minute ist NetPulse unter `SITE_ADDRESS` erreichbar
   (Benutzer `admin`).

**Updates:** Stack öffnen → **Pull and redeploy** und dabei *Re-pull image* aktivieren.
Wer es automatisch mag, schaltet im Stack **GitOps updates** ein.

**Stammzertifikat für den Browser** (gegen die Zertifikatswarnung): In Portainer den Container
`netpulse-proxy` öffnen → **Console** → *Connect* → `cat /data/caddy/pki/authorities/local/root.crt`
eingeben, die Ausgabe in eine Datei `netpulse-root.crt` kopieren und wie unten beschrieben importieren.

---

## Installation auf NAS / Raspberry Pi / Linux-Server (ohne Portainer)

**Voraussetzungen:** 64-Bit-Linux mit Docker und Docker Compose
(Raspberry Pi 4/5 mit 64-Bit-Raspberry-Pi-OS, Synology mit Container Manager, QNAP, Unraid, Ubuntu/Debian).
Mindestens 2 GB RAM.

1. Projekt auf das Gerät holen:
   ```bash
   git clone https://github.com/Sirbuschi2003/NetPulse.git
   cd NetPulse
   ```
2. Konfiguration anlegen:
   ```bash
   cp .env.example .env
   ```
   In `.env` mindestens `DB_PASSWORD`, `SITE_ADDRESS` und `SCAN_NETWORKS` setzen.
3. Starten:
   ```bash
   docker compose up -d --build
   ```
   Der erste Build auf einem Raspberry Pi dauert 15–30 Minuten. Schneller geht es, wenn du das Image
   auf dem PC baust (siehe unten).
4. Im Browser `SITE_ADDRESS` öffnen, z. B. `https://192.168.178.10:8443`.
   Wenn du kein `INITIAL_ADMIN_PASSWORD` gesetzt hast, steht das erzeugte Passwort im Log:
   ```bash
   docker compose logs app | grep Passwort
   ```
   Nach dem ersten Login bitte unter **Mein Konto** ein eigenes Passwort setzen.

### Image auf dem PC für den Raspberry Pi bauen

Dafür muss Docker Desktop auf dem PC laufen. Rust musst du nicht installieren.

```bash
docker buildx build --platform linux/arm64 -t netpulse:latest --output type=docker,dest=netpulse-arm64.tar .
```

Die Datei `netpulse-arm64.tar` auf den Pi kopieren und dort laden:

```bash
docker load -i netpulse-arm64.tar
```

Anschließend auf dem Pi `docker compose up -d` ausführen, **ohne** `--build`.
Für Intel/AMD-NAS (z. B. die meisten Synology-Geräte) `linux/amd64` statt `linux/arm64` verwenden.

### Browser-Warnung zum Zertifikat abstellen

Caddy erzeugt eine eigene lokale Zertifizierungsstelle. Ihr Stammzertifikat holst du so:

```bash
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./netpulse-root.crt
```

Unter Windows: Doppelklick auf die Datei → *Zertifikat installieren* → *Lokaler Computer* →
*Vertrauenswürdige Stammzertifizierungsstellen*. In der Firma kann die IT das Zertifikat per
Gruppenrichtlinie verteilen oder ein Zertifikat der firmeneigenen CA verwenden.

---

## Entwicklung & Test unter Windows

```bash
docker compose -f docker-compose.dev.yml up --build
```

Danach https://localhost:8443 öffnen. Docker Desktop sieht das echte Heimnetz nur eingeschränkt
(keine MAC-Adressen). Zum Ausprobieren eignet sich das Docker-interne Netz
(`docker network inspect netpulse-dev_default` zeigt es an).

Rust-Tests und Lints ohne lokale Rust-Installation:

```bash
docker run --rm -v "${PWD}/backend:/src" -w /src rust:1-bookworm cargo test
```

---

## Konfiguration (`.env`)

| Variable | Standard | Bedeutung |
|---|---|---|
| `DB_PASSWORD` | – (Pflicht) | Passwort der Datenbank; nur Buchstaben und Ziffern |
| `SITE_ADDRESS` | `https://localhost:8443` | Adresse der Weboberfläche |
| `SCAN_NETWORKS` | – | Netze beim ersten Start, z. B. `192.168.178.0/24,10.0.10.0/24` |
| `INITIAL_ADMIN_USER` / `_PASSWORD` | `admin` / zufällig | Erstes Admin-Konto |
| `DISCOVERY_INTERVAL_MIN` | 15 | Abstand der Netz-Scans in Minuten |
| `MONITOR_INTERVAL_SEC` | 60 | Abstand der Erreichbarkeitsprüfungen in Sekunden |
| `RETENTION_METRICS_DAYS` | 90 | Aufbewahrung der Messwerte |
| `RETENTION_EVENTS_DAYS` | 180 | Aufbewahrung der Ereignisse |
| `RETENTION_AUDIT_DAYS` | 365 | Aufbewahrung des Audit-Logs |
| `DB_PORT` / `APP_PORT` | 5433 / 8080 | Interne Ports auf dem Host (nur 127.0.0.1) |

## Sicherheit auf einen Blick

- Von außen erreichbar ist nur HTTPS (Caddy); Datenbank und App lauschen nur auf `127.0.0.1`.
- Die App läuft ohne root-Rechte, mit schreibgeschütztem Dateisystem und nur der Capability `NET_RAW` (für Ping).
- Passwörter werden mit Argon2id gespeichert, Sitzungs-Tokens nur als SHA-256-Hash.
- Cookies sind `HttpOnly`, `Secure` und `SameSite=Strict`; dazu kommt ein CSRF-Header und nach 5 Fehlversuchen eine Login-Sperre.
- Strenge Content-Security-Policy, HSTS und keine externen Skripte oder CDNs.
- Gescannt werden nur Netze, die ein Admin ausdrücklich freigegeben hat (höchstens /20 je Eintrag).
- Das Audit-Log protokolliert alle Anmeldungen und Änderungen.

## Backup

```bash
docker compose exec db pg_dump -U netpulse -p 5433 -h 127.0.0.1 netpulse | gzip > netpulse-backup.sql.gz
```

## Projektstruktur

```
backend/            Rust-Quellcode
  migrations/       Datenbankschema (wird beim Start automatisch angewendet)
  src/api/          REST-API (Login, Geräte, Dashboard, Verwaltung)
  src/scanner/      Discovery und Statusprüfung
  src/auth.rs       Passwörter, Sitzungen, Rollen, Brute-Force-Schutz
web/                Weboberfläche (index.html, app.js, style.css)
docs/               Architektur, Datenschutz, Roadmap
deploy/             Stack-Datei für Portainer (fertige Images)
proxy/              Caddy-Image mit eingebauter Konfiguration
.github/workflows/  Automatische Tests und Image-Builds
Dockerfile          Multi-Arch-Build (amd64 + arm64)
docker-compose.yml  Produktivbetrieb (Host-Netzwerk)
docker-compose.dev.yml  Test unter Windows/macOS
Caddyfile           HTTPS und Sicherheits-Header
```
