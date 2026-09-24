# Architektur

## Überblick

```
                ┌──────────────────── Docker-Host (NAS / Raspberry Pi), network_mode: host ─────────────────────┐
                │                                                                                              │
 Browser ──HTTPS──►  Caddy :8443  ──HTTP──►  NetPulse (Rust)  127.0.0.1:18080                                    │
                │    TLS, CSP, HSTS          ├─ REST-API + Weboberfläche (axum)                                │
                │                            ├─ Discovery-Task   (alle 15 min + „Jetzt scannen“)               │
                │                            ├─ Monitor-Task     (jede Minute)                                 │
                │                            └─ Wartungs-Task    (stündlich: Löschfristen, Sitzungen)          │
                │                                      │                                                       │
                │                                      ▼                                                       │
                │                     PostgreSQL + TimescaleDB  127.0.0.1:5433                                 │
                └──────────────────────────────────────┼───────────────────────────────────────────────────────┘
                                                       │ ICMP · TCP · ARP · DNS  (später: SNMP · SSH · WinRM · Redfish)
                                                       ▼
                                          Geräte im LAN (ohne Agent)
```

Die Anwendung ist **ein einziges Rust-Programm**. Webserver und Scanner laufen darin als
parallele Tasks auf der asynchronen Laufzeitumgebung *tokio*. Das hält den Betrieb auf einem
Raspberry Pi einfach und sparsam: etwa 10–30 MB RAM für NetPulse selbst.

## Datenmodell

| Tabelle | Inhalt |
|---|---|
| `devices` | Ein Eintrag je IP: MAC, Hostname, eigener Name, Notizen, offene Ports, Status |
| `device_metrics` | **Hypertable** (TimescaleDB): Zeitpunkt, erreichbar ja/nein, Antwortzeit. Wird nach 7 Tagen komprimiert und nach `RETENTION_METRICS_DAYS` gelöscht |
| `events` | Statuswechsel, neue Geräte, MAC-Änderungen |
| `networks` | Freigegebene Scan-Bereiche (Allowlist) |
| `users`, `sessions` | Konten (Argon2id) und Sitzungen (nur Token-Hash) |
| `dashboards` | Widget-Layout je Benutzer (JSON) |
| `audit_log` | Wer hat wann was getan |
| `settings` | Schlüssel/Wert, z. B. Ergebnis des letzten Scans |
| `credentials`, `device_credentials` | Zugangsdaten (Geheimnisse verschlüsselt) und ihre Zuordnung zu Geräten |
| `device_stats` | **Hypertable**: CPU, RAM, Speicher, Temperatur, Datenrate aus SNMP/SSH |
| `notification_channels`, `alert_rules`, `alerts` | Kanäle (Konfiguration verschlüsselt), Regeln, ausgelöste Alarme |

Das Schema liegt in `backend/migrations/` und wird beim Start automatisch angewendet.
Neue Änderungen kommen immer als **neue** Datei hinzu (`0002_…sql`); bestehende Migrationen werden nie geändert.

## Ablauf der Datenerfassung

**Discovery** (je freigegebenem Netz):
1. ICMP-Ping an jede Adresse (256 parallel). Antwortet eine Adresse nicht, folgt ein TCP-Verbindungsversuch
   auf 443/80/22/445/3389. Auch ein „Connection refused“ zählt als Lebenszeichen.
2. Die ARP-Tabelle des Kernels liefert MAC-Adressen. Sie findet auch Geräte, die Ping und TCP blockieren.
3. Für jedes aktive Gerät: Scan von 28 typischen Ports und Reverse-DNS-Name.
4. Speichern. Neue Geräte und geänderte MAC-Adressen werden als Ereignis erfasst (Hinweis auf ARP-Spoofing).

**Monitor** (jede Minute, alle überwachten Geräte):
Ping, bei Misserfolg TCP auf bekannte offene Ports. Das Ergebnis wird als Messwert gespeichert.
Wechselt der Status, entsteht ein Ereignis.

## Warum agentenlos, und wo die Grenzen liegen

Ohne Agent sieht NetPulse, was ein Gerät **über das Netzwerk preisgibt**. Für tiefe Einblicke
(CPU, RAM, Festplatten, Software, Hardware-Sensoren) braucht es Standardprotokolle, die auf dem
Zielgerät einmalig aktiviert und mit einem Konto mit Leserechten versehen werden:

| Zielsystem | Protokoll | Einrichtung auf dem Zielgerät |
|---|---|---|
| Linux, NAS, Proxmox, Raspberry Pi | SSH | Benutzer mit Leserechten + SSH-Schlüssel |
| Windows | WinRM (WS-Management) | `winrm quickconfig`, in der Firma per Gruppenrichtlinie |
| Switch, Router, Drucker, USV, Fritzbox | SNMP v3 | SNMP im Gerät aktivieren |
| Server-Hardware (iDRAC, iLO, IPMI) | Redfish (HTTPS/JSON) | Benutzer mit Leserechten |
| IoT, Smart-TV, Handys | – | nur Erkennung, Ports und Erreichbarkeit |

## Roadmap

**✅ Phase 1: Erkennung und Erreichbarkeit** (Version 0.1)

**✅ Phase 2: Tiefe Abfragen und Zugangsdaten-Tresor**
- Zugangsdaten AES-256-GCM-verschlüsselt, Schlüssel in `/data/secret.key` außerhalb der Datenbank
- SNMP v2c/v3: System, Schnittstellen und Datenverkehr, CPU, RAM, Speicher, Drucker, USV, Synology, ENTITY, LLDP
- SSH: Linux, NAS, Proxmox, Raspberry Pi und Windows (OpenSSH + PowerShell/CIM), Host-Schlüssel nach „Trust on first use“
- Automatisches Ausprobieren von Zugangsdaten (SNMP, SSH-Schlüssel), Treffer werden fest zugeordnet
- Herstellererkennung über die MAC-Adresse (IEEE-OUI-Liste), automatische Erkennung des Gerätetyps

**✅ Phase 3: Alarmierung**
- Regeln: offline länger als X Minuten, neues Gerät, MAC-/SSH-Schlüssel geändert, Speicher, CPU, RAM, Temperatur
- Kanäle: E-Mail, ntfy, Gotify, Telegram, Discord, Microsoft Teams, Webhook; Entwarnung beim Beheben

**✅ Phase 3b: Live-Daten, Herstellerprofile, Shelly**
- Live-Datenraten je Schnittstelle (SNMP und SSH), WAN-Erkennung über die Standardroute, Dashboard-Widget „Internet“
- Profile für UniFi, Synology, MikroTik, APC, pf-Firewalls, ENTITY-SENSOR-MIB
- SNMP-Explorer mit Namen aus ~4.800 MIBs (Tabelle `mib_names`)
- Shelly Gen1–Gen4 über die lokale HTTP-API (Digest-Auth für Gen2+), Gerätenamen per mDNS und NetBIOS

**Phase 4: Weitere Datenquellen**
- WinRM (HTTPS) als Alternative zu SSH für Windows
- FRITZ!Box über TR-064 (Bandbreite, verbundene Geräte, DSL-Werte)
- UniFi- und OPNsense-API (Clients, Bandbreite je Client, Regeln), weitere Smart-Home-Geräte (Tasmota, ESPHome, Home Assistant)
- Redfish für Server-Hardware (iDRAC, iLO)
- mDNS/NetBIOS-Namen, Syslog-Empfang, NetFlow/sFlow
- HTTP- und TLS-Prüfungen (Antwortzeit, Statuscode, Zertifikatslaufzeit)
- Netzwerkkarte (Topologie) aus den LLDP-Nachbarn
- Wartungsfenster und Bestätigen von Alarmen

**Phase 5: Firmeneinsatz**
- Anmeldung über OIDC/SSO (Entra ID, Keycloak) und TOTP-Zwei-Faktor
- Feinere Rechte (z. B. nur bestimmte Netze oder Gerätegruppen sehen)
- Optionaler Agent (Rust, ein einzelnes Programm ohne Abhängigkeiten) für Geräte ohne passenden Zugang
- Hochverfügbarkeit, IPv6-Discovery über Neighbor-Tabellen

## Warum diese Technik

- **Rust:** kein Garbage Collector und niedriger Speicherbedarf (ideal für den Pi); Speicherfehler wie
  Buffer Overflows sind ausgeschlossen, für eine Software mit Netz- und Admin-Zugang ein echter Sicherheitsgewinn.
- **TimescaleDB statt separater Zeitreihen-DB:** eine Datenbank für alles, Backups mit einem `pg_dump`,
  eingebaute Kompression und Löschfristen.
- **Frontend ohne Framework:** kein npm, keine Lieferketten-Risiken durch hunderte Pakete,
  funktioniert mit strenger CSP. Wird die Oberfläche deutlich größer, bietet sich ein Umstieg auf Svelte an.
- **Caddy:** HTTPS ohne Handarbeit, gute Sicherheitsvoreinstellungen.
