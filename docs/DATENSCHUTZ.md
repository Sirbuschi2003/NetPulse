# Datenschutz und rechtliche Hinweise

> Diese Übersicht ist eine technische Orientierungshilfe und **keine Rechtsberatung**.
> Vor dem Einsatz in einer Firma bitte Datenschutzbeauftragte(n) und ggf. Betriebsrat einbeziehen.

## Privater Einsatz

Nutzt du NetPulse ausschließlich für dein eigenes Heimnetz, greift in der Regel die
**Haushaltsausnahme** (Art. 2 Abs. 2 lit. c DSGVO). Trotzdem gilt:
- Nur **eigene** Netze scannen (siehe Strafrecht unten).
- Geräte von Mitbewohnern oder Gästen tauchen ebenfalls auf. Transparenz schadet nicht.

## Einsatz in der Firma

### Welche personenbezogenen Daten entstehen?

| Daten | Personenbezug | Wo |
|---|---|---|
| IP- und MAC-Adresse, Hostname (z. B. `laptop-mmueller`) | ja, wenn einer Person zuordenbar | `devices` |
| Online-/Offline-Zeiten eines Arbeitsplatzrechners | **ja**: lässt Rückschlüsse auf Anwesenheit zu | `device_metrics`, `events` |
| Benutzernamen und Anmeldezeiten der NetPulse-Nutzer | ja | `users`, `audit_log` |
| Inventar aus SNMP/SSH: Rechnername, Seriennummer, Auslastung eines Arbeitsplatzrechners | ja, wenn einer Person zuordenbar | `devices.inventory`, `device_stats` |
| Empfangene Syslog-Meldungen und SNMP-Traps: können Benutzernamen, IP-Adressen, besuchte Namen (DNS) enthalten | **ja** | `syslog_messages` (Standard 30 Tage, `RETENTION_SYSLOG_DAYS`) |
| Angemeldete Sitzungen der NetPulse-Nutzer: Browser/Gerät, IP-Adresse, letzte Aktivität | ja | `sessions` (bis Ablauf/Abmeldung) |
| Push-Anmeldungen der NetPulse-App: Gerätebezeichnung, Push-Adresse des Browser-Herstellers | ja | `push_subscriptions` |
| Clients aus dem UniFi-Controller: Name, MAC, IP, verbunden seit | ja, wenn einer Person zuordenbar | `devices.inventory` des Controllers |

### Rechtsgrundlage und Pflichten (DSGVO)

- **Rechtsgrundlage:** meist berechtigtes Interesse an IT-Sicherheit und Betrieb (Art. 6 Abs. 1 lit. f DSGVO),
  bei Beschäftigtendaten zusätzlich Art. 88 DSGVO i. V. m. § 26 BDSG bzw. einer Betriebsvereinbarung.
- **Verzeichnis von Verarbeitungstätigkeiten** (Art. 30): NetPulse als Verarbeitung eintragen.
- **Datenschutz-Folgenabschätzung** (Art. 35): prüfen, vor allem wenn Arbeitsplatzrechner überwacht werden.
- **Information der Beschäftigten** (Art. 13).
- **Löschkonzept:** in NetPulse über die `RETENTION_*`-Einstellungen umgesetzt (Standard: Messwerte 90 Tage,
  Ereignisse 180 Tage, Audit-Log 365 Tage). Die Fristen sollten so kurz wie möglich gewählt werden.

### Betriebsrat (§ 87 Abs. 1 Nr. 6 BetrVG)

Ein System, das **objektiv geeignet** ist, Verhalten oder Leistung von Beschäftigten zu überwachen,
ist mitbestimmungspflichtig. Auf die Absicht kommt es dabei nicht an. Die Online-Zeiten von
Arbeitsplatzrechnern erfüllen das in der Regel.
**Empfehlung:** Server, Netzwerktechnik und Drucker überwachen, Arbeitsplatzrechner in NetPulse auf
„nicht überwacht“ setzen oder eine Betriebsvereinbarung abschließen.

### Datenschutzfreundliche Voreinstellungen (Art. 25 DSGVO) in NetPulse

- Gescannt werden nur ausdrücklich freigegebene Netze.
- Es gibt keine Inhaltsdaten: NetPulse liest keinen Datenverkehr, keine Dateien, keine Prozesse und keine angemeldeten Benutzer.
  Tiefe Abfragen (SNMP/SSH) erfassen nur technische Kennzahlen (Hardware, Auslastung, Speicher) und nur bei Geräten,
  denen ein Admin Zugangsdaten zugeordnet hat.
- Die Überwachung lässt sich je Gerät abschalten.
- Automatische Löschfristen.
- Keine Telemetrie: TimescaleDB-Telemetrie ist abgeschaltet, keine externen CDNs oder Tracker.
- Das Rollenmodell gewährt Lesern nur Lesezugriff; Verwaltung und Audit-Log sehen nur Admins.

### Technische und organisatorische Maßnahmen (Art. 32 DSGVO)

| Maßnahme | Umsetzung |
|---|---|
| Verschlüsselung im Transport | HTTPS (TLS 1.2/1.3), HSTS |
| Zugriffskontrolle | Login, Rollen, Argon2id, Zwei-Faktor-Anmeldung (TOTP), Sitzungsablauf, Sitzungsübersicht mit Abmelden, Brute-Force-Sperre je Benutzer+IP |
| Schutz von Zugangsdaten | AES-256-GCM-Verschlüsselung, Schlüssel getrennt von der Datenbank, keine Anzeige in der Oberfläche |
| Protokollierung | Audit-Log für Anmeldungen und Änderungen |
| Härtung | nicht-root, schreibgeschütztes Dateisystem, minimale Capabilities, no-new-privileges, DB nur lokal |
| Protokoll-Empfang | Syslog/Traps nur aus freigegebenen Netzen (`SYSLOG_ALLOW`), Größen- und Mengenbegrenzung |
| Öffentliche Statusseite | nur ausdrücklich freigegebene Einträge mit selbst gewählten Namen, keine IP-Adressen, geheimer Link im Fragment |
| Web-Sicherheit | CSP, CSRF-Schutz, SameSite-Cookies, konsequentes Escaping |
| Verfügbarkeit | Docker-Restart-Policy, Backup per `pg_dump` (siehe README) |

**Noch organisatorisch zu regeln:** Backup-Konzept, Verschlüsselung der Festplatte des Hosts,
Updates (Images regelmäßig neu bauen), Berechtigungskonzept und wer Admin ist.

## Strafrecht: nur eigene Netze scannen

Das unbefugte Ausspähen fremder Systeme ist strafbar (§§ 202a, 202b, 202c, 303b StGB).
Port-Scans fremder Netze können darunter fallen oder zumindest Abwehrmaßnahmen auslösen. NetPulse
scannt deshalb nur Bereiche, die ein Admin ausdrücklich freigibt, und protokolliert jede Freigabe im Audit-Log.
In der Firma sollte die Freigabe der Netze schriftlich mit der IT-Leitung abgestimmt sein.

## Weitere Regelwerke

- **NIS2 / NIS2UmsuCG:** Für betroffene Unternehmen verlangt es u. a. die Erkennung von Sicherheitsvorfällen.
  Ein Monitoring hilft dabei, muss aber selbst sicher betrieben werden.
- **BSI IT-Grundschutz:** Baustein OPS.1.1.1 („Allgemeiner IT-Betrieb“) und DER.1 („Detektion von sicherheitsrelevanten Ereignissen“).
- **Cyber Resilience Act (EU):** Relevant, falls NetPulse später **vertrieben** wird (Pflichten zu
  Schwachstellenmanagement, Sicherheitsupdates und SBOM ab Ende 2027). Für den internen Einsatz nicht einschlägig.

## Dienste von Drittanbietern (nur wenn eingerichtet)

- **Push-Nachrichten der NetPulse-App** laufen über den Push-Dienst des Browser-Herstellers (Google, Apple, Mozilla,
  Microsoft – teils USA). Der Inhalt ist Ende-zu-Ende verschlüsselt (RFC 8291); der Dienst sieht nur Zeitpunkt und Größe.
- **Benachrichtigungskanäle** wie Telegram, Discord, Microsoft Teams oder ntfy.sh übertragen den Alarmtext an den jeweiligen
  Anbieter (teils USA). Für personenbezogene Inhalte in der Firma besser E-Mail über den eigenen Server, Gotify oder einen
  eigenen ntfy-Server nutzen.
- **Öffentliche Statusseite:** Wer den Link kennt, sieht die freigegebenen Einträge. Keine personenbezogenen Namen als
  Anzeigenamen verwenden (z. B. „PC Buchhaltung“ statt „PC Müller“). Der Link lässt sich jederzeit erneuern.
