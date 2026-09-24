# Tiefe Abfragen einrichten (SNMP & SSH)

Ohne Zugangsdaten sieht NetPulse, **ob** ein Gerät da ist, welche Dienste es anbietet und wie schnell es antwortet.
Mit SNMP oder SSH kommen **CPU, RAM, Festplatten, Temperaturen, Schnittstellen, Datenverkehr, Toner, USV-Akku,
Betriebssystem, Modell und Seriennummer** dazu.

Grundregeln:
- Immer ein **eigenes Konto nur mit Leserechten** für NetPulse anlegen, nie das Admin-Konto verwenden.
- **SNMP v3** statt v2c (v2c überträgt die Community unverschlüsselt).
- **SSH-Schlüssel** statt Passwort. Schlüssel können auch automatisch bei mehreren Geräten ausprobiert werden,
  Passwörter aus Sicherheitsgründen nicht.
- NetPulse merkt sich beim ersten Kontakt den SSH-Host-Schlüssel. Ändert er sich später, stoppt die Abfrage und es gibt
  einen Sicherheitshinweis (Schutz vor Man-in-the-Middle-Angriffen).

In NetPulse: **Zugangsdaten → Hinzufügen**, danach beim Gerät unter **Einstellungen** zuordnen
(oder „automatisch ausprobieren“ aktivieren).

---

## SSH-Schlüssel für NetPulse erzeugen (einmalig)

Auf dem PC (Windows-Terminal, Linux oder macOS):

```bash
ssh-keygen -t ed25519 -C netpulse -f netpulse_key
```

Das erzeugt zwei Dateien:
- `netpulse_key` ist der **private** Schlüssel. Seinen Inhalt kopierst du in NetPulse unter Zugangsdaten → „SSH mit Schlüssel“.
- `netpulse_key.pub` ist der **öffentliche** Schlüssel. Er kommt auf die Zielgeräte (siehe unten).

---

## Linux, Raspberry Pi, Proxmox

```bash
# Benutzer ohne Passwort und ohne sudo-Rechte anlegen
sudo adduser --disabled-password --gecos "" netpulse
sudo mkdir -p /home/netpulse/.ssh
sudo nano /home/netpulse/.ssh/authorized_keys      # Inhalt von netpulse_key.pub einfügen
sudo chown -R netpulse:netpulse /home/netpulse/.ssh
sudo chmod 700 /home/netpulse/.ssh && sudo chmod 600 /home/netpulse/.ssh/authorized_keys
```

Optional, für die Zahl laufender Docker-Container: `sudo usermod -aG docker netpulse`.
Achtung: Mitglieder der Gruppe docker haben faktisch Root-Rechte, das also nur bewusst setzen.

## Synology NAS

**SNMP (einfach, empfohlen):** Systemsteuerung → Terminal & SNMP → SNMP →
„SNMPv3-Dienst aktivieren“, Benutzername und Passwörter setzen, Protokoll SHA/AES.
NetPulse liest dann Modell, DSM-Version, Temperatur, Speicherbelegung und Schnittstellen.

**SSH (mehr Details):** Systemsteuerung → Terminal & SNMP → SSH aktivieren. Einen Benutzer ohne Admin-Rechte anlegen.
Hinweis: Bei Synology dürfen sich per SSH standardmäßig nur Administratoren anmelden. Für den Alltag reicht SNMP.

## QNAP, TrueNAS, Unraid

SNMP v3 in den Systemeinstellungen aktivieren (Netzwerk-/Dienste-Bereich) oder wie bei Linux einen SSH-Benutzer anlegen.

## Windows 10/11 und Windows Server

Windows bringt einen **OpenSSH-Server** mit. NetPulse fragt Windows darüber per PowerShell/CIM ab
(Hardware, Betriebssystem, CPU, RAM, Laufwerke, Netzwerkkarten, letztes Update, gestoppte Dienste).

In einer **PowerShell als Administrator**:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
# Firewall-Regel wird normalerweise automatisch angelegt; sonst:
New-NetFirewallRule -Name sshd -DisplayName "OpenSSH Server" -Protocol TCP -LocalPort 22 -Action Allow
```

Lokales Konto für NetPulse (Standardbenutzer, **kein** Administrator):

```powershell
$pw = Read-Host -AsSecureString "Passwort für netpulse"
New-LocalUser -Name netpulse -Password $pw -PasswordNeverExpires -Description "NetPulse Monitoring (nur lesen)"
```

Schlüssel statt Passwort: Inhalt von `netpulse_key.pub` in `C:\Users\netpulse\.ssh\authorized_keys` ablegen.

In der **Firma** lässt sich das per Gruppenrichtlinie oder Intune auf alle Rechner verteilen. Vorher bitte die Hinweise zum
Betriebsrat in [DATENSCHUTZ.md](DATENSCHUTZ.md) beachten.

> **Warum SSH und nicht WinRM?** Der Windows-eigene Fernverwaltungsdienst WinRM braucht für eine sichere Verbindung
> NTLM- oder Kerberos-Verschlüsselung oder ein HTTPS-Zertifikat auf jedem Rechner. OpenSSH ist bei aktuellen
> Windows-Versionen eingebaut, sicher verschlüsselt und funktioniert mit Schlüsseln. WinRM ist für eine spätere Version geplant.

## Switches, Router, Access Points

Fast alle verwalteten Geräte (Cisco, HPE/Aruba, Ubiquiti UniFi, MikroTik, Netgear, TP-Link Omada, Zyxel, Lancom …)
unterstützen SNMP. Im Webinterface unter „SNMP“ **v3** aktivieren, Benutzer mit Leserechten, SHA-256 + AES.
NetPulse liest Schnittstellen (Status, Geschwindigkeit, Datenverkehr), CPU/RAM (falls angeboten), Modell,
Seriennummer und LLDP-Nachbarn.

- **UniFi:** Network-App → Einstellungen → System → SNMP (v3).
- **MikroTik:** `/snmp set enabled=yes` und `/snmp community` bzw. v3-Benutzer anlegen.
- **FRITZ!Box:** unterstützt **kein SNMP**. NetPulse erkennt sie trotzdem als Router und überwacht die Erreichbarkeit.
  Die Abfrage über die FRITZ!Box-Schnittstelle (TR-064) ist geplant.

## Shelly (Steckdosen, Relais, Rollladen, Energiezähler)

NetPulse erkennt Shellys automatisch (Gen1 sowie Gen2/Gen3/Gen4 „Plus/Pro/Mini“) und liest ihren **Namen**,
Schaltzustand, **Leistung (W)**, Zählerstand (kWh), Spannung, Temperatur, WLAN-Signal und verfügbare Updates.

- **Ohne Passwort am Shelly:** Es ist nichts zu tun.
- **Mit Passwort:** unter Zugangsdaten → **„HTTP / Web-Anmeldung (z. B. Shelly)“** einmal Benutzer (`admin`) und Passwort
  eintragen und **„automatisch bei allen passenden Geräten verwenden“** aktivieren. Damit gilt der Eintrag für alle Shellys.
  - Das Passwort geht nur an Geräte, die sich vorher als Shelly ausgewiesen haben.
  - Gen2 und neuer nutzen eine Digest-Anmeldung (SHA-256); das Passwort wird dabei nie im Klartext übertragen.
    Gen1-Geräte kennen nur die einfache Basic-Anmeldung, dort sichert nur das eigene WLAN die Übertragung.
  - Haben Shellys unterschiedliche Passwörter, einfach mehrere Einträge anlegen. NetPulse probiert sie der Reihe nach durch.

Die aktuelle Leistung aller Shellys zeigt das Dashboard-Widget **„Stromverbrauch“**.

## Gerätenamen

NetPulse fragt jeden gefundenen Gerätenamen aus mehreren Quellen ab (der erste Treffer zählt):
1. Name aus dem Gerät selbst (Shelly, SNMP `sysName`, SSH-Hostname)
2. **mDNS/Bonjour** (Apple, Drucker, Chromecast, Sonos, ESPHome, Shelly …)
3. **NetBIOS** (Windows-PCs, Samba)
4. DNS-Name (z. B. von der FRITZ!Box)

Ein eigener Anzeigename (Gerät → Einstellungen) hat immer Vorrang.

## Live-Ansicht und SNMP-Explorer

- **Live:** Bei Geräten mit SNMP- oder SSH-Zugang zeigt der Reiter „Live“ die Datenrate jeder Schnittstelle, aktualisiert
  alle 2 Sekunden. Die WAN-Schnittstelle von Routern und Firewalls (z. B. **OPNsense** mit dem Plugin `os-net-snmp`) wird
  über die Standardroute erkannt und im Dashboard-Widget **„Internet“** angezeigt. Falls die Erkennung nicht passt:
  Gerät → Schnittstellen → Schnittstelle anklicken → „Als Internet markieren“.
- **SNMP-Explorer:** liest beliebige Werte eines Geräts, mit Namen aus rund **4.800 MIBs** (IETF/IANA und die Hersteller-MIBs
  der LibreNMS-Sammlung, knapp 960.000 benannte Werte). Suche per OID oder Name, z. B. `ifXTable`, `unifiVapTable` oder
  `enterprises`. Die Namensliste belegt etwa 160 MB in der Datenbank.

## Drucker

Netzwerkdrucker haben SNMP meist schon aktiv (oft v1/v2c mit Community `public`). Dann reicht ein SNMP-v2c-Eintrag
mit Community `public`, am besten fest dem Drucker zugeordnet statt „automatisch“. NetPulse zeigt dann die
Füllstände von Toner, Tinte und Trommel an.

## USV (APC, Eaton, CyberPower …)

Mit Netzwerkkarte: SNMP v3 im Webinterface der Karte aktivieren. NetPulse liest Ladezustand, Restlaufzeit und
Akkuzustand und erkennt, wenn die USV auf Akkubetrieb läuft.

---

## Fehlersuche

| Meldung in NetPulse | Ursache / Lösung |
|---|---|
| „Zeitüberschreitung – Gerät antwortet nicht auf SNMP“ | SNMP aus, falsche Community/Benutzer, Firewall blockiert UDP 161 |
| „SNMPv3-Anmeldung fehlgeschlagen“ | Benutzer, Passwörter oder Protokolle (SHA/AES) stimmen nicht überein |
| „Anmeldung fehlgeschlagen“ (SSH) | Benutzer, Passwort oder Schlüssel falsch; Schlüssel in `authorized_keys`? |
| „Keine Antwort auf Port 22“ | SSH-Dienst aus oder Firewall |
| „SSH-Host-Schlüssel hat sich geändert“ | Gerät neu installiert → in der Geräteansicht „Schlüssel vergessen“. Sonst: möglicher Angriff prüfen! |
