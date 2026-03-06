# CH7465VF Logger
Ein kleines Python-Tool zum Extrahieren von Diagnosedaten und Ereignisprotokollen aus dem Technicolor **CH7465VF** Kabelmodem/Router.
Das Tool kann Momentaufnahmen des Modemstatus erstellen, Protokolle über einen bestimmten Zeitraum überwachen und Diagnosedaten zur späteren Analyse in das CSV-Format exportieren.

---

## Funktionen

- Momentaufnahmen des Routerstatus
- Downstream-/Upstream-Kanalstatistiken
- Extraktion von Ereignisprotokollen
- Kontinuierliche Überwachung
- CSV-Export zur Analyse
- Einfache Überprüfung der Verbindungsqualität

---

## Anforderungen

- Python 3.10+
- Python-Modul: requests (pip install requests)

---

## Nutzung

Script mittels "python3 ch7465vf_logger.py" ausführen.


Du wirst nach folgenden Angaben gefragt:

- Router-IP (Standard: `192.168.0.1`)
- Benutzername des Routers
- Passwort des Routers

Wähle dann einen der folgenden Modi:

### 1 – Snapshot
Erstellt einen einzelnen Snapshot des Routerstatus und speichert ihn als Textdatei.

### 2 – Mehrere Snapshots
Erstellt mehrere Text-Snapshots über einen bestimmten Zeitraum.

Du wirst nach folgenden Angaben gefragt:

- Protokollierungsdauer (Minuten)
- Intervall (Sekunden)

### 3 – CSV-Protokollierung
Protokolliert kontinuierlich Routerstatistiken in einer CSV-Datei.

Nützlich für die Analyse der Verbindungsstabilität, der Signalstärke
oder von Paketverlustproblemen im Zeitverlauf.

Du wirst nach folgenden Angaben gefragt:

- Protokollierungsdauer (Minuten)
- Intervall (Sekunden)

---

## Ausgabe

Alle Protokolle werden in den folgenden Ordner geschrieben: router_logs/
Beispiele für die Ausgaben sind: snapshot_2026-03-06_20-12-55.txt oder log_2026-03-06_20-12-55.csv

## Gesundheitscheck
Das Tool bewertet die Verbindungsqualität anhand folgender Kriterien:

- Downstream-SNR
- Downstream-Leistungspegel
- Upstream-Modulation
- T3-/T4-Timeouts
- Kritische DOCSIS-Protokollereignisse

Die Snapshot-Ausgabe zeigt einen einfachen Status an: OK / WARN / BAD


---

## Getestete Hardware

Technicolor **CH7465VF**

Das Skript basiert auf der internen XML-Schnittstelle der Router-Firmware.
Die Kompatibilität mit anderen Geräten kann nicht garantiert werden.

---

## Haftungsausschluss

Dieses Tool greift auf die interne Diagnoseschnittstelle des Routers zu.
Es **ändert keine Routerkonfiguration**.

Die Verwendung erfolgt auf eigene Gefahr.

---

## Lizenz
MIT-Lizenz

Copyright (c) 2026 Kevin Neumann

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
