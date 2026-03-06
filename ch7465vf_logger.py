#     $$$$$$\  $$\   $$\ $$$$$$$$\ $$\   $$\  $$$$$$\  $$$$$$$\ $$\    $$\ $$$$$$$$\
#    $$  __$$\ $$ |  $$ |\____$$  |$$ |  $$ |$$  __$$\ $$  ____|$$ |   $$ |$$  _____|
#    $$ /  \__|$$ |  $$ |    $$  / $$ |  $$ |$$ /  \__|$$ |     $$ |   $$ |$$ |
#    $$ |      $$$$$$$$ |   $$  /  $$$$$$$$ |$$$$$$$\  $$$$$$$\ \$$\  $$  |$$$$$\
#    $$ |      $$  __$$ |  $$  /   \_____$$ |$$  __$$\ \_____$$\ \$$\$$  / $$  __|
#    $$ |  $$\ $$ |  $$ | $$  /          $$ |$$ /  $$ |$$\   $$ | \$$$  /  $$ |
#    \$$$$$$  |$$ |  $$ |$$  /           $$ | $$$$$$  |\$$$$$$  |  \$  /   $$ |
#     \______/ \__|  \__|\__/            \__| \______/  \______/    \_/    \__|
#
#
#
#                $$\
#                $$ |
#                $$ |      $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\
#                $$ |     $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\
#                $$ |     $$ /  $$ |$$ /  $$ |$$ /  $$ |$$$$$$$$ |$$ |  \__|
#                $$ |     $$ |  $$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |
#                $$$$$$$$\\$$$$$$  |\$$$$$$$ |\$$$$$$$ |\$$$$$$$\ $$ |
#                \________|\______/  \____$$ | \____$$ | \_______|\__|
#                                   $$\   $$ |$$\   $$ |
#                                   \$$$$$$  |\$$$$$$  |
#                                    \______/  \______/

# ================================================================
#  CH7465VF LOGGER
# ================================================================
#  Autor:        Kevin Neumann
#  Version:      1.0.2
#  Beschreibung: Liest Event-Logs eines CH7465VF Kabelmodems aus
#                und speichert sie optional als CSV oder als
#                Textdatei.
#
#  Nutzung:
#      python3 CH7465VF_Logger.py
#      1 für einen Snapshot
#      2 für mehrere Snapshots über X Minuten in Y Sekunden Interval
#      3 für Logging in eine CSV-Datei über
#        X Minuten in Y Sekunden Interval
#
#      Router IP: IP-Adresse des Routers (Enter für 192.168.0.1)
#      Router Username: Benutzername des Routers
#      Router Passwort: Passwort des Routers
#
#  Erstellt:
#      2026-03-06
#  Letzte Änderung:
#      2026-03-06
#
#  Changelog:
#      v1.0.2 - IP-Adresse wird abgefragt
#      v1.0.1 - Beschreibung und Nutzung angepasst
#      v1.0  - Initiale Version / CSV Logging hinzugefügt
# ================================================================

import csv
import hashlib
import random
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
import requests
from urllib.parse import urlparse

DEFAULT_ROUTER = "http://192.168.0.1"
LOG_TIME_OFFSET_HOURS = 1
RECENT_EVENT_WINDOW_MINUTES = 15
SEEN_EVENTS_FILE = Path("router_logs/seen_events.txt")

def parse_router_log_time(time_str: str) -> datetime | None:
    try:
        dt = datetime.strptime(time_str, "%d-%m-%Y %H:%M:%S")
        dt += timedelta(hours=LOG_TIME_OFFSET_HOURS)
        return dt
    except Exception:
        return None

@dataclass
class RouterConfig:
    router: str
    username: str
    password: str
    output_dir: Path


class CH7465VF:
    def __init__(self, config: RouterConfig):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Referer": f"{self.config.router}/",
            "Origin": self.config.router,
            "X-Requested-With": "XMLHttpRequest",
        })

    def _set_cookie(self, name: str, value: str) -> None:
        host = urlparse(self.config.router).hostname
        self.session.cookies.set(name, value, domain=host, path="/")

    def login(self) -> None:
        r = self.session.get(f"{self.config.router}/common_page/login.html", timeout=10)
        r.raise_for_status()

        self._set_cookie("SID", str(random.randint(0, 2**32 - 1)))

        payload = {
            "fun": "15",
            "Username": self.config.username,
            "Password": hashlib.sha256(self.config.password.encode("utf-8")).hexdigest(),
        }

        r = self.session.post(
            f"{self.config.router}/xml/setter.xml",
            data=payload,
            headers={"Accept": "text/plain, */*; q=0.01"},
            timeout=10,
        )
        r.raise_for_status()

        if "successful" not in r.text.lower():
            raise RuntimeError(f"Login fehlgeschlagen: {r.text}")

        match = re.search(r"SID=(\d+)", r.text)
        if not match:
            raise RuntimeError(f"Keine SID im Login-Response gefunden: {r.text}")

        self._set_cookie("SID", match.group(1))

        r = self.session.post(
            f"{self.config.router}/xml/getter.xml",
            data={"fun": "3"},
            headers={"Accept": "application/xml, text/xml, */*; q=0.01"},
            timeout=10,
        )
        r.raise_for_status()

    def get_xml(self, fun: int) -> ET.Element:
        r = self.session.post(
            f"{self.config.router}/xml/getter.xml",
            data={"fun": str(fun)},
            headers={"Accept": "application/xml, text/xml, */*; q=0.01"},
            timeout=10,
        )
        r.raise_for_status()
        return ET.fromstring(r.text)

    def collect(self) -> dict[str, Any]:
        global_settings = self.get_xml(1)
        downstream = self.get_xml(10)
        upstream = self.get_xml(11)
        eventlog = self.get_xml(13)

        return {
            "timestamp_iso": datetime.now().isoformat(timespec="seconds"),
            "timestamp_human": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
            "global": parse_global_settings(global_settings),
            "downstream": parse_downstream(downstream),
            "upstream": parse_upstream(upstream),
            "eventlog": parse_eventlog(eventlog),
        }


def parse_global_settings(root: ET.Element) -> dict[str, str]:
    fields = [
        "AccessLevel",
        "SwVersion",
        "CmProvisionMode",
        "GwProvisionMode",
        "GWOperMode",
        "ConfigVenderModel",
        "OperatorId",
        "AccessDenied",
        "LockedOut",
        "title",
        "Interface",
        "MsoBandmode",
        "operStatus",
        "model_name",
    ]
    return {field: root.findtext(field, "") for field in fields}


def parse_downstream(root: ET.Element) -> list[dict[str, str]]:
    rows = []
    for ds in root.findall("downstream"):
        rows.append({
            "freq": ds.findtext("freq", ""),
            "pow": ds.findtext("pow", ""),
            "snr": ds.findtext("snr", ""),
            "mod": ds.findtext("mod", ""),
            "chid": ds.findtext("chid", ""),
            "RxMER": ds.findtext("RxMER", ""),
            "PreRs": ds.findtext("PreRs", ""),
            "PostRs": ds.findtext("PostRs", ""),
            "IsQamLocked": ds.findtext("IsQamLocked", ""),
            "IsFECLocked": ds.findtext("IsFECLocked", ""),
            "IsMpegLocked": ds.findtext("IsMpegLocked", ""),
        })
    return rows


def parse_upstream(root: ET.Element) -> list[dict[str, str]]:
    rows = []
    for us in root.findall("upstream"):
        rows.append({
            "usid": us.findtext("usid", ""),
            "freq": us.findtext("freq", ""),
            "power": us.findtext("power", ""),
            "srate": us.findtext("srate", ""),
            "mod": us.findtext("mod", ""),
            "t1Timeouts": us.findtext("t1Timeouts", ""),
            "t2Timeouts": us.findtext("t2Timeouts", ""),
            "t3Timeouts": us.findtext("t3Timeouts", ""),
            "t4Timeouts": us.findtext("t4Timeouts", ""),
            "messageType": us.findtext("messageType", ""),
        })
    return rows


def parse_eventlog(root: ET.Element) -> list[dict[str, str]]:
    rows = []
    for ev in root.findall("eventlog"):
        rows.append({
            "prior": ev.findtext("prior", ""),
            "text": ev.findtext("text", ""),
            "time": ev.findtext("time", ""),
            "t": ev.findtext("t", ""),
        })

    rows.sort(key=lambda x: int(x["t"]) if x["t"].isdigit() else 0, reverse=True)
    return rows


def mean_int(values: list[str]) -> float:
    nums = [int(v) for v in values if v not in ("", None)]
    return round(sum(nums) / len(nums), 2) if nums else 0.0


def snapshot_to_text(data: dict[str, Any]) -> str:
    g = data["global"]
    ds = data["downstream"]
    us = data["upstream"]
    ev = data["eventlog"]
    health = build_health_summary(data)

    lines = []
    lines.append(f"Router Snapshot - {data['timestamp_human']}")
    lines.append("=" * 72)
    lines.append("")

    lines.append("HEALTH CHECK")
    lines.append("-" * 72)
    lines.append(f"Overall Status      : {health['status']}")
    lines.append(f"Downstream Avg Pow  : {health['avg_ds_power']} dBmV")
    lines.append(f"Downstream Avg SNR  : {health['avg_ds_snr']} dB")
    lines.append(f"T3 Total            : {health['total_t3']}")
    lines.append(f"T4 Total            : {health['total_t4']}")
    if health["reasons"]:
        lines.append("Reasons             :")
        for reason in health["reasons"]:
            lines.append(f"  - {reason}")
    else:
        lines.append("Reasons             : Keine Auffälligkeiten")
    lines.append("")

    lines.append("GLOBAL")
    lines.append("-" * 72)
    for key, value in g.items():
        lines.append(f"{key:18}: {value}")
    lines.append("")

    lines.append("DOWNSTREAM SUMMARY")
    lines.append("-" * 72)
    lines.append(f"Channels           : {len(ds)}")
    lines.append(f"Average Power      : {mean_int([row['pow'] for row in ds])} dBmV")
    lines.append(f"Average SNR        : {mean_int([row['snr'] for row in ds])} dB")
    lines.append("")

    for i, row in enumerate(ds, start=1):
        lines.append(
            f"DS {i:02d} | CH {row['chid']:>2} | "
            f"{row['freq']:>9} Hz | Pow {row['pow']:>3} | "
            f"SNR {row['snr']:>2} | Mod {row['mod']}"
        )
    lines.append("")

    lines.append("UPSTREAM SUMMARY")
    lines.append("-" * 72)
    lines.append(f"Channels           : {len(us)}")
    lines.append(f"Average Power      : {mean_int([row['power'] for row in us])} dBmV")
    lines.append("")

    for i, row in enumerate(us, start=1):
        lines.append(
            f"US {i:02d} | USID {row['usid']:>2} | "
            f"{row['freq']:>8} Hz | Pow {row['power']:>2} | "
            f"Mod {row['mod']:<6} | T3 {row['t3Timeouts']} | T4 {row['t4Timeouts']}"
        )
    lines.append("")

    lines.append("EVENT LOG (latest first)")
    lines.append("-" * 72)
    for row in ev[:20]:
        lines.append(f"[{row['prior']:<8}] {row['time']} | {row['text']}")
    lines.append("")

    return "\n".join(lines)


def flatten_for_csv(data: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "timestamp_iso": data["timestamp_iso"],
        "timestamp_human": data["timestamp_human"],
    }

    for key, value in data["global"].items():
        row[f"global_{key}"] = value

    downstream = data["downstream"]
    upstream = data["upstream"]
    events = data["eventlog"]

    row["downstream_count"] = len(downstream)
    row["downstream_avg_power"] = mean_int([d["pow"] for d in downstream])
    row["downstream_avg_snr"] = mean_int([d["snr"] for d in downstream])

    row["upstream_count"] = len(upstream)
    row["upstream_avg_power"] = mean_int([u["power"] for u in upstream])
    row["upstream_total_t3"] = sum(int(u["t3Timeouts"] or 0) for u in upstream)
    row["upstream_total_t4"] = sum(int(u["t4Timeouts"] or 0) for u in upstream)
    row["upstream_mods"] = "|".join(u["mod"] for u in upstream)

    for idx, us in enumerate(upstream, start=1):
        row[f"us{idx}_usid"] = us["usid"]
        row[f"us{idx}_freq"] = us["freq"]
        row[f"us{idx}_power"] = us["power"]
        row[f"us{idx}_mod"] = us["mod"]
        row[f"us{idx}_t3"] = us["t3Timeouts"]
        row[f"us{idx}_t4"] = us["t4Timeouts"]

    health = build_health_summary(data)
    row["health_status"] = health["status"]
    row["health_reasons"] = " | ".join(health["reasons"])
    row["bad_upstream_mods"] = "|".join(
        f"USID {u['usid']}={u['mod']}"
        for u in upstream
        if u["mod"].lower() != "64qam"
    )

    critical_events = [e for e in events if is_critical_event(e)]
    row["event_count"] = len(events)
    row["critical_event_count"] = len(critical_events)
    row["latest_event_time"] = events[0]["time"] if events else ""
    row["latest_event_prior"] = events[0]["prior"] if events else ""
    row["latest_event_text"] = events[0]["text"] if events else ""

    row["relevant_event_count"] = len(events)
    row["relevant_critical_event_count"] = len(critical_events)
    row["latest_relevant_event_time"] = events[0]["time"] if events else ""
    row["latest_relevant_event_text"] = events[0]["text"] if events else ""

    return row

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_snapshot_text(output_dir: Path, data: dict[str, Any]) -> Path:
    ensure_dir(output_dir)
    filename = f"snapshot_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
    target = output_dir / filename
    target.write_text(snapshot_to_text(data), encoding="utf-8")
    return target


def append_csv(csv_path: Path, row: dict[str, Any]) -> None:
    ensure_dir(csv_path.parent)
    file_exists = csv_path.exists()

    with csv_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def run_snapshot(modem: CH7465VF, output_dir: Path) -> None:
    modem.login()
    data = modem.collect()
    seen_events = load_seen_events(SEEN_EVENTS_FILE)
    now = datetime.now()

    relevant_events, updated_seen = filter_relevant_events(
        data["eventlog"],
        seen_events,
        now,
    )

    data["eventlog"] = relevant_events
    save_seen_events(SEEN_EVENTS_FILE, updated_seen)
    path = write_snapshot_text(output_dir, data)
    print(f"Snapshot gespeichert: {path}")


def run_watch_text(modem: CH7465VF, output_dir: Path, duration_minutes: int, interval_seconds: int) -> None:
    modem.login()
    end_time = time.time() + duration_minutes * 60
    seen_events = load_seen_events(SEEN_EVENTS_FILE)

    while time.time() <= end_time:
        data = modem.collect()
        now = datetime.now()

        relevant_events, updated_seen = filter_relevant_events(
            data["eventlog"],
            seen_events,
            now,
        )

        data["eventlog"] = relevant_events
        seen_events = updated_seen
        save_seen_events(SEEN_EVENTS_FILE, updated_seen)

        path = write_snapshot_text(output_dir, data)
        print(f"[{data['timestamp_human']}] Snapshot gespeichert: {path}")

        if time.time() + interval_seconds > end_time:
            break
        time.sleep(interval_seconds)


def run_watch_csv(modem: CH7465VF, output_dir: Path, duration_minutes: int, interval_seconds: int) -> None:
    modem.login()
    csv_path = output_dir / f"log_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    end_time = time.time() + duration_minutes * 60
    seen_events = load_seen_events(SEEN_EVENTS_FILE)

    while time.time() <= end_time:
        data = modem.collect()
        now = datetime.now()

        relevant_events, updated_seen = filter_relevant_events(
            data["eventlog"],
            seen_events,
            now,
        )

        data["eventlog"] = relevant_events
        seen_events = updated_seen
        save_seen_events(SEEN_EVENTS_FILE, updated_seen)

        row = flatten_for_csv(data)
        append_csv(csv_path, row)
        print(f"[{data['timestamp_human']}] CSV-Zeile geschrieben: {csv_path}")

        if time.time() + interval_seconds > end_time:
            break
        time.sleep(interval_seconds)


def main():
    print("\nRouter Logging Tool")
    print("===================")
    print("1) Snapshot erstellen")
    print("2) Mehrere Snapshots (Text)")
    print("3) Logging (CSV)")
    print("")

    choice = input("Auswahl (1/2/3): ").strip()

    router_ip = input(f"Router IP (Default {DEFAULT_ROUTER}): ").strip()

    if not router_ip:
        router = DEFAULT_ROUTER
    else:
        if not router_ip.startswith("http"):
            router = f"http://{router_ip}"
        else:
            router = router_ip

    username = input("Router Username: ").strip()
    password = input("Router Passwort: ").strip()

    print(f"\nVerbinde mit Router: {router}\n")

    config = RouterConfig(
        router=router,
        username=username,
        password=password,
        output_dir=Path("router_logs"),
    )

    modem = CH7465VF(config)

    if choice == "1":
        print("\nErstelle Snapshot...")
        run_snapshot(modem, config.output_dir)

    elif choice == "2":
        minutes = int(input("Wie viele Minuten loggen?: "))
        interval = int(input("Intervall in Sekunden?: "))
        print("\nStarte Snapshot-Serie...")
        run_watch_text(modem, config.output_dir, minutes, interval)

    elif choice == "3":
        minutes = int(input("Wie viele Minuten loggen?: "))
        interval = int(input("Intervall in Sekunden?: "))
        print("\nStarte CSV Logging...")
        run_watch_csv(modem, config.output_dir, minutes, interval)

    else:
        print("Ungültige Auswahl.")

def build_health_summary(data: dict[str, Any]) -> dict[str, Any]:
    ds = data["downstream"]
    us = data["upstream"]
    ev = data["eventlog"]

    reasons = []
    status = "OK"

    # Downstream prüfen
    avg_ds_snr = mean_int([row["snr"] for row in ds])
    avg_ds_power = mean_int([row["pow"] for row in ds])

    if avg_ds_snr < 35:
        status = "WARN"
        reasons.append(f"Downstream SNR niedrig ({avg_ds_snr} dB)")

    if avg_ds_power < -8 or avg_ds_power > 8:
        status = "WARN"
        reasons.append(f"Downstream Power auffällig ({avg_ds_power} dBmV)")

    # Upstream prüfen
    bad_mods = [f"USID {row['usid']}={row['mod']}" for row in us if row["mod"].lower() != "64qam"]
    total_t3 = sum(int(row["t3Timeouts"] or 0) for row in us)
    total_t4 = sum(int(row["t4Timeouts"] or 0) for row in us)

    if bad_mods:
        status = "WARN" if status == "OK" else status
        reasons.append("Upstream Modulation degradiert: " + ", ".join(bad_mods))

    if total_t3 > 0:
        status = "BAD" if total_t3 >= 3 else "WARN"
        reasons.append(f"T3-Timeouts gesamt: {total_t3}")

    if total_t4 > 0:
        status = "BAD"
        reasons.append(f"T4-Timeouts gesamt: {total_t4}")

    # Eventlog prüfen
    critical_hits = [
        e for e in ev
        if "T3 time-out" in e["text"]
        or "No Ranging Response" in e["text"]
        or "DHCP failed" in e["text"]
        or "Primary lease failed" in e["text"]
    ]

    if critical_hits:
        status = "BAD"
        reasons.append(f"Kritische Eventlog-Treffer: {len(critical_hits)}")

    return {
        "status": status,
        "avg_ds_snr": avg_ds_snr,
        "avg_ds_power": avg_ds_power,
        "total_t3": total_t3,
        "total_t4": total_t4,
        "reasons": reasons,
    }

def load_seen_events(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return set(path.read_text(encoding="utf-8").splitlines())

def save_seen_events(path: Path, seen: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(sorted(seen)), encoding="utf-8")

def event_fingerprint(event: dict[str, str]) -> str:
    return f"{event.get('t', '')}|{event.get('time', '')}|{event.get('text', '')}"

def filter_relevant_events(
    events: list[dict[str, str]],
    seen_events: set[str],
    now: datetime,
) -> tuple[list[dict[str, str]], set[str]]:
    relevant = []
    updated_seen = set(seen_events)

    for event in events:
        fp = event_fingerprint(event)
        event_dt = parse_router_log_time(event.get("time", ""))

        is_new = fp not in seen_events
        is_recent = False

        if event_dt is not None:
            age = now - event_dt
            is_recent = age <= timedelta(minutes=RECENT_EVENT_WINDOW_MINUTES)

        if is_new or is_recent:
            relevant.append(event)

        updated_seen.add(fp)

    return relevant, updated_seen

def is_critical_event(event: dict[str, str]) -> bool:
    text = event.get("text", "")
    return (
        "T3 time-out" in text
        or "No Ranging Response" in text
        or "DHCP failed" in text
        or "Primary lease failed" in text
    )

if __name__ == "__main__":
    main()