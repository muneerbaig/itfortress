Create the launcher script (custom-misp.py  extension):

Add your misp_base_url = your ip address
Add your misp_api_auth_key=your api keys:


nano /var/ossec/integrations/custom-misp.py

#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
import json
import ipaddress
import re
import requests
import time
import urllib3

# Disable SSL warnings for self-signed MISP certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- USER CONFIGURATION ---
misp_base_url = "https://10.10.30.50/attributes/restSearch/"
misp_api_auth_key = "S8Ae7uLs2AyhOmlnEOfWrlo1b9aueWxheWel13rj"
debug_file = "/var/ossec/logs/misp_debug.log"

def debug(msg: str) -> None:
    try:
        with open(debug_file, "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {msg}\n")
    except Exception:
        pass

# Wazuh queue socket
PWD = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
SOCKET_ADDR = f"{PWD}/queue/sockets/queue"

def send_event(msg, agent=None) -> None:
    if not agent or agent.get("id") == "000":
        data = f'1:misp:{json.dumps(msg)}'
    else:
        data = '1:[{0}] ({1}) {2}->misp:{3}'.format(
            agent.get("id"), agent.get("name"), agent.get("ip", "any"), json.dumps(msg)
        )
    sock = socket(AF_UNIX, SOCK_DGRAM)
    try:
        sock.connect(SOCKET_ADDR)
        sock.send(data.encode())
    finally:
        sock.close()

# ---- Helpers to extract observables ----
def extract_hash(text: str):
    if not text: return None
    # Extracts hex strings, ignoring prefixes like SHA256= or MD5=
    m = re.search(r'([A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})', text)
    return m.group(1) if m else None

def extract_ip(text: str):
    if not text: return None
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).is_global: return ip
        except: continue
    return None

def extract_url(text: str):
    if not text: return None
    m = re.search(r"https?://[^\s\"'>]+", text)
    return m.group(0) if m else None

def misp_search(value: str):
    if not value: return None
    headers = {"Content-Type": "application/json", "Authorization": misp_api_auth_key, "Accept": "application/json"}
    search_url = f"{misp_base_url}value:{value}"
    try:
        debug(f"Querying MISP with value={value}")
        r = requests.get(search_url, headers=headers, verify=False, timeout=5)
        r.raise_for_status()
        js = r.json()
        attrs = js.get("response", {}).get("Attribute")
        if attrs:
            attr = attrs[0]
            debug(f"MATCH: {value} (Type: {attr.get('type')})")
            return attr
    except Exception as e:
        debug(f"ERROR: {e}")
    return None

def main():
    try:
        if len(sys.argv) < 2: return
        with open(sys.argv[1]) as f:
            alert = json.load(f)

        groups = alert.get("rule", {}).get("groups", [])
        event_source = alert.get("data", {}).get("win", {}).get("system", {}).get("providerName", "")
        event_type = next((g for g in groups if "sysmon_event" in g or g == "syscheck_entry_added"), "unknown")

        observables = []
        win_data = alert.get("data", {}).get("win", {}).get("eventdata", {})

        if event_type == "sysmon_event1":
            observables = [extract_url(win_data.get("commandLine")), extract_ip(win_data.get("commandLine")), extract_hash(win_data.get("hashes"))]
        elif event_type == "sysmon_event3":
            observables = [win_data.get("destinationIp")]
        elif event_type == "sysmon_event11":
            path = win_data.get("targetFilename", "")
            fname = os.path.basename(path) if path else None
            fhash = extract_hash(win_data.get("hashes", ""))
            # Try combined, then hash alone, then filename alone
            observables = [f"{fname}|{fhash}" if fname and fhash else None, fhash, fname]
        elif event_type == "sysmon_event22":
            observables = [win_data.get("queryName")]
        elif event_type in ["sysmon_event6", "sysmon_event7", "sysmon_event15"]:
            observables = [extract_hash(win_data.get("hashes"))]
        elif event_type == "syscheck_entry_added":
            syscheck = alert.get("syscheck", {})
            observables = [syscheck.get("sha256"), syscheck.get("md5"), os.path.basename(syscheck.get("path", ""))]

        for val in observables:
            if not val: continue
            attr = misp_search(val)
            if attr:
                alert_out = {
                    "misp": {
                        "event_id": attr.get("event_id"),
                        "category": attr.get("category"),
                        "type": attr.get("type"),
                        "value": attr.get("value"),
                        "source_desc": alert.get("rule", {}).get("description")
                    }
                }
                send_event(alert_out, alert.get("agent"))
                break # Stop after first match

    except Exception as e:
        debug(f"FATAL: {e}")

if __name__ == "__main__":
    main()
