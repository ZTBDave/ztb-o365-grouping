#!/usr/bin/env python3
"""
ZTB Microsoft 365 Object & Security Policy Automation
Compatible with Mike Dechow's ztb-objects-bulk repository pattern.

Fetches O365 IPs, FQDNs, and Ports from Microsoft's web service / Learn pages,
generates pipe-delimited CSVs for bulk ingestion, and uses ZTB REST APIs to
provision Network Objects and Security Policies.
"""

import os
import re
import csv
import json
import uuid
import ipaddress
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

# ==============================================================================
# CONFIGURATION
# ==============================================================================
# Read strictly from exported environment variables (no placeholder fallback)
ZTB_BASE_URL = os.getenv("ZTB_BASE_URL")
if not ZTB_BASE_URL:
    raise ValueError(
        "Missing required environment variable: ZTB_BASE_URL is not set.\n"
        "Export it in your shell or .env: export ZTB_BASE_URL='https://<tenant>-api.goairgap.com'"
    )
ZTB_BASE_URL = ZTB_BASE_URL.rstrip("/")
ZTB_UI_ORIGIN = ZTB_BASE_URL.replace("-api.", ".")

ZTB_API_KEY = os.getenv("ZTB_API_KEY")
if not ZTB_API_KEY:
    raise ValueError(
        "Missing required environment variable: ZTB_API_KEY is not set.\n"
        "Export it in your shell or .env: export ZTB_API_KEY='<your_api_key>'"
    )

# Site and Group settings
# If ZTB_SITE_ID is unset or left as placeholder, security policies default to 'global' (site_id=None)
SITE_ID = os.getenv("ZTB_SITE_ID")
if SITE_ID in ("", "YOUR_SITE_UUID"):
    SITE_ID = None

SRC_GROUP_ID = int(os.getenv("ZTB_SRC_GROUP_ID", "2"))  # 2 = System-All-Networks-Group ("ZTB Network")

MS_LEARN_URL = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges?view=o365-worldwide"
MS_WEB_SERVICE_URL = "https://endpoints.office.com/endpoints/worldwide"


# ==============================================================================
# 1. PARSING & EXTRACTION HELPERS
# ==============================================================================
def normalize_ipv4_cidr(ip_str: str) -> str | None:
    """
    Validates IPv4 network string and guarantees CIDR notation (/32 for single hosts).
    Crucial for ZTB: API stores raw strings; missing mask causes silent match failure.
    """
    ip_str = ip_str.strip()
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            return f"{net.network_address}/{net.prefixlen}"
    except ValueError:
        pass
    return None


def normalize_fqdn(raw: str) -> str | None:
    """
    Normalizes Microsoft URLs/FQDNs to comply with ZTB FQDN validation rules:
    - Replaces patterns like '*xxx.yyy.zzz' with '*.yyy.zzz' (wildcarding the entire first word).
    - Strips http://, https://, URL paths, and port suffixes.
    - Discards invalid characters or internal wildcards (e.g. foo.*.com).
    """
    cleaned = raw.strip().lower()
    if cleaned.startswith("http://"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("https://"):
        cleaned = cleaned[8:]
    cleaned = cleaned.split("/")[0].split(":")[0].strip()

    if not cleaned or "." not in cleaned:
        return None

    # Replace *xxx.yyy.zzz with *.yyy.zzz (effectively wildcard the entire first word)
    if cleaned.startswith("*") and not cleaned.startswith("*."):
        cleaned = re.sub(r"^\*[^.]+\.", "*.", cleaned)

    # Discard if internal wildcard exists (e.g. foo.*.com) or invalid
    if cleaned.count("*") > 1 or ("*" in cleaned and not cleaned.startswith("*.")):
        return None

    return cleaned


def fetch_o365_endpoints(categories=("Optimize", "Allow"), include_required=True) -> dict:
    """
    Fetches official Microsoft endpoints JSON feed with fallback to HTML parsing.
    Extracts all endpoints marked as 'Required' as well as endpoints in Optimize and Allow categories.
    """
    client_req_id = str(uuid.uuid4())
    url = f"{MS_WEB_SERVICE_URL}?clientRequestId={client_req_id}"
    print(f"[*] Querying Microsoft Web Service API: {url}")

    ipv4_set, fqdn_set, tcp_ports, udp_ports = set(), set(), set(), set()

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        records = resp.json()

        for ep in records:
            is_req = ep.get("required", False) is True
            is_cat = ep.get("category") in categories if categories else False

            # Include if marked as required OR belongs to specified categories (Optimize / Allow)
            if include_required:
                if not (is_req or is_cat):
                    continue
            else:
                if categories and not is_cat:
                    continue

            for ip in ep.get("ips", []):
                cidr = normalize_ipv4_cidr(ip)
                if cidr:
                    ipv4_set.add(cidr)

            for url_entry in ep.get("urls", []):
                norm = normalize_fqdn(url_entry)
                if norm:
                    fqdn_set.add(norm)

            if ep.get("tcpPorts"):
                for p in ep["tcpPorts"].split(","):
                    p = p.strip()
                    if p:
                        tcp_ports.add(p)

            if ep.get("udpPorts"):
                for p in ep["udpPorts"].split(","):
                    p = p.strip()
                    if p:
                        udp_ports.add(p)

    except Exception as e:
        print(f"[!] Web service API query failed ({e}). Falling back to HTML scraping...")
        h_resp = requests.get(MS_LEARN_URL, timeout=30)
        h_resp.raise_for_status()
        soup = BeautifulSoup(h_resp.text, "html.parser")

        for table in soup.find_all("table"):
            headers = [th.get_text(strip=True).lower() for th in table.find_all("th")]
            if "id" not in headers:
                continue
            col_map = {h: idx for idx, h in enumerate(headers)}

            for row in table.find_all("tr")[1:]:
                cells = row.find_all(["td", "th"])
                if len(cells) < len(headers):
                    continue

                req_val = cells[col_map.get("required", -1)].get_text(strip=True).lower() if "required" in col_map else ""
                is_req = req_val in ("yes", "true", "required")

                cat_val = cells[col_map.get("category", -1)].get_text(strip=True).lower() if "category" in col_map else ""
                is_cat = any(c.lower() in cat_val for c in categories) if categories else False

                if include_required:
                    if not (is_req or is_cat):
                        continue
                else:
                    if categories and not is_cat:
                        continue

                addr_text = cells[col_map.get("addresses", -1)].get_text(" ", strip=True)
                for token in re.split(r"[\s,;]+", addr_text):
                    cidr = normalize_ipv4_cidr(token)
                    if cidr:
                        ipv4_set.add(cidr)
                    elif ":" not in token and "." in token:
                        norm = normalize_fqdn(token)
                        if norm:
                            fqdn_set.add(norm)

                ports_text = cells[col_map.get("ports", -1)].get_text(" ", strip=True)
                t_match = re.search(r"TCP:\s*([0-9,\-\s]+)", ports_text, re.I)
                u_match = re.search(r"UDP:\s*([0-9,\-\s]+)", ports_text, re.I)
                if t_match:
                    for p in re.split(r"[\s,]+", t_match.group(1).strip()):
                        if p:
                            tcp_ports.add(p)
                if u_match:
                    for p in re.split(r"[\s,]+", u_match.group(1).strip()):
                        if p:
                            udp_ports.add(p)

    return {
        "ips": sorted(ipv4_set),
        "fqdns": sorted(fqdn_set),
        "tcp_ports": sorted(tcp_ports),
        "udp_ports": sorted(udp_ports),
    }


# ==============================================================================
# 2. EXPORT COMPATIBILITY FOR ztb-objects-bulk (CSV EXPORT)
# ==============================================================================
def export_pipe_delimited_csv(filename: str, objects: list[dict]):
    """
    Exports objects using the pipe (|) delimiter required by ZTB CSV ingestion
    and Mike Dechow's ztb-objects-bulk ingestion format.
    Format: Name|Type|Values
    """
    print(f"[*] Exporting bulk object file to {filename} (pipe-delimited)...")
    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter="|")
        writer.writerow(["name", "type", "values"])
        for obj in objects:
            writer.writerow([obj["name"], obj["type"], ",".join(obj["values"])])
    print(f"[+] Successfully wrote {len(objects)} object rows to {filename}.")


# ==============================================================================
# 3. ZTB REST API CLIENT
# ==============================================================================
class ZTBClient:
    def __init__(self, api_base: str, api_key: str, ui_origin: str):
        self.api_base = api_base
        self.api_key = api_key
        self.ui_origin = ui_origin
        self.session = requests.Session()
        self.token = None

    def authenticate(self):
        """Exchange API Key for Bearer delegate token and set headers."""
        auth_url = f"{self.api_base}/api/v3/api-key-auth/login"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": self.ui_origin,
            "Referer": f"{self.ui_origin}/",
            "X-Requested-With": "XMLHttpRequest",
        }
        try:
            resp = self.session.post(auth_url, json={"api_key": self.api_key}, headers=headers, timeout=15)
            if resp.status_code >= 400:
                print(f"[!] Auth Failed ({resp.status_code}): {resp.text}")
            resp.raise_for_status()
        except requests.exceptions.ConnectionError:
            print(f"\n[!] Connection Error: Unable to resolve or connect to '{self.api_base}'.")
            print("    Please check that ZTB_BASE_URL points to your live tenant API endpoint")
            print("    (e.g., https://<tenant>-api.goairgap.com) and that DNS resolution works.\n")
            raise SystemExit(1) from None
        except requests.exceptions.HTTPError as exc:
            print(f"\n[!] Authentication HTTP Error ({exc.response.status_code}): {exc.response.text}\n")
            raise SystemExit(1) from None

        data = resp.json()
        self.token = data.get("result", {}).get("delegate_token") or data.get("delegate_token")
        if not self.token:
            raise RuntimeError(f"Missing delegate_token in response: {data}")

        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": self.ui_origin,
            "Referer": f"{self.ui_origin}/",
            "X-Requested-With": "XMLHttpRequest",
        })
        print("[+] Authenticated to ZTB Management API.")

    def upsert_group(self, name: str, group_type: str, member_attributes: dict) -> int:
        """Create or update group object via /api/v2/groups."""
        get_url = f"{self.api_base}/api/v2/groups"
        params = {"group_type": group_type, "group_owner": "user", "size": 500, "page": 0}
        resp = self.session.get(get_url, params=params, timeout=20)
        resp.raise_for_status()

        groups_list = resp.json().get("result", resp.json() if isinstance(resp.json(), list) else [])
        existing_id = None
        for g in groups_list:
            if g.get("name") == name or g.get("display_name") == name:
                existing_id = g.get("group_id")
                break

        payload = {
            "name": name,
            "display_name": name,
            "type": group_type,
            "autonomous": False,
            "hidden": False,
            "owner": "user",
            "member_attributes": member_attributes,
        }

        if existing_id:
            print(f"[*] Updating existing {group_type} '{name}' (ID: {existing_id})...")
            url = f"{self.api_base}/api/v2/groups/{existing_id}?refresh_token=enabled"
            r = self.session.put(url, json=payload, timeout=30)
            if r.status_code >= 400:
                print(f"[!] Group update error ({r.status_code}): {r.text}")
            r.raise_for_status()
            return existing_id
        else:
            print(f"[*] Creating new {group_type} '{name}'...")
            url = f"{self.api_base}/api/v2/groups?refresh_token=enabled"
            r = self.session.post(url, json=payload, timeout=30)
            if r.status_code >= 400:
                print(f"[!] Group creation error ({r.status_code}): {r.text}")
            r.raise_for_status()
            res_data = r.json().get("result", r.json())
            group_id = res_data.get("group_id")
            print(f"[+] Created object '{name}' (ID: {group_id}).")
            return group_id

    def get_security_policies(self, policy_type: str = "global", site_id: str | None = None) -> list[dict]:
        """Queries existing security policies to detect duplicates and conflicts."""
        url = f"{self.api_base}/api/v2/group-policies"
        params = {"type": policy_type, "size": 500, "page": 0}
        if site_id:
            params["site_id"] = site_id
            params["type"] = "user"
        try:
            resp = self.session.get(url, params=params, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                return data
            return data.get("result", [])
        except Exception as e:
            print(f"[!] Note: Could not query existing policies ({e}). Proceeding...")
            return []

    def create_security_policy(
        self,
        name: str,
        src_ids: list[int],
        dst_ids: list[int],
        port_group_id: int,
        site_id: str | None = None,
        sequence_number: int = 1,
    ):
        """
        Upserts security policy with duplicate detection and conflict avoidance.
        If a policy with the same name exists, it updates it via PUT /api/v2/group-policies/{id};
        otherwise it creates it via POST /api/v2/group-policies/bulk.
        """
        actual_site_id = site_id if (site_id and site_id != "YOUR_SITE_UUID") else None
        policy_type = "user" if actual_site_id else "global"

        # 1. Detection: check if a policy with this name already exists
        existing_list = self.get_security_policies(policy_type=policy_type, site_id=actual_site_id)
        existing_policy = None
        for item in existing_list:
            p_data = item.get("policy", item)
            if p_data.get("name") == name or p_data.get("display_name") == name:
                existing_policy = p_data
                break

        policy_payload = {
            "sequence_number": existing_policy.get("sequence_number", sequence_number) if existing_policy else sequence_number,
            "name": name,
            "display_name": name,
            "src_group_negate": False,
            "src_group_id_set": src_ids,
            "dst_group_id_set": dst_ids,
            "dst_group_negate": False,
            "action": "accept",
            "site_id": actual_site_id,
            "dst_port_group_id": port_group_id,
            "dst_port_group_negate": False,
            "ts_group_id": 0,
            "type": policy_type,
            "log_enabled": True,
            "rks": {
                "green": True,
                "yellow": True,
                "orange": True,
                "red": True,
            },
        }

        # 2. Avoidance & Update: if policy exists, update via PUT
        if existing_policy:
            pol_id = existing_policy.get("policy_id") or existing_policy.get("id")
            print(f"[*] Policy '{name}' already exists (ID: {pol_id}). Updating policy criteria...")
            put_url = f"{self.api_base}/api/v2/group-policies/{pol_id}?refresh_token=enabled"
            r = self.session.put(put_url, json=policy_payload, timeout=30)
            if r.status_code >= 400:
                print(f"[!] Policy update warning ({r.status_code}): {r.text}")
                print(f"[+] Reusing existing policy '{name}'. Referenced network/port objects have been refreshed.")
                return existing_policy
            print(f"[+] Successfully updated Security Policy '{name}' (ID: {pol_id}).")
            return r.json()

        # 3. Creation: create new policy if not found
        url = f"{self.api_base}/api/v2/group-policies/bulk"
        payload = [policy_payload]
        print(f"[*] Creating Security Policy '{name}' (Scope: {policy_type}, Site: {actual_site_id})...")
        r = self.session.post(url, json=payload, timeout=30)
        if r.status_code == 409:
            print(f"[*] Policy '{name}' already exists (409 Conflict handled). Referenced objects are updated.")
            return {"status": "already_exists", "name": name}
        if r.status_code >= 400:
            print(f"[!] Security Policy creation error ({r.status_code}) on {url}:")
            print(f"    Server response payload: {r.text}")
        r.raise_for_status()
        print(f"[+] Security Policy '{name}' established.")
        return r.json()


# ==============================================================================
# MAIN EXECUTION ROUTINE
# ==============================================================================
def main():
    # 1. Fetch Microsoft Endpoints (Include all Required endpoints, plus Optimize & Allow categories)
    o365 = fetch_o365_endpoints(categories=("Optimize", "Allow"), include_required=True)
    print(f"[+] Extracted: {len(o365['ips'])} CIDRs, {len(o365['fqdns'])} FQDNs, "
          f"{len(o365['tcp_ports'])} TCP ports, {len(o365['udp_ports'])} UDP ports.")

    # 2. Export pipe-delimited CSV for Mike Dechow's ztb-objects-bulk pattern
    bulk_objects = [
        {"name": "O365-Required-IPs", "type": "network", "values": o365["ips"]},
        {"name": "O365-Required-FQDNs", "type": "network", "values": o365["fqdns"]},
    ]
    export_pipe_delimited_csv("ztb_o365_network_objects.csv", bulk_objects)

    # 3. Direct ZTB REST API Execution
    ztb = ZTBClient(ZTB_BASE_URL, ZTB_API_KEY, ZTB_UI_ORIGIN)
    ztb.authenticate()

    # Create IP Network Object
    ip_group_id = ztb.upsert_group(
        name="O365-Required-IPs",
        group_type="network",
        member_attributes={
            "ip_prefix": o365["ips"],
            "ip_prefix_local": o365["ips"],
            "fqdn": [],
            "fqdn_local": [],
        },
    )

    # Create FQDN Network Object
    fqdn_group_id = ztb.upsert_group(
        name="O365-Required-FQDNs",
        group_type="network",
        member_attributes={
            "ip_prefix": [],
            "ip_prefix_local": [],
            "fqdn": o365["fqdns"],
            "fqdn_local": o365["fqdns"],
        },
    )

    # Create L4 Port Object
    port_entries = []
    if o365["tcp_ports"]:
        port_entries.append(f"tcp:{','.join(o365['tcp_ports'])}")
    if o365["udp_ports"]:
        port_entries.append(f"udp:{','.join(o365['udp_ports'])}")

    port_group_id = ztb.upsert_group(
        name="O365-Required-Ports",
        group_type="l4port",
        member_attributes={"port_group": port_entries},
    )

    # 4. Provision Security Policy (Upsert with conflict avoidance)
    ztb.create_security_policy(
        name="Allow-O365-Direct",
        src_ids=[SRC_GROUP_ID],
        dst_ids=[ip_group_id, fqdn_group_id],
        port_group_id=port_group_id,
        site_id=SITE_ID,
    )


if __name__ == "__main__":
    main()
