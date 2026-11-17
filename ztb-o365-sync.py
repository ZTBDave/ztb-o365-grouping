#!/usr/bin/env python3
"""
Zscaler Zero Trust Branch (ZTB) - Microsoft 365 Category & Umbrella Group Sync
==============================================================================
Synchronizes Microsoft 365 endpoints into dedicated category child groups
(Exchange, SharePoint, Skype/Teams, Common) and nests them into Master Umbrella
FQDN and IP groups. The master groups reference ONLY child member groups, 
with zero direct/duplicate leaf entries.
"""

import os
import re
import sys
import uuid
import ipaddress
import requests

# ==============================================================================
# CONFIGURATION & ENVIRONMENT VALIDATION
# ==============================================================================
ZTB_BASE_URL = os.environ.get("ZTB_BASE_URL")
if not ZTB_BASE_URL:
    raise ValueError(
        "Missing required environment variable: ZTB_BASE_URL.\n"
        "Export it: export ZTB_BASE_URL='https://<tenant>-api.goairgap.com'"
    )
ZTB_BASE_URL = ZTB_BASE_URL.rstrip("/")
ZTB_UI_ORIGIN = os.environ.get("ZTB_UI_ORIGIN", ZTB_BASE_URL.replace("-api.", "."))

ZTB_API_KEY = os.environ.get("ZTB_API_KEY")
if not ZTB_API_KEY:
    raise ValueError(
        "Missing required environment variable: ZTB_API_KEY.\n"
        "Export it: export ZTB_API_KEY='<your_api_key>'"
    )

MS_WEB_SERVICE_URL = "https://endpoints.office.com/endpoints/worldwide"

SERVICE_AREAS = {
    "Exchange": "O365-Exchange",
    "SharePoint": "O365-SharePoint",
    "Skype": "O365-Teams-Skype",
    "Common": "O365-Common",
}

MASTER_FQDN_GROUP_NAME = "O365-Master-FQDN-Group"
MASTER_IP_GROUP_NAME = "O365-Master-IP-Group"


# ==============================================================================
# 1. PARSING & SANITIZATION HELPERS
# ==============================================================================
def normalize_ipv4_cidr(ip_str: str) -> str | None:
    """Validates IPv4 network string and guarantees strict CIDR notation (/32 for hosts)."""
    ip_str = ip_str.strip()
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            return f"{net.network_address}/{net.prefixlen}"
    except ValueError:
        pass
    return None


def normalize_fqdn(raw: str) -> str | None:
    """Normalizes Microsoft URLs/FQDNs to comply with ZTB regex rules."""
    cleaned = raw.strip().lower()
    if cleaned.startswith("http://"):
        cleaned = cleaned[7:]
    elif cleaned.startswith("https://"):
        cleaned = cleaned[8:]
    cleaned = cleaned.split("/")[0].split(":")[0].strip()

    if not cleaned or "." not in cleaned:
        return None

    if cleaned.startswith("*") and not cleaned.startswith("*."):
        cleaned = re.sub(r"^\*[^.]+\.", "*.", cleaned)

    if cleaned.count("*") > 1 or ("*" in cleaned and not cleaned.startswith("*.")):
        return None

    return cleaned


def fetch_and_categorize_o365(categories=("Optimize", "Allow"), include_required=True) -> dict:
    """Fetches Microsoft endpoints and partitions them strictly by serviceArea."""
    client_req_id = str(uuid.uuid4())
    url = f"{MS_WEB_SERVICE_URL}?clientRequestId={client_req_id}"
    print(f"[*] Querying Microsoft Web Service API: {url}")

    categorized = {area: {"ips": set(), "fqdns": set()} for area in SERVICE_AREAS.keys()}

    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        records = resp.json()
    except requests.exceptions.RequestException as exc:
        sys.exit(f"[!] Failed to fetch Microsoft 365 endpoints: {exc}")

    for ep in records:
        is_req = ep.get("required", False) is True
        is_cat = ep.get("category") in categories if categories else False

        if include_required:
            if not (is_req or is_cat):
                continue
        else:
            if categories and not is_cat:
                continue

        service_area = ep.get("serviceArea", "Common")
        if service_area not in categorized:
            service_area = "Common"

        for raw_ip in ep.get("ips", []):
            cidr = normalize_ipv4_cidr(raw_ip)
            if cidr:
                categorized[service_area]["ips"].add(cidr)

        for raw_url in ep.get("urls", []):
            norm = normalize_fqdn(raw_url)
            if norm:
                categorized[service_area]["fqdns"].add(norm)

    result = {}
    for area, data in categorized.items():
        result[area] = {
            "ips": sorted(data["ips"]),
            "fqdns": sorted(data["fqdns"]),
        }
        print(f"    - {area}: {len(result[area]['fqdns'])} FQDNs, {len(result[area]['ips'])} IPv4 CIDRs")

    return result


# ==============================================================================
# 2. ZTB REST API CLIENT
# ==============================================================================
class ZTBClient:
    def __init__(self, api_base: str, api_key: str, ui_origin: str):
        self.api_base = api_base
        self.api_key = api_key
        self.ui_origin = ui_origin
        self.session = requests.Session()
        self.group_cache = {}

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
            resp.raise_for_status()
        except requests.exceptions.RequestException as exc:
            sys.exit(f"\n[!] ZTB Authentication Error: {exc}\n")

        data = resp.json()
        token = data.get("result", {}).get("delegate_token") or data.get("delegate_token")
        if not token:
            sys.exit(f"[!] Missing delegate_token in response: {data}")

        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": self.ui_origin,
            "Referer": f"{self.ui_origin}/",
            "X-Requested-With": "XMLHttpRequest",
        })
        print("[+] Authenticated to ZTB Management API.")

    def load_all_existing_groups(self):
        """Preloads existing groups into cache for conflict-free resolution."""
        self.group_cache.clear()
        get_url = f"{self.api_base}/api/v2/groups"
        params = {"size": 1000, "page": 0}

        try:
            resp = self.session.get(get_url, params=params, timeout=20)
            resp.raise_for_status()
            groups_list = resp.json().get("result", resp.json() if isinstance(resp.json(), list) else [])
            for g in groups_list:
                name = g.get("name") or g.get("display_name")
                gid = g.get("group_id")
                if name and gid:
                    self.group_cache[name] = gid
            print(f"[*] Pre-loaded {len(self.group_cache)} existing groups from ZTB.")
        except requests.exceptions.RequestException as exc:
            print(f"[!] Warning: Could not pre-cache existing groups ({exc}).")

    def upsert_network_group(self, name: str, member_attributes: dict, member_groups: str = "") -> int:
        """
        Creates or updates a network group. Supports top-level 'member_groups' string.
        """
        existing_id = self.group_cache.get(name)

        payload = {
            "name": name,
            "display_name": name,
            "type": "network",
            "autonomous": False,
            "hidden": False,
            "owner": "user",
            "member_attributes": member_attributes,
        }

        # Include top-level member_groups for umbrella parent groups
        if member_groups:
            payload["member_groups"] = member_groups

        # 1. Update existing group
        if existing_id:
            print(f"[*] Updating existing group '{name}' (ID: {existing_id})...")
            url = f"{self.api_base}/api/v2/groups/{existing_id}?refresh_token=enabled"
            try:
                r = self.session.put(url, json=payload, timeout=30)
                if r.status_code >= 400:
                    print(f"[!] PUT error payload ({r.status_code}): {r.text}")
                r.raise_for_status()
                print(f"[+] Successfully updated '{name}' (ID: {existing_id}).")
                return existing_id
            except requests.exceptions.HTTPError:
                print(f"[!] PUT failed for '{name}'. Retrying with fresh lookup...")

        # 2. Create new group
        print(f"[*] Creating group '{name}'...")
        url = f"{self.api_base}/api/v2/groups?refresh_token=enabled"
        r = self.session.post(url, json=payload, timeout=30)

        # 3. Handle 409 Conflict fallback
        if r.status_code == 409:
            print(f"[*] Conflict (409) detected for '{name}'. Refreshing group cache...")
            self.load_all_existing_groups()
            existing_id = self.group_cache.get(name)
            if existing_id:
                put_url = f"{self.api_base}/api/v2/groups/{existing_id}?refresh_token=enabled"
                put_resp = self.session.put(put_url, json=payload, timeout=30)
                if put_resp.status_code >= 400:
                    print(f"[!] PUT retry error ({put_resp.status_code}): {put_resp.text}")
                put_resp.raise_for_status()
                print(f"[+] Successfully updated '{name}' (ID: {existing_id}).")
                return existing_id
            else:
                sys.exit(f"[!] 409 Conflict received, but group '{name}' was not found in group list.")

        if r.status_code >= 400:
            print(f"[!] Group creation error ({r.status_code}): {r.text}")
        r.raise_for_status()

        res_data = r.json().get("result", r.json())
        new_id = res_data.get("group_id")
        self.group_cache[name] = new_id
        print(f"[+] Successfully created network group '{name}' (ID: {new_id}).")
        return new_id


# ==============================================================================
# 3. MAIN EXECUTION ROUTINE
# ==============================================================================
def main():
    print("====================================================================")
    print(" ZTB Microsoft 365 Category Child & Umbrella Group Provisioning")
    print("====================================================================")

    # 1. Fetch & Categorize Microsoft 365 Endpoints
    categorized = fetch_and_categorize_o365(categories=("Optimize", "Allow"), include_required=True)

    # 2. Authenticate and initialize group cache
    ztb = ZTBClient(ZTB_BASE_URL, ZTB_API_KEY, ZTB_UI_ORIGIN)
    ztb.authenticate()
    ztb.load_all_existing_groups()

    created_fqdn_child_names = []
    created_ip_child_names = []

    # 3. Provision Category Child Groups (Leaf Groups holding raw entries)
    print("\n[*] Provisioning Category Child Groups...")
    for area_key, prefix in SERVICE_AREAS.items():
        area_fqdns = categorized[area_key]["fqdns"]
        area_ips = categorized[area_key]["ips"]

        # Category FQDN Child Group
        fqdn_child_name = f"{prefix}-FQDN"
        if area_fqdns:
            ztb.upsert_network_group(
                name=fqdn_child_name,
                member_attributes={
                    "ip_prefix": [],
                    "ip_prefix_local": [],
                    "fqdn": area_fqdns,
                    "fqdn_local": area_fqdns,
                },
            )
            created_fqdn_child_names.append(fqdn_child_name)

        # Category IP Child Group
        ip_child_name = f"{prefix}-IP"
        if area_ips:
            ztb.upsert_network_group(
                name=ip_child_name,
                member_attributes={
                    "ip_prefix": area_ips,
                    "ip_prefix_local": area_ips,
                    "fqdn": [],
                    "fqdn_local": [],
                },
            )
            created_ip_child_names.append(ip_child_name)

    # 4. Provision Master Umbrella Groups (Containing ONLY member groups)
    print("\n[*] Provisioning Master Umbrella Groups (Member Groups Only)...")

    # Master FQDN Umbrella Group: empty leaf lists, only top-level member_groups
    fqdn_members_csv = ",".join(created_fqdn_child_names)
    ztb.upsert_network_group(
        name=MASTER_FQDN_GROUP_NAME,
        member_groups=fqdn_members_csv,
        member_attributes={
            "ip_prefix": [],
            "ip_prefix_local": [],
            "fqdn": [],
            "fqdn_local": [],
        },
    )
    print(f"[+] Master FQDN Umbrella '{MASTER_FQDN_GROUP_NAME}' updated with member groups only: {fqdn_members_csv}")

    # Master IP Umbrella Group: empty leaf lists, only top-level member_groups
    ip_members_csv = ",".join(created_ip_child_names)
    ztb.upsert_network_group(
        name=MASTER_IP_GROUP_NAME,
        member_groups=ip_members_csv,
        member_attributes={
            "ip_prefix": [],
            "ip_prefix_local": [],
            "fqdn": [],
            "fqdn_local": [],
        },
    )
    print(f"[+] Master IP Umbrella '{MASTER_IP_GROUP_NAME}' updated with member groups only: {ip_members_csv}")

    print("\n[SUCCESS] Synchronization complete. Master groups contain only member groups.")


if __name__ == "__main__":
    main()
