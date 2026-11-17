Zscaler Zero Trust Branch (ZTB) - Microsoft 365 Group Sync (README.md)
Overview
The ztb-o365-sync.py automation script queries the official Microsoft 365 IP Address and URL Web Service to automatically categorize and synchronize Microsoft 365 endpoints into Zscaler Zero Trust Branch (ZTB) (Airgap) Network Groups.
It establishes a clean, hierarchical architecture:
Category Child Groups (Leaf Groups): Dedicated FQDN and IP groups populated strictly per Microsoft service area (Exchange, SharePoint, Skype/Teams, Common).
Master Umbrella Groups (Parent Groups): Top-level umbrella groups (O365-Master-FQDN-Group and O365-Master-IP-Group) that nest and reference only the child member groups—containing zero direct leaf/duplicate entries.
Key Features & Use Cases
Dynamic O365 Policy Enforcement: Simplifies branch egress and firewall rules by grouping Microsoft endpoints into logical service boundaries rather than monolithic flat lists.
Automatic Categorization & Filtering: Pulls only Optimize and Allow categories (as well as required endpoints) to minimize noise and optimize traffic forwarding.
Strict Normalization:
Validates and guarantees IPv4 CIDR formats (/32 notation for single hosts).
Cleans URL schemes (http://, https://), path strings, port numbers, and ensures wildcards match ZTB regex specifications (*.domain.com).
Conflict-Free Idempotency: Pre-loads existing ZTB groups into a local lookup cache and handles HTTP 409 Conflict gracefully by refreshing the cache and falling back to a PUT update.
Clean Group Nesting: Passes comma-separated child group names via the top-level member_groups payload attribute, keeping umbrella parent groups clean and maintainable.
Group Architecture
The script automatically provisions or updates the following objects in ZTB:
Group Name
Type
Scope / Content
O365-Exchange-FQDN
Network Group (Leaf)
Exchange Online FQDNs / Wildcards
O365-Exchange-IP
Network Group (Leaf)
Exchange Online IPv4 CIDRs
O365-SharePoint-FQDN
Network Group (Leaf)
SharePoint Online & OneDrive FQDNs
O365-SharePoint-IP
Network Group (Leaf)
SharePoint Online IPv4 CIDRs
O365-Teams-Skype-FQDN
Network Group (Leaf)
Teams & Skype for Business FQDNs
O365-Teams-Skype-IP
Network Group (Leaf)
Teams & Skype for Business IPv4 CIDRs
O365-Common-FQDN
Network Group (Leaf)
Microsoft 365 Common / Shared FQDNs
O365-Common-IP
Network Group (Leaf)
Microsoft 365 Common IPv4 CIDRs
O365-Master-FQDN-Group
Network Group (Parent Umbrella)
References all 4 Category FQDN groups in member_groups
O365-Master-IP-Group
Network Group (Parent Umbrella)
References all 4 Category IP groups in member_groups

Requirements & Prerequisites
1. Python Environment
Python 3.10+
Standard libraries: os, re, sys, uuid, ipaddress
Third-party library: requests
2. Required Python Packages
Install the required dependency using pip:
pip install requests


3. Environment Variables
The script loads all tenant configuration and authentication secrets strictly from environment variables:
Variable
Required
Description
Example
ZTB_BASE_URL
Yes
ZTB Management API Base URL
https://<tenant>-api.goairgap.com
ZTB_API_KEY
Yes
ZTB API authentication key
ztb_api_key_xxxxxxxx
ZTB_UI_ORIGIN
No
ZTB Web UI Origin URL (defaults to ZTB_BASE_URL without -api.)
https://<tenant>.goairgap.com

API Endpoints Invoked
Target Service
HTTP Method
Endpoint
Description
Microsoft 365
GET
https://endpoints.office.com/endpoints/worldwide
Retrieves active Microsoft 365 IPv4 and FQDN endpoints.
ZTB API
POST
/api/v3/api-key-auth/login
Authenticates with ZTB_API_KEY to obtain a Bearer delegate_token.
ZTB API
GET
/api/v2/groups?size=1000&page=0
Lists existing network groups to populate the local cache.
ZTB API
POST
/api/v2/groups?refresh_token=enabled
Creates a new Network Group.
ZTB API
PUT
/api/v2/groups/{group_id}?refresh_token=enabled
Updates an existing Network Group.

Usage Instructions
1. Export Required Environment Variables
export ZTB_BASE_URL="https://customer-api.goairgap.com"
export ZTB_API_KEY="your-secret-api-key"

# Optional: override UI origin if different from customer.goairgap.com
# export ZTB_UI_ORIGIN="https://customer.goairgap.com"


2. Run the Script
python3 ztb-o365-sync.py


3. Expected Output
====================================================================
 ZTB Microsoft 365 Category Child & Umbrella Group Provisioning
====================================================================
[*] Querying Microsoft Web Service API: https://endpoints.office.com/endpoints/worldwide?clientRequestId=...
    - Exchange: 14 FQDNs, 38 IPv4 CIDRs
    - SharePoint: 11 FQDNs, 4 IPv4 CIDRs
    - Skype: 22 FQDNs, 16 IPv4 CIDRs
    - Common: 51 FQDNs, 10 IPv4 CIDRs
[+] Authenticated to ZTB Management API.
[*] Pre-loaded 18 existing groups from ZTB.

[*] Provisioning Category Child Groups...
[*] Creating group 'O365-Exchange-FQDN'...
[+] Successfully created network group 'O365-Exchange-FQDN' (ID: 101).
...
[*] Provisioning Master Umbrella Groups (Member Groups Only)...
[+] Master FQDN Umbrella 'O365-Master-FQDN-Group' updated with member groups only: O365-Exchange-FQDN,O365-SharePoint-FQDN,O365-Teams-Skype-FQDN,O365-Common-FQDN
[+] Master IP Umbrella 'O365-Master-IP-Group' updated with member groups only: O365-Exchange-IP,O365-SharePoint-IP,O365-Teams-Skype-IP,O365-Common-IP

[SUCCESS] Synchronization complete. Master groups contain only member groups.


4. Periodic Automation (Cron Job)
To keep ZTB network groups aligned with Microsoft's monthly endpoint updates, schedule the script via cron:
0 2 1 * * /usr/bin/env bash -c 'source /path/to/ztb.env && /usr/bin/python3 /path/to/ztb-o365-sync.py >> /var/log/ztb-o365-sync.log 2>&1'


Would you like me to add an example GitHub Actions workflow or a systemd timer configuration for running this synchronization on a schedule?
