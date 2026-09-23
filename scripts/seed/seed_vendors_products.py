"""Seed the vendors and products tables with a comprehensive catalog.

Pulls Wikipedia article content as descriptions where available.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_vendors_products.py
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_vendors_products.py --dry-run

--dry-run reports which vendors and products would be created and rolls back.
It skips the Wikipedia lookups, which are the slow part and only affect the
description text, so it finishes in seconds rather than minutes.
"""

import argparse
import asyncio
import sys
import time

sys.path.insert(0, "/app")
# Also support running from project root
sys.path.insert(0, "backend")

try:
    import wikipediaapi

    HAS_WIKIPEDIA = True
except ImportError:
    HAS_WIKIPEDIA = False
    print("WARNING: wikipedia-api package not installed. Descriptions will be empty.")
    print("Install with: pip install wikipedia-api")

from sqlalchemy import func, select

from app.database import async_session
from app.models.product import Product
from app.models.vendor import Vendor

# ─── Wikipedia helper ──────────────────────────────────────────────────────

_wiki_cache: dict[str, str | None] = {}
_wiki_calls = 0


def fetch_wikipedia(query: str, fallback_query: str | None = None) -> str | None:
    """Fetch full Wikipedia article content for a query. Returns None on failure."""
    global _wiki_calls
    if not HAS_WIKIPEDIA:
        return None

    if query in _wiki_cache:
        return _wiki_cache[query]

    wiki = wikipediaapi.Wikipedia(user_agent="IntelFeed/1.0", language="en")

    for q in [query, fallback_query] if fallback_query else [query]:
        if not q:
            continue
        try:
            _wiki_calls += 1
            # Rate limit: ~1 req/sec to be polite
            if _wiki_calls > 1:
                time.sleep(0.5)
            page = wiki.page(q)
            if not page.exists():
                continue
            content = page.text
            _wiki_cache[query] = content
            return content
        except Exception as e:
            print(f"  Wikipedia error for '{q}': {e}")
            continue

    _wiki_cache[query] = None
    return None


# ─── Vendor + Product Catalog ──────────────────────────────────────────────
# Format: (vendor_name, vendor_type, aliases, wiki_query, products_list)
# Products: (product_name, product_type, aliases, wiki_query)

VENDOR_PRODUCT_CATALOG = [
    # ───────────────────────────────────────────────────────────────────────
    # SECURITY VENDORS
    # ───────────────────────────────────────────────────────────────────────
    (
        "CrowdStrike",
        "security",
        ["CS"],
        "CrowdStrike",
        [
            ("CrowdStrike Falcon", "security_tool", ["Falcon", "Falcon EDR"], "CrowdStrike Falcon"),
            ("Falcon LogScale", "application", ["LogScale", "Humio"], "Humio"),
            ("Falcon OverWatch", "security_tool", ["OverWatch"], None),
        ],
    ),
    (
        "SentinelOne",
        "security",
        ["S1"],
        "SentinelOne",
        [
            ("SentinelOne Singularity", "security_tool", ["Singularity", "Singularity XDR"], None),
            ("SentinelOne Purple AI", "security_tool", ["Purple AI"], None),
        ],
    ),
    (
        "Palo Alto Networks",
        "security",
        ["PAN", "PANW"],
        "Palo Alto Networks",
        [
            ("Cortex XDR", "security_tool", ["XDR"], None),
            ("Cortex XSOAR", "security_tool", ["XSOAR", "Demisto"], "Demisto"),
            ("Prisma Cloud", "cloud_service", ["Prisma"], None),
            ("PAN-OS", "firmware", ["Palo Alto Firewall OS"], None),
            ("Panorama", "security_tool", [], None),
            ("WildFire", "security_tool", [], None),
        ],
    ),
    (
        "Fortinet",
        "security",
        [],
        "Fortinet",
        [
            ("FortiGate", "network_device", ["Fortinet Firewall"], "FortiGate"),
            ("FortiSIEM", "security_tool", [], None),
            ("FortiEDR", "security_tool", [], None),
            ("FortiAnalyzer", "security_tool", [], None),
            ("FortiManager", "security_tool", [], None),
            ("FortiOS", "firmware", [], None),
        ],
    ),
    (
        "Check Point",
        "security",
        ["Check Point Software"],
        "Check Point Software Technologies",
        [
            ("Check Point Quantum", "network_device", ["Quantum Security Gateway"], None),
            ("Check Point Harmony", "security_tool", ["Harmony Endpoint"], None),
            ("Check Point CloudGuard", "cloud_service", ["CloudGuard"], None),
        ],
    ),
    (
        "Sophos",
        "security",
        [],
        "Sophos",
        [
            ("Sophos Intercept X", "security_tool", ["Intercept X"], None),
            ("Sophos XGS Firewall", "network_device", ["XGS", "Sophos Firewall"], None),
            ("Sophos Central", "security_tool", [], None),
        ],
    ),
    (
        "Trend Micro",
        "security",
        [],
        "Trend Micro",
        [
            ("Trend Vision One", "security_tool", ["Vision One", "XDR"], None),
            ("Deep Security", "security_tool", [], "Trend Micro Deep Security"),
            ("Apex One", "security_tool", [], None),
        ],
    ),
    (
        "Trellix",
        "security",
        ["McAfee Enterprise", "FireEye"],
        "Trellix",
        [
            ("Trellix EDR", "security_tool", ["McAfee EDR"], None),
            ("Trellix Helix", "security_tool", ["FireEye Helix"], None),
            ("Trellix ePO", "security_tool", ["McAfee ePO", "ePolicy Orchestrator"], None),
        ],
    ),
    (
        "Rapid7",
        "security",
        [],
        "Rapid7",
        [
            ("InsightIDR", "security_tool", ["IDR"], None),
            ("Metasploit", "security_tool", ["MSF", "Metasploit Framework"], "Metasploit"),
            ("InsightVM", "security_tool", ["Nexpose"], "Nexpose"),
            ("InsightConnect", "security_tool", ["SOAR"], None),
        ],
    ),
    (
        "Qualys",
        "security",
        [],
        "Qualys",
        [
            ("Qualys VMDR", "security_tool", ["VMDR"], None),
            ("Qualys Cloud Agent", "security_tool", ["QCA"], None),
        ],
    ),
    (
        "Tenable",
        "security",
        [],
        "Tenable (company)",
        [
            ("Tenable Nessus", "security_tool", ["Nessus"], "Nessus (software)"),
            ("Tenable.io", "cloud_service", ["Tenable Vulnerability Management"], None),
            ("Tenable.sc", "security_tool", ["SecurityCenter"], None),
        ],
    ),
    (
        "CyberArk",
        "security",
        [],
        "CyberArk",
        [
            ("CyberArk PAM", "security_tool", ["Privileged Access Manager"], None),
            ("CyberArk Conjur", "security_tool", ["Conjur"], None),
        ],
    ),
    (
        "BeyondTrust",
        "security",
        [],
        "BeyondTrust",
        [
            ("BeyondTrust PRA", "security_tool", ["Privileged Remote Access"], None),
            ("BeyondTrust Password Safe", "security_tool", ["Password Safe"], None),
        ],
    ),
    (
        "Proofpoint",
        "security",
        [],
        "Proofpoint (company)",
        [
            ("Proofpoint Email Protection", "security_tool", ["Proofpoint TAP"], None),
            ("Proofpoint TRAP", "security_tool", ["TRAP"], None),
        ],
    ),
    (
        "Mimecast",
        "security",
        [],
        "Mimecast",
        [
            ("Mimecast Email Security", "security_tool", [], None),
            ("Mimecast Awareness Training", "security_tool", [], None),
        ],
    ),
    (
        "Barracuda",
        "security",
        ["Barracuda Networks"],
        "Barracuda Networks",
        [
            ("Barracuda Email Gateway", "security_tool", ["Barracuda ESG"], None),
            ("Barracuda WAF", "network_device", ["Barracuda Web Application Firewall"], None),
        ],
    ),
    (
        "Darktrace",
        "security",
        [],
        "Darktrace",
        [
            ("Darktrace DETECT", "security_tool", ["Enterprise Immune System"], None),
            ("Darktrace RESPOND", "security_tool", ["Antigena"], None),
        ],
    ),
    (
        "Wiz",
        "security",
        [],
        "Wiz (company)",
        [
            ("Wiz Cloud Security", "cloud_service", ["Wiz CNAPP"], None),
        ],
    ),
    (
        "Snyk",
        "security",
        [],
        "Snyk",
        [
            ("Snyk Open Source", "security_tool", [], None),
            ("Snyk Container", "security_tool", [], None),
            ("Snyk Code", "security_tool", ["SAST"], None),
        ],
    ),
    (
        "Cybereason",
        "security",
        [],
        "Cybereason",
        [
            ("Cybereason EDR", "security_tool", [], None),
        ],
    ),
    (
        "Carbon Black",
        "security",
        ["VMware Carbon Black"],
        "Carbon Black (company)",
        [
            ("Carbon Black Cloud", "security_tool", ["CB Cloud"], None),
        ],
    ),
    (
        "Vectra AI",
        "security",
        ["Vectra"],
        "Vectra AI",
        [
            ("Vectra Cognito", "security_tool", ["Cognito"], None),
        ],
    ),
    (
        "Tanium",
        "security",
        [],
        "Tanium",
        [
            ("Tanium Platform", "security_tool", [], None),
        ],
    ),
    (
        "Recorded Future",
        "security",
        ["RF"],
        "Recorded Future",
        [
            ("Recorded Future Intelligence Cloud", "security_tool", ["RFIC"], None),
        ],
    ),
    (
        "Mandiant",
        "security",
        ["Google Mandiant", "FireEye Mandiant"],
        "Mandiant",
        [
            ("Mandiant Advantage", "security_tool", [], None),
        ],
    ),
    (
        "Huntress",
        "security",
        [],
        "Huntress (company)",
        [
            ("Huntress MDR", "security_tool", [], None),
        ],
    ),
    (
        "Wazuh",
        "security",
        [],
        "Wazuh",
        [
            ("Wazuh SIEM", "security_tool", [], None),
        ],
    ),
    (
        "ESET",
        "security",
        [],
        "ESET",
        [
            ("ESET PROTECT", "security_tool", ["ESET Endpoint Security"], None),
            ("ESET NOD32", "security_tool", ["NOD32"], "ESET NOD32 Antivirus"),
        ],
    ),
    (
        "Bitdefender",
        "security",
        [],
        "Bitdefender",
        [
            ("Bitdefender GravityZone", "security_tool", ["GravityZone"], None),
        ],
    ),
    (
        "Malwarebytes",
        "security",
        [],
        "Malwarebytes",
        [
            ("Malwarebytes EDR", "security_tool", [], None),
        ],
    ),
    (
        "KnowBe4",
        "security",
        [],
        "KnowBe4",
        [
            ("KnowBe4 Security Awareness", "security_tool", ["KMSAT"], None),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # SIEM / LOG MANAGEMENT
    # ───────────────────────────────────────────────────────────────────────
    (
        "Splunk",
        "software",
        ["Cisco Splunk"],
        "Splunk",
        [
            ("Splunk Enterprise", "application", ["Splunk SIEM"], "Splunk"),
            ("Splunk Cloud", "cloud_service", [], None),
            ("Splunk SOAR", "application", ["Phantom"], "Splunk SOAR"),
        ],
    ),
    (
        "Elastic",
        "software",
        ["Elastic NV"],
        "Elastic NV",
        [
            ("Elastic Security", "security_tool", ["Elastic SIEM"], None),
            ("Elasticsearch", "database", ["ES"], "Elasticsearch"),
            ("Kibana", "application", [], "Kibana"),
            ("Elastic Defend", "security_tool", [], None),
        ],
    ),
    (
        "IBM",
        "software",
        [],
        "IBM",
        [
            ("IBM QRadar", "security_tool", ["QRadar", "QRadar SIEM"], "IBM QRadar"),
            ("IBM Guardium", "security_tool", ["Guardium"], None),
            ("IBM MaaS360", "security_tool", ["MaaS360"], None),
            ("IBM Cloud", "cloud_service", [], "IBM Cloud"),
        ],
    ),
    (
        "Exabeam",
        "security",
        [],
        "Exabeam",
        [
            ("Exabeam Fusion SIEM", "security_tool", ["Fusion SIEM"], None),
        ],
    ),
    (
        "LogRhythm",
        "security",
        [],
        "LogRhythm",
        [
            ("LogRhythm SIEM", "security_tool", [], None),
        ],
    ),
    (
        "Securonix",
        "security",
        [],
        None,
        [
            ("Securonix SNYPR", "security_tool", ["SNYPR"], None),
        ],
    ),
    (
        "Sumo Logic",
        "software",
        [],
        "Sumo Logic",
        [
            ("Sumo Logic Cloud SIEM", "security_tool", ["Cloud SIEM"], None),
        ],
    ),
    (
        "Devo",
        "software",
        [],
        None,
        [
            ("Devo Platform", "security_tool", [], None),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # CLOUD PROVIDERS
    # ───────────────────────────────────────────────────────────────────────
    (
        "Microsoft",
        "software",
        ["MSFT"],
        "Microsoft",
        [
            ("Microsoft Azure", "cloud_service", ["Azure"], "Microsoft Azure"),
            ("Microsoft 365", "cloud_service", ["M365", "Office 365", "O365"], "Microsoft 365"),
            ("Microsoft Defender for Endpoint", "security_tool", ["MDE", "Defender ATP"], None),
            ("Microsoft Sentinel", "security_tool", ["Azure Sentinel"], "Microsoft Sentinel"),
            ("Microsoft Entra ID", "security_tool", ["Azure AD", "Azure Active Directory", "Entra"], None),
            ("Microsoft Intune", "security_tool", ["Intune"], "Microsoft Intune"),
            ("Microsoft Exchange", "application", ["Exchange Server", "Exchange Online"], "Microsoft Exchange Server"),
            ("Windows", "os", ["Windows OS", "Microsoft Windows"], "Microsoft Windows"),
            ("Windows Server", "os", ["Win Server"], "Windows Server"),
            ("Active Directory", "application", ["AD"], "Active Directory"),
            ("Microsoft SQL Server", "database", ["MSSQL", "SQL Server"], "Microsoft SQL Server"),
            ("Microsoft Teams", "application", ["Teams"], "Microsoft Teams"),
            ("SharePoint", "application", ["SharePoint Online"], "SharePoint"),
            ("Microsoft Defender for Cloud", "security_tool", ["Azure Security Center"], None),
            ("Microsoft Purview", "security_tool", ["Azure Purview"], None),
            ("PowerShell", "application", ["PS"], "PowerShell"),
            ("Visual Studio Code", "application", ["VSCode", "VS Code"], "Visual Studio Code"),
            ("GitHub", "cloud_service", [], "GitHub"),
        ],
    ),
    (
        "Google",
        "software",
        ["Alphabet", "Google LLC"],
        "Google",
        [
            ("Google Cloud Platform", "cloud_service", ["GCP"], "Google Cloud Platform"),
            ("Google Workspace", "cloud_service", ["G Suite", "GSuite"], "Google Workspace"),
            ("Google Chronicle", "security_tool", ["Chronicle SIEM"], None),
            ("Google Security Operations", "security_tool", ["SecOps"], None),
            ("Android", "os", ["Android OS"], "Android (operating system)"),
            ("Chrome", "application", ["Google Chrome"], "Google Chrome"),
            ("ChromeOS", "os", ["Chrome OS"], "ChromeOS"),
            ("Gmail", "application", [], "Gmail"),
        ],
    ),
    (
        "Amazon",
        "cloud",
        ["AWS", "Amazon.com"],
        "Amazon (company)",
        [
            ("Amazon Web Services", "cloud_service", ["AWS"], "Amazon Web Services"),
            ("AWS GuardDuty", "security_tool", ["GuardDuty"], "Amazon GuardDuty"),
            ("AWS CloudTrail", "security_tool", ["CloudTrail"], "AWS CloudTrail"),
            ("AWS Security Hub", "security_tool", ["Security Hub"], None),
            ("Amazon S3", "cloud_service", ["S3"], "Amazon S3"),
            ("Amazon EC2", "cloud_service", ["EC2"], "Amazon Elastic Compute Cloud"),
            ("AWS WAF", "security_tool", [], None),
            ("AWS IAM", "security_tool", ["IAM"], "AWS Identity and Access Management"),
            ("Amazon CloudWatch", "cloud_service", ["CloudWatch"], "Amazon CloudWatch"),
        ],
    ),
    (
        "Oracle",
        "software",
        [],
        "Oracle Corporation",
        [
            ("Oracle Cloud", "cloud_service", ["OCI", "Oracle Cloud Infrastructure"], "Oracle Cloud"),
            ("Oracle Database", "database", ["Oracle DB"], "Oracle Database"),
            ("Oracle Linux", "os", [], "Oracle Linux"),
            ("Java", "library", ["JDK", "JRE"], "Java (programming language)"),
        ],
    ),
    (
        "Salesforce",
        "cloud",
        [],
        "Salesforce",
        [
            ("Salesforce CRM", "cloud_service", ["SFDC"], "Salesforce"),
            ("Slack", "application", [], "Slack (software)"),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # NETWORKING
    # ───────────────────────────────────────────────────────────────────────
    (
        "Cisco",
        "networking",
        [],
        "Cisco",
        [
            ("Cisco IOS", "firmware", ["IOS", "IOS XE"], "Cisco IOS"),
            ("Cisco ASA", "network_device", ["ASA", "Adaptive Security Appliance"], "Cisco ASA"),
            ("Cisco Firepower", "security_tool", ["FTD", "Firepower Threat Defense"], None),
            ("Cisco Umbrella", "security_tool", ["OpenDNS"], "OpenDNS"),
            ("Cisco ISE", "security_tool", ["Identity Services Engine"], None),
            ("Cisco AnyConnect", "application", ["AnyConnect VPN"], "Cisco AnyConnect"),
            ("Cisco Meraki", "network_device", ["Meraki"], "Cisco Meraki"),
            ("Cisco Webex", "application", ["Webex"], "Cisco Webex"),
            ("Cisco Duo", "security_tool", ["Duo Security", "Duo MFA"], "Duo Security"),
        ],
    ),
    (
        "Juniper Networks",
        "networking",
        ["Juniper"],
        "Juniper Networks",
        [
            ("Junos OS", "firmware", ["Junos", "JUNOS"], "Junos OS"),
            ("Juniper SRX", "network_device", ["SRX"], None),
        ],
    ),
    (
        "Arista Networks",
        "networking",
        ["Arista"],
        "Arista Networks",
        [
            ("Arista EOS", "firmware", ["EOS"], None),
        ],
    ),
    (
        "F5 Networks",
        "networking",
        ["F5"],
        "F5 Networks",
        [
            ("F5 BIG-IP", "network_device", ["BIG-IP"], "F5 BIG-IP"),
            ("F5 NGINX", "application", ["NGINX", "nginx"], "Nginx"),
        ],
    ),
    (
        "Cloudflare",
        "networking",
        ["CF"],
        "Cloudflare",
        [
            ("Cloudflare CDN", "cloud_service", [], None),
            ("Cloudflare WAF", "security_tool", [], None),
            ("Cloudflare Zero Trust", "security_tool", ["Cloudflare Access"], None),
            ("Cloudflare Workers", "cloud_service", [], None),
        ],
    ),
    (
        "Akamai",
        "networking",
        [],
        "Akamai Technologies",
        [
            ("Akamai Guardicore", "security_tool", ["Guardicore"], None),
            ("Akamai CDN", "cloud_service", [], None),
        ],
    ),
    (
        "Zscaler",
        "security",
        [],
        "Zscaler",
        [
            ("Zscaler Internet Access", "security_tool", ["ZIA"], None),
            ("Zscaler Private Access", "security_tool", ["ZPA"], None),
        ],
    ),
    (
        "Netskope",
        "security",
        [],
        "Netskope",
        [
            ("Netskope CASB", "security_tool", ["Netskope Cloud Security"], None),
        ],
    ),
    (
        "WatchGuard",
        "networking",
        ["WatchGuard Technologies"],
        "WatchGuard Technologies",
        [
            ("WatchGuard Firebox", "network_device", ["Firebox"], None),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # OPERATING SYSTEMS & INFRASTRUCTURE
    # ───────────────────────────────────────────────────────────────────────
    (
        "Canonical",
        "software",
        [],
        "Canonical (company)",
        [
            ("Ubuntu", "os", ["Ubuntu Linux"], "Ubuntu"),
        ],
    ),
    (
        "Red Hat",
        "software",
        [],
        "Red Hat",
        [
            ("Red Hat Enterprise Linux", "os", ["RHEL"], "Red Hat Enterprise Linux"),
            ("Ansible", "application", ["Red Hat Ansible"], "Ansible (software)"),
            ("OpenShift", "cloud_service", ["Red Hat OpenShift"], "OpenShift"),
        ],
    ),
    (
        "SUSE",
        "software",
        [],
        "SUSE",
        [
            ("SUSE Linux Enterprise", "os", ["SLES", "SLE"], "SUSE Linux Enterprise"),
        ],
    ),
    (
        "Apple",
        "hardware",
        [],
        "Apple Inc.",
        [
            ("macOS", "os", ["Mac OS", "OS X", "Mac OS X"], "macOS"),
            ("iOS", "os", ["iPhone OS"], "iOS"),
            ("iPadOS", "os", [], "iPadOS"),
            ("Safari", "application", [], "Safari (web browser)"),
            ("Xcode", "application", [], "Xcode"),
        ],
    ),
    (
        "VMware",
        "software",
        ["Broadcom VMware"],
        "VMware",
        [
            ("VMware vSphere", "application", ["vSphere", "ESXi"], "VMware vSphere"),
            ("VMware vCenter", "application", ["vCenter"], None),
            ("VMware NSX", "network_device", ["NSX"], "VMware NSX"),
            ("VMware Horizon", "application", ["Horizon VDI"], None),
        ],
    ),
    (
        "Citrix",
        "software",
        ["Cloud Software Group"],
        "Citrix Systems",
        [
            ("Citrix NetScaler", "network_device", ["NetScaler", "ADC"], "Citrix ADC"),
            ("Citrix Virtual Apps", "application", ["XenApp"], None),
        ],
    ),
    (
        "Docker",
        "software",
        ["Docker Inc"],
        "Docker (software)",
        [
            ("Docker Engine", "application", ["Docker"], "Docker (software)"),
            ("Docker Desktop", "application", [], None),
        ],
    ),
    (
        "HashiCorp",
        "software",
        [],
        "HashiCorp",
        [
            ("Terraform", "application", [], "Terraform (software)"),
            ("Vault", "security_tool", ["HashiCorp Vault"], "Vault (software)"),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # IDENTITY & ACCESS
    # ───────────────────────────────────────────────────────────────────────
    (
        "Okta",
        "security",
        [],
        "Okta",
        [
            ("Okta Identity Cloud", "security_tool", ["Okta SSO"], None),
            ("Auth0", "security_tool", [], "Auth0"),
        ],
    ),
    (
        "Ping Identity",
        "security",
        [],
        "Ping Identity",
        [
            ("PingOne", "security_tool", [], None),
            ("PingFederate", "security_tool", [], None),
        ],
    ),
    (
        "OneLogin",
        "security",
        [],
        "OneLogin",
        [
            ("OneLogin IAM", "security_tool", [], None),
        ],
    ),
    (
        "SailPoint",
        "security",
        [],
        "SailPoint",
        [
            ("SailPoint IdentityNow", "security_tool", ["IdentityNow"], None),
        ],
    ),
    (
        "JumpCloud",
        "security",
        [],
        None,
        [
            ("JumpCloud Directory", "security_tool", [], None),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # DATABASES
    # ───────────────────────────────────────────────────────────────────────
    (
        "PostgreSQL",
        "software",
        ["Postgres"],
        None,
        [
            ("PostgreSQL", "database", ["Postgres", "PG"], "PostgreSQL"),
        ],
    ),
    (
        "MongoDB",
        "software",
        ["MongoDB Inc"],
        "MongoDB Inc.",
        [
            ("MongoDB", "database", ["Mongo"], "MongoDB"),
            ("MongoDB Atlas", "cloud_service", ["Atlas"], None),
        ],
    ),
    (
        "Snowflake",
        "cloud",
        ["Snowflake Inc"],
        "Snowflake Inc.",
        [
            ("Snowflake Data Cloud", "cloud_service", ["Snowflake"], None),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # COLLABORATION & PRODUCTIVITY
    # ───────────────────────────────────────────────────────────────────────
    (
        "Atlassian",
        "software",
        [],
        "Atlassian",
        [
            ("Jira", "application", ["Jira Software", "Jira Cloud"], "Jira (software)"),
            ("Confluence", "application", [], "Confluence (software)"),
            ("Bitbucket", "application", [], "Bitbucket"),
        ],
    ),
    (
        "Zoom",
        "software",
        ["Zoom Video"],
        "Zoom (software)",
        [
            ("Zoom Meetings", "application", ["Zoom"], "Zoom (software)"),
        ],
    ),
    (
        "ServiceNow",
        "software",
        [],
        "ServiceNow",
        [
            ("ServiceNow ITSM", "application", ["ServiceNow"], None),
            ("ServiceNow SecOps", "security_tool", [], None),
        ],
    ),
    (
        "Workday",
        "software",
        [],
        "Workday, Inc.",
        [
            ("Workday HCM", "application", ["Workday"], None),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # OPEN SOURCE / COMMUNITY
    # ───────────────────────────────────────────────────────────────────────
    (
        "Linux Foundation",
        "software",
        [],
        "Linux Foundation",
        [
            ("Linux", "os", ["GNU/Linux"], "Linux"),
            ("Kubernetes", "application", ["K8s"], "Kubernetes"),
        ],
    ),
    (
        "Mozilla",
        "software",
        ["Mozilla Foundation"],
        "Mozilla",
        [
            ("Firefox", "application", ["Mozilla Firefox"], "Firefox"),
        ],
    ),
    (
        "Apache Software Foundation",
        "software",
        ["ASF", "Apache"],
        "Apache Software Foundation",
        [
            ("Apache HTTP Server", "application", ["httpd", "Apache"], "Apache HTTP Server"),
            ("Apache Log4j", "library", ["Log4j", "Log4Shell"], "Log4j"),
            ("Apache Kafka", "application", ["Kafka"], "Apache Kafka"),
            ("Apache Tomcat", "application", ["Tomcat"], "Apache Tomcat"),
            ("Apache Struts", "library", ["Struts"], "Apache Struts"),
        ],
    ),
    (
        "OpenSSL",
        "software",
        ["OpenSSL Project"],
        None,
        [
            ("OpenSSL", "library", [], "OpenSSL"),
        ],
    ),
    (
        "Ivanti",
        "software",
        [],
        "Ivanti",
        [
            ("Ivanti Connect Secure", "security_tool", ["Pulse Secure", "Pulse Connect Secure"], None),
            ("Ivanti EPMM", "security_tool", ["MobileIron"], None),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # SEMICONDUCTORS & HARDWARE
    # ───────────────────────────────────────────────────────────────────────
    (
        "Intel",
        "semiconductor",
        [],
        "Intel",
        [
            ("Intel vPro", "firmware", ["vPro"], "Intel vPro"),
        ],
    ),
    (
        "AMD",
        "semiconductor",
        ["Advanced Micro Devices"],
        "AMD",
        [
            ("AMD EPYC", "hardware", ["EPYC"], "AMD Epyc"),
        ],
    ),
    (
        "NVIDIA",
        "semiconductor",
        [],
        "Nvidia",
        [
            ("NVIDIA CUDA", "library", ["CUDA"], "CUDA"),
            ("NVIDIA DGX", "hardware", ["DGX"], None),
        ],
    ),
    (
        "Broadcom",
        "semiconductor",
        ["Symantec"],
        "Broadcom Inc.",
        [
            ("Symantec Endpoint Protection", "security_tool", ["SEP"], "Symantec Endpoint Protection"),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # TELECOMMUNICATIONS
    # ───────────────────────────────────────────────────────────────────────
    (
        "Huawei",
        "telecommunications",
        [],
        "Huawei",
        [
            ("HarmonyOS", "os", [], "HarmonyOS"),
        ],
    ),
    (
        "Samsung",
        "hardware",
        ["Samsung Electronics"],
        "Samsung Electronics",
        [
            ("Samsung Knox", "security_tool", ["Knox"], "Samsung Knox"),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # VPN / REMOTE ACCESS
    # ───────────────────────────────────────────────────────────────────────
    (
        "WireGuard",
        "software",
        [],
        None,
        [
            ("WireGuard", "application", [], "WireGuard"),
        ],
    ),
    (
        "OpenVPN",
        "software",
        ["OpenVPN Inc"],
        None,
        [
            ("OpenVPN", "application", [], "OpenVPN"),
        ],
    ),
    (
        "Tailscale",
        "software",
        [],
        None,
        [
            ("Tailscale", "application", [], "Tailscale"),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # CLOUD STORAGE
    # ───────────────────────────────────────────────────────────────────────
    (
        "Dropbox",
        "cloud",
        [],
        "Dropbox (service)",
        [
            ("Dropbox Business", "cloud_service", ["Dropbox"], "Dropbox (service)"),
        ],
    ),
    (
        "Box",
        "cloud",
        ["Box Inc"],
        "Box (company)",
        [
            ("Box Enterprise", "cloud_service", ["Box"], "Box (company)"),
        ],
    ),
    # ───────────────────────────────────────────────────────────────────────
    # ADDITIONAL SECURITY TOOLS
    # ───────────────────────────────────────────────────────────────────────
    (
        "Cofense",
        "security",
        [],
        None,
        [
            ("Cofense Triage", "security_tool", [], None),
        ],
    ),
    (
        "Abnormal Security",
        "security",
        [],
        None,
        [
            ("Abnormal Security Platform", "security_tool", [], None),
        ],
    ),
    (
        "Menlo Security",
        "security",
        [],
        None,
        [
            ("Menlo Security Browser", "security_tool", ["Menlo"], None),
        ],
    ),
    (
        "Forcepoint",
        "security",
        [],
        "Forcepoint",
        [
            ("Forcepoint DLP", "security_tool", ["DLP"], None),
            ("Forcepoint NGFW", "network_device", [], None),
        ],
    ),
    (
        "Imperva",
        "security",
        ["Thales Imperva"],
        "Imperva",
        [
            ("Imperva WAF", "security_tool", ["SecureSphere"], None),
            ("Imperva Data Security", "security_tool", [], None),
        ],
    ),
    (
        "Orca Security",
        "security",
        [],
        None,
        [
            ("Orca Cloud Security", "cloud_service", ["Orca"], None),
        ],
    ),
    (
        "Aqua Security",
        "security",
        [],
        "Aqua Security",
        [
            ("Aqua Platform", "security_tool", [], None),
        ],
    ),
    (
        "Corelight",
        "security",
        [],
        None,
        [
            ("Corelight Sensors", "security_tool", ["Zeek Sensors"], None),
        ],
    ),
    (
        "ExtraHop",
        "security",
        [],
        "ExtraHop",
        [
            ("ExtraHop Reveal(x)", "security_tool", ["Reveal(x)", "RevealX"], None),
        ],
    ),
    (
        "Gigamon",
        "networking",
        [],
        "Gigamon",
        [
            ("Gigamon GigaVUE", "network_device", ["GigaVUE"], None),
        ],
    ),
    (
        "Infoblox",
        "networking",
        [],
        "Infoblox",
        [
            ("Infoblox BloxOne", "security_tool", ["BloxOne Threat Defense"], None),
        ],
    ),
    (
        "Axonius",
        "security",
        [],
        None,
        [
            ("Axonius Platform", "security_tool", ["CAASM"], None),
        ],
    ),
    (
        "runZero",
        "security",
        ["Rumble"],
        None,
        [
            ("runZero Explorer", "security_tool", ["Rumble Network Discovery"], None),
        ],
    ),
    (
        "Lansweeper",
        "software",
        [],
        None,
        [
            ("Lansweeper", "application", [], None),
        ],
    ),
    (
        "JAMF",
        "software",
        ["Jamf"],
        "Jamf",
        [
            ("Jamf Pro", "security_tool", ["Jamf"], None),
        ],
    ),
    (
        "Sysdig",
        "security",
        [],
        "Sysdig",
        [
            ("Sysdig Secure", "security_tool", [], None),
            ("Falco", "security_tool", ["Sysdig Falco"], "Falco (software)"),
        ],
    ),
    (
        "GitLab",
        "software",
        [],
        "GitLab",
        [
            ("GitLab CI/CD", "application", ["GitLab"], "GitLab"),
        ],
    ),
    (
        "Fastly",
        "networking",
        [],
        "Fastly",
        [
            ("Fastly CDN", "cloud_service", [], None),
            ("Fastly WAF", "security_tool", ["Signal Sciences"], None),
        ],
    ),
]


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        existing_vendors = (await db.execute(select(func.count()).select_from(Vendor))).scalar() or 0
        existing_products = (await db.execute(select(func.count()).select_from(Product))).scalar() or 0

        if existing_vendors > 10:
            print(f"Vendors table already has {existing_vendors} rows. Skipping seed.")
            print("To re-seed, truncate the vendors and products tables first.")
            return

        print(f"Seeding vendors and products (existing: {existing_vendors} vendors, {existing_products} products)...")
        wiki_state = "skipped (dry run)" if dry_run else ("enabled" if HAS_WIKIPEDIA else "DISABLED")
        print(f"Wikipedia descriptions: {wiki_state}")
        print()

        vendor_count = 0
        product_count = 0
        wiki_hits = 0
        vendor_id_map: dict[str, Vendor] = {}

        for vendor_name, vendor_type, aliases, wiki_query, products in VENDOR_PRODUCT_CATALOG:
            # Check if vendor already exists
            existing = await db.execute(select(Vendor).where(func.lower(Vendor.name) == vendor_name.lower()))
            vendor = existing.scalar_one_or_none()

            if not vendor:
                # Fetch Wikipedia description
                description = None
                if wiki_query and not dry_run:
                    print(f"  Fetching Wikipedia: {vendor_name}...", end=" ", flush=True)
                    description = fetch_wikipedia(wiki_query)
                    if description:
                        wiki_hits += 1
                        print(f"OK ({len(description)} chars)")
                    else:
                        print("not found")

                vendor = Vendor(
                    name=vendor_name,
                    vendor_type=vendor_type,
                    aliases=aliases,
                    description=description,
                    article_count=0,
                )
                db.add(vendor)
                await db.flush()
                await db.refresh(vendor)
                vendor_count += 1
            else:
                print(f"  Vendor '{vendor_name}' already exists, skipping creation")

            vendor_id_map[vendor_name] = vendor

            # Create products
            for prod_name, prod_type, prod_aliases, prod_wiki in products:
                existing_prod = await db.execute(select(Product).where(func.lower(Product.name) == prod_name.lower()))
                if existing_prod.scalar_one_or_none():
                    continue

                # Fetch Wikipedia description for product
                prod_description = None
                if prod_wiki and not dry_run:
                    print(f"    Fetching Wikipedia: {prod_name}...", end=" ", flush=True)
                    prod_description = fetch_wikipedia(prod_wiki)
                    if prod_description:
                        wiki_hits += 1
                        print(f"OK ({len(prod_description)} chars)")
                    else:
                        print("not found")

                product = Product(
                    name=prod_name,
                    vendor_id=vendor.id,
                    product_type=prod_type,
                    aliases=prod_aliases,
                    description=prod_description,
                    article_count=0,
                )
                db.add(product)
                product_count += 1

            # Commit every 10 vendors to avoid huge transactions
            if not dry_run and vendor_count % 10 == 0 and vendor_count > 0:
                await db.commit()

        if dry_run:
            await db.rollback()
            print()
            print(f"Would seed {vendor_count} vendors and {product_count} products.")
            print("Dry run — nothing written, and Wikipedia was not queried.")
            return

        await db.commit()
        print()
        print(f"Seeded {vendor_count} vendors and {product_count} products.")
        print(f"Wikipedia descriptions fetched: {wiki_hits}")

        # Refresh the autolinker vocabulary
        try:
            from app.intelligence.autolinker import refresh_vocabulary

            count = await refresh_vocabulary(db)
            print(f"Autolinker vocabulary rebuilt: {count} surface forms.")
        except Exception as e:
            print(f"Note: Could not refresh autolinker vocabulary: {e}")
            print("It will refresh automatically on next feed fetch.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be created, without Wikipedia lookups or writes.",
    )
    asyncio.run(main(parser.parse_args().dry_run))
