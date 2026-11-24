"""Which platforms a telemetry source collects from.

A log type alone says too little: CrowdStrike Falcon gives process
creation, but only on hosts that run its sensor, so a hunt on an ESXi host
or a vCenter appliance cannot run on it however many process-creation
sources are enabled. The hunt pack's runs / needs check therefore asks, per
hunt, whether an enabled source that gives the log also collects from the
hunt's target, in the vocabulary hypotheses use for it (ATT&CK's platform
names). ``Any`` marks a source that watches from the network or collects
regardless of host — a firewall sees ESXi's traffic as well as a laptop's.

Nobody assigns this: it is a fact about the kind of product, so it follows
from the source's category, with a few name hints for the exceptions
(Hyper-V is Windows, macOS logs are macOS). Nothing is stored.
"""

ANY = "Any"

# ATT&CK platform names, as the hunt_pack prompt asks the model to use them.
# ESXi stands for VMware's virtualization stack: ESXi hosts and the vCenter
# appliance that manages them, neither of which runs an EDR agent.
PLATFORMS: tuple[str, ...] = (
    "Windows",
    "macOS",
    "Linux",
    "ESXi",
    "Network Devices",
    "Containers",
    "IaaS",
    "SaaS",
    "Identity Provider",
    "Office Suite",
)

_HOSTS = ["Windows", "macOS", "Linux"]

# Category → platforms its sources cover unless a source says otherwise.
_CATEGORY_DEFAULTS: dict[str, list[str]] = {
    "endpoint_edr": _HOSTS,
    "windows_events": ["Windows"],
    "linux_macos": ["Linux"],
    "virtualization": ["ESXi"],
    "web_server": ["Linux", "Windows"],
    "network_infra": ["Network Devices"],
    # Watch traffic, whatever the host on either end.
    "network_security": [ANY],
    "ndr": [ANY],
    "ids_ips": [ANY],
    "dns_security": [ANY],
    "web_proxy": [ANY],
    "waf_appsec": [ANY],
    "vpn_remote_access": [ANY],
    "identity": ["Identity Provider"],
    "cloud": ["IaaS"],
    "container": ["Containers"],
    "saas": ["SaaS"],
    "email": ["Office Suite", "SaaS"],
    # Host-independent records or not attack telemetry at all.
    "database": [ANY],
    "backup_storage": [ANY],
    "file_transfer": [ANY],
    "siem": [ANY],
    "threat_intel": [ANY],
    "vuln_management": [ANY],
    "endpoint_mgmt": [ANY],
    "dlp": [ANY],
    "physical_iot": [ANY],
}

# Name hints that move a source off its category's default.
_NAME_OVERRIDES: list[tuple[str, list[str]]] = [
    ("macos", ["macOS"]),
    ("hyper-v", ["Windows"]),
    ("microsoft iis", ["Windows"]),
    ("nutanix", ["Linux"]),
    ("proxmox", ["Linux"]),
    ("kubernetes", ["Containers"]),
    ("eks audit", ["Containers", "IaaS"]),
    ("gke audit", ["Containers", "IaaS"]),
    ("aks", ["Containers", "IaaS"]),
    ("google workspace", ["SaaS", "Office Suite"]),
    ("microsoft 365", ["SaaS", "Office Suite"]),
    ("sharepoint", ["SaaS", "Office Suite"]),
    ("onedrive", ["SaaS", "Office Suite"]),
    ("teams", ["SaaS", "Office Suite"]),
    ("exchange server", ["Windows", "Office Suite"]),
    ("radius", [ANY]),
    # Network-wide records, whatever host is on either end.
    ("netflow", [ANY]),
    ("infoblox", [ANY]),
    ("nsx", [ANY]),
]

_ALIASES = {
    "vcenter": "ESXi",
    "vmware": "ESXi",
    "vsphere": "ESXi",
    "esx": "ESXi",
    "network": "Network Devices",
    "network device": "Network Devices",
    "network devices": "Network Devices",
    "container": "Containers",
    "kubernetes": "Containers",
    "office 365": "Office Suite",
    "microsoft 365": "Office Suite",
    "identity": "Identity Provider",
    "azure ad": "Identity Provider",
    "entra id": "Identity Provider",
    "cloud": "IaaS",
    "aws": "IaaS",
    "azure": "IaaS",
    "gcp": "IaaS",
    "mac": "macOS",
}
_BY_LOWER = {p.lower(): p for p in (*PLATFORMS, ANY)}


def normalize_platform(value: str | None) -> str | None:
    """A platform name in the canonical spelling, or None when it isn't one."""
    if not value:
        return None
    key = value.strip().lower()
    return _BY_LOWER.get(key) or _ALIASES.get(key)


def default_platforms(category: str | None, name: str | None = "") -> list[str]:
    """The platforms a source of this category (and name) collects from."""
    lowered = (name or "").lower()
    for hint, platforms in _NAME_OVERRIDES:
        if hint in lowered:
            return list(platforms)
    return list(_CATEGORY_DEFAULTS.get(category or "", [ANY]))


def covers(platforms: list[str], platform: str | None) -> bool:
    """Whether a source covering ``platforms`` sees a hunt on ``platform``.

    A hunt with no platform, or one outside the vocabulary, is not narrowed:
    any source that gives its logs counts, as before platforms existed.
    """
    target = normalize_platform(platform)
    return target is None or ANY in platforms or target in platforms
