# ruff: noqa: E501 — file embeds the generated denylist seed corpus
"""entity resolution guardrails: entity_norm, normalized_name columns, alias index, denylist

Entity creation guardrails, phases 1-2:

- pg_trgm extension (fuzzy-candidate advisory queries)
- entity_norm(text) IMMUTABLE function: lowercase -> NFKC -> leetspeak fold
  (0->o 1->l 3->e 4->a 5->s 7->t $->s @->a) -> strip non-alphanumerics. Must
  stay in lockstep with normalize_entity_name().norm_exact in
  app/intelligence/entity_resolution.py.
- normalized_name generated column + btree/trgm indexes on threat_actors,
  malware_families, offensive_tools, vendors, products.
- entity_alias_index: trigger-maintained (entity, surface form, normalized)
  rows for every name + alias of those five tables; backfilled here.
- entity_name_denylist: seeded from the 2026-08 prod cleanup review_delete
  verdicts (remaining_cleanup_judged.csv). The 353 junk entities deleted in
  that cleanup have no tombstones - without this seed they resurrect on the
  next extraction that mentions them.

The per-table UNIQUE constraint on normalized_name ships separately
(validated against a fresh prod sync; malware_families and offensive_tools
carry residual collisions - see the follow-up revision).

Revision ID: d4f6h8j0l2n4
Revises: c3e5g7i9k1m3
Create Date: 2026-08-16
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "d4f6h8j0l2n4"
down_revision = "c3e5g7i9k1m3"
branch_labels = None
depends_on = None

# (slug, table) pairs kept in sync with app/models/entity_index.py ALIAS_INDEXED_TABLES.
ENTITY_TABLES = [
    ("threat_actor", "threat_actors"),
    ("malware_family", "malware_families"),
    ("offensive_tool", "offensive_tools"),
    ("vendor", "vendors"),
    ("product", "products"),
]

ENTITY_NORM_FN_SQL = """
CREATE OR REPLACE FUNCTION entity_norm(txt text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE STRICT AS $fn$
    SELECT regexp_replace(
        translate(lower(normalize(lower(txt), NFKC)), '013457$@', 'oleastsa'),
        '[^a-z0-9]', '', 'g'
    )
$fn$;
"""

ALIAS_INDEX_TRIGGER_FN_SQL = """
CREATE OR REPLACE FUNCTION sync_entity_alias_index() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    IF TG_OP = 'DELETE' THEN
        DELETE FROM entity_alias_index
        WHERE entity_type = TG_ARGV[0] AND entity_id = OLD.id;
        RETURN OLD;
    END IF;
    DELETE FROM entity_alias_index
    WHERE entity_type = TG_ARGV[0] AND entity_id = NEW.id;
    INSERT INTO entity_alias_index (id, entity_type, entity_id, surface, normalized, is_name)
    SELECT gen_random_uuid(), TG_ARGV[0], NEW.id, f.surface, entity_norm(f.surface), f.is_name
    FROM (
        SELECT NEW.name AS surface, true AS is_name
        UNION ALL
        SELECT a, false FROM unnest(COALESCE(NEW.aliases, '{}'::text[])) AS a
    ) f
    WHERE f.surface IS NOT NULL AND entity_norm(f.surface) <> ''
    ON CONFLICT (entity_type, entity_id, normalized) DO NOTHING;
    RETURN NEW;
END
$fn$;
"""

# (entity_type slug, normalized_name, display_name, reason) - generated from
# cleanup/remaining_cleanup_judged.csv review_delete rows whose judgment was a
# delete verdict (approve_delete / delete / delete_after_cve_relink), deduped
# on (type, normalized). 320 rows covering the deleted junk entities from the
# threat_actor, malware, and tools cleanup passes.
DENYLIST_SEED = [
    ("threat_actor", "attackers", "attackers", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "threatactorsunnamed",
        "Threat actors (unnamed)",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "nationstateactors",
        "Nation-state actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "statesponsoredthreatgroup",
        "State-sponsored threat group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "unknown", "Unknown", "generic/junk descriptor entity, not a trackable actor"),
    ("threat_actor", "unknownapt", "Unknown APT", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "unknownthreatactor",
        "Unknown threat actor",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownthreatactors",
        "Unknown threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownchinesehackergroup",
        "Unknown Chinese Hacker Group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownchinesethreatactor",
        "Unknown Chinese threat actor",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownchineselinkedgroup",
        "Unknown Chinese-linked group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownchinesespeakingthreatactor",
        "Unknown Chinese-speaking threat actor",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknowncriminalfraudring",
        "Unknown Criminal Fraud Ring",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknowncryptocurrencyscammergroup",
        "Unknown cryptocurrency scammer group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownrussianvpnserviceoperator",
        "Unknown Russian VPN Service Operator",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownscamnetwork",
        "Unknown Scam Network",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownsextortionscammers",
        "Unknown sextortion scammers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unknownstatebackedgroup",
        "Unknown State-Backed Group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unnamedchinesethreatactor",
        "Unnamed Chinese threat actor",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unnamedrussianthreatactors",
        "Unnamed Russian threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "chinaalignedthreatactors",
        "China-aligned threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "chinalinkedhackers",
        "China-linked hackers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "chinesethreatgroups",
        "Chinese threat groups",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "chinesecriminalgangs",
        "Chinese criminal gangs",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "chinesetransnationalcriminalgroups",
        "Chinese transnational criminal groups",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "chinesetransnationalcriminalorganizations",
        "Chinese transnational criminal organizations",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "chinesespeakingapt",
        "Chinese-speaking APT",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "irancyberactors", "Iran (cyber actors)", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "iranaffiliatedhackers",
        "Iran-affiliated hackers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranalignedactors",
        "Iran-aligned actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "iranlinkedactors", "Iran-linked actors", "generic/junk descriptor entity, not a trackable actor"),
    ("threat_actor", "iranlinkedcrews", "Iran-linked crews", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "iranlinkedcybergroup",
        "Iran-linked cyber group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranlinkedhackers",
        "Iran-linked hackers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranlinkedthreatactors",
        "Iran-linked threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "iranianhackers", "Iranian hackers", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "iranianmilitaryconnectedgroups",
        "Iranian military-connected groups",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianmoislinkedthreatactors",
        "Iranian MOIS-linked threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianoperatorsandproxies",
        "Iranian operators and proxies",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "iranianredguard", "Iranian Red Guard", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "iranianstatesponsoredhackers",
        "Iranian state-sponsored hackers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianstatesponsoredsyndicates",
        "Iranian state-sponsored syndicates",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianthreatactors",
        "Iranian threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianaffiliatedactors",
        "Iranian-affiliated actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianaffiliatedapt",
        "Iranian-affiliated APT",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianaffiliatedaptgroup",
        "Iranian-affiliated APT group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianaffiliatedcyberactors",
        "Iranian-affiliated cyber actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianaffiliatedhackers",
        "Iranian-affiliated hackers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianaffiliatedthreatactors",
        "Iranian-affiliated threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianlinkedgroups",
        "Iranian-linked groups",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "iranianlinkedthreatactors",
        "Iranian-linked threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "russiacyberactors",
        "Russia (cyber actors)",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "russiaimplied", "Russia (implied)", "generic/junk descriptor entity, not a trackable actor"),
    ("threat_actor", "russianactors", "Russian actors", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "russiancybergroup",
        "Russian cyber group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "russiancyberespionageactors",
        "Russian cyberespionage actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "russianhackers", "Russian hackers", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "russianstateactors",
        "Russian state actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "russianstatesupportedactors",
        "Russian state-supported actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "russianthreatactors",
        "Russian threat actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "russianmilitaryservices",
        "Russian Military Services",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "russianspeakinginitialaccessbroker",
        "Russian-speaking initial access broker",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "northkoreanhackergroup",
        "North Korean hacker group",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "northkoreanitworkerschemes",
        "North Korean IT Worker Schemes",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "northkoreanthreatactor",
        "North Korean threat actor",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "dprkalignedactors",
        "DPRK-aligned actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "dprklinkedthreatactor",
        "DPRK-linked threat actor",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "eastasialinkedthreatactor",
        "East Asia-linked threat actor",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "suspectedchinesehackers",
        "Suspected Chinese Hackers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "suspectedchineseoperators",
        "Suspected Chinese operators",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "suspectediranianhackers",
        "Suspected Iranian Hackers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "multipleransomseekingcrews",
        "Multiple ransom-seeking crews",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "hackersforhire", "Hackers-for-Hire", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "uncuncategorized",
        "UNC (uncategorized)",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "unattributedopportunisticthreatactors",
        "Unattributed Opportunistic Threat Actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "johndoe", "John Doe", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "sexualexploitationactors",
        "sexual exploitation actors",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    ("threat_actor", "l", "L", "generic/junk descriptor entity, not a trackable actor"),
    (
        "threat_actor",
        "cambodiabasedscamnetwork",
        "Cambodia-based scam network",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "threat_actor",
        "cambodianscamcenters",
        "Cambodian scam centers",
        "generic/junk descriptor entity, not a trackable actor",
    ),
    (
        "malware_family",
        "ransomwarepayloads",
        "ransomware payloads",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "ransomwaregeneral",
        "Ransomware (general)",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "ransomwareunnamed",
        "Ransomware (unnamed)",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "unknownransomware", "Unknown Ransomware", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "cryptostealer", "Crypto Stealer", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "informationstealer",
        "Information Stealer",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "infostealermalware",
        "infostealer malware",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "infostealermodule", "Infostealer Module", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "infostealerrat", "Infostealer RAT", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "infostealers", "Infostealers", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "credentialstealingmalware",
        "Credential-stealing malware",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "nodejsinfostealer", "NodeJS Infostealer", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "pythonbasedbackdoor",
        "Python-based backdoor",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "pythonbasedinfostealer",
        "Python-based infostealer",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "gobasedmacosmalware",
        "Go-based macOS malware",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "gobasedmacosstealer",
        "Go-based macOS Stealer",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "gobasedimplant", "Go-based implant", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "rustbasedbackdoor",
        "Rust-based backdoor",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "malware", "malware", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "malwaredropper", "malware dropper", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "malwarewiper", "malware wiper", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "macmalware", "Mac Malware", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "androidmalware", "Android malware", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "androidbankingtrojan",
        "Android Banking Trojan",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "trojans", "Trojans", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "we2trojan", "W32.Trojan", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "botnet", "Botnet", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "wiper", "Wiper", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "keylogger", "Keylogger", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "webshell", "webshell", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "remoteaccesstool", "Remote Access Tool", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "remoteaccesstrojan",
        "Remote Access Trojan",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "remoteaccesstrojanrat",
        "Remote Access Trojan (RAT)",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "crossplatformratinfostealer",
        "Cross-platform RAT/infostealer",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "cryptominers", "Cryptominers", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "cryptominer", "Crypto Miner", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "monerocryptominer",
        "Monero crypto miner",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "monerominersxmrigxmrstak",
        "Monero miners (xmrig, xmr-stak)",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "linuxcryptominer", "Linux Cryptominer", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "lnkmalware", "LNK malware", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "htapayload", "HTA payload", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "customloader", "Custom loader", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "reflectiveloader", "reflective loader", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "persistencemodule", "persistence module", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "digitalskimming", "digital skimming", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "formjacking", "formjacking", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "eskimming", "eskimming", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "inbrowsermalware", "In-Browser Malware", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "aipoweredransomware",
        "AI-powered ransomware",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "payload", "Payload", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "dangerousobjectmultigeneric",
        "DangerousObject.Multi.Generic",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "malwaredeliveredviawirelessconnection",
        "Malware delivered via wireless connection",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "maliciouspypipackage",
        "Malicious PyPI Package",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "maliciouspythonpackage",
        "Malicious Python Package",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "pypimalware", "PyPI Malware", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "trojanizednpmpackages",
        "trojanized npm packages",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "npmpackagebackdoor",
        "Npm Package Backdoor",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "rootkitstylepayloads",
        "Rootkit-style payloads",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "routerbackdoor", "Router Backdoor", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "unknownlogger", "Unknown Logger", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "netinfostealer", ".NET infostealer", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "trojandropper", "Trojan.Dropper", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "malicioussetuppy", "malicious setup.py", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "maliciouscodeinsoftwareproject",
        "Malicious Code in Software Project",
        "generic/junk/filename entity, not a malware family",
    ),
    (
        "malware_family",
        "clickfixmalwaregobased",
        "ClickFix malware (Go-based)",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "sshbot", "SSH Bot", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "psl", "PS1", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "payloadexe", "payload.exe", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "svhostexe", "svhost.exe", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "msidll", "msi.dll", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "bitmapexe", "bitmap.exe", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "wkhpdexe", "wkhpd.exe", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "createtsmediaadmdll",
        "createtsmediaadm.dll",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "nativecachesvcdll", "nativecachesvc.dll", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "inicorev2eeodll", "inicore_v2.3.30.dll", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "stylecsaspx", "stylecs.aspx", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "stylecssaspx", "stylecss.aspx", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "testaspx", "test.aspx", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "payaspx", "pay.aspx", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "emerrunphp", "emer-run.php", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "gctxt", "gc.txt", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "w2js", "w2.js", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "xjs", "x.js", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "capturepsl", "capture.Ps1", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "distlua", "Dist.lua", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "mathsymboljs", "Math_Symbol.js", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "defenderupdatejs", "DefenderUpdate.Js", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "updatemsmsi", "update_ms.msi", "generic/junk/filename entity, not a malware family"),
    ("malware_family", "zoomupdatevbs", "zoom-update.vbs", "generic/junk/filename entity, not a malware family"),
    (
        "malware_family",
        "zoomupdateinstallerpkg",
        "ZoomUpdateInstaller.pkg",
        "generic/junk/filename entity, not a malware family",
    ),
    ("malware_family", "readme", "readme", "generic/junk/filename entity, not a malware family"),
    ("offensive_tool", "backupdir", "--backup-dir", "command-line flag/option, not a tool"),
    ("offensive_tool", "copyunsafelinks", "--copy-unsafe-links", "command-line flag/option, not a tool"),
    ("offensive_tool", "logfile", "--log-file", "command-line flag/option, not a tool"),
    ("offensive_tool", "partialdir", "--partial-dir", "command-line flag/option, not a tool"),
    ("offensive_tool", "prefix", "--prefix", "command-line flag/option, not a tool"),
    ("offensive_tool", "template", "--template", "command-line flag/option, not a tool"),
    ("offensive_tool", "uploadpackparameter", "--upload-pack parameter", "command-line flag/option, not a tool"),
    ("offensive_tool", "zt", "--zt", "command-line flag/option, not a tool"),
    ("offensive_tool", "d", "-D", "command-line flag/option, not a tool"),
    ("offensive_tool", "absint", "absint()", "code function/method call, not a tool"),
    ("offensive_tool", "adkprtriagingagent", "adk_pr_triaging_agent", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "allowattachmentactions", "allow_attachment_actions()", "code function/method call, not a tool"),
    ("offensive_tool", "arrayindexnospec", "array_index_nospec()", "code function/method call, not a tool"),
    ("offensive_tool", "athlokhalt", "ath10k_halt()", "code function/method call, not a tool"),
    (
        "offensive_tool",
        "awsafetchclientbuildurl",
        "Aws4FetchClient.buildUrl()",
        "code function/method call, not a tool",
    ),
    ("offensive_tool", "awsafetchclientpresign", "Aws4FetchClient.presign()", "code function/method call, not a tool"),
    ("offensive_tool", "bcmgeneteeeenableset", "bcmgenet_eee_enable_set", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "bitmapset", "bitmap_set()", "code function/method call, not a tool"),
    ("offensive_tool", "bpfoverridereturn", "bpf_override_return", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "bpfprobewriteuser", "bpf_probe_write_user", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "cephhandlecaps", "ceph_handle_caps()", "code function/method call, not a tool"),
    ("offensive_tool", "checkmuloverflow", "check_mul_overflow()", "code function/method call, not a tool"),
    ("offensive_tool", "checkauth", "CheckAuth()", "code function/method call, not a tool"),
    ("offensive_tool", "childprocess", "child_process", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "childprocessspawn", "child_process.spawn()", "code function/method call, not a tool"),
    ("offensive_tool", "cr", "Cr...", "template placeholder / artifact string, not a tool"),
    ("offensive_tool", "crushdecode", "crush_decode()", "code function/method call, not a tool"),
    ("offensive_tool", "cve2ol8ls982", "CVE-2018-15982", "CVE identifier, not a tool"),
    ("offensive_tool", "cve2o26l9s98", "CVE-2026-19598", "CVE identifier, not a tool"),
    ("offensive_tool", "cve2o26ssaol", "CVE-2026-55401", "CVE identifier, not a tool"),
    ("offensive_tool", "cve2o26s82el", "CVE-2026-58231", "CVE identifier, not a tool"),
    ("offensive_tool", "cve2o26s8ela", "CVE-2026-58314", "CVE identifier, not a tool"),
    ("offensive_tool", "cve2o26t2t9e", "CVE-2026-72793", "CVE identifier, not a tool"),
    ("offensive_tool", "debugfsremove", "debugfs_remove()", "code function/method call, not a tool"),
    (
        "offensive_tool",
        "disabledelayedworksync",
        "disable_delayed_work_sync()",
        "code function/method call, not a tool",
    ),
    (
        "offensive_tool",
        "dockerimagefieldinterpolationmechanisminbuildremotedocker",
        "dockerImage field interpolation mechanism in buildRemoteDocker()",
        "code function/method call, not a tool",
    ),
    ("offensive_tool", "elasticsearchmemory", "elasticsearch_memory", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "extrahoprevealx", "ExtraHop Reveal(x)", "code function/method call, not a tool"),
    (
        "offensive_tool",
        "flexapicontrollerupdate",
        "Flex ApiController::update()",
        "code function/method call, not a tool",
    ),
    ("offensive_tool", "fscryptdirectkey", "fscrypt_direct_key", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "fscryptgetdevices", "fscrypt_get_devices()", "code function/method call, not a tool"),
    ("offensive_tool", "fwnodeinit", "fwnode_init()", "code function/method call, not a tool"),
    ("offensive_tool", "genevechangelink", "geneve_changelink()", "code function/method call, not a tool"),
    ("offensive_tool", "goodixi2cread", "goodix_i2c_read()", "code function/method call, not a tool"),
    ("offensive_tool", "hidhwstop", "hid_hw_stop()", "code function/method call, not a tool"),
    ("offensive_tool", "ieee8o2llmlegetmldid", "ieee80211_mle_get_mld_id()", "code function/method call, not a tool"),
    (
        "offensive_tool",
        "ionettyhandlercodecxmlxmlframedecoderdecode",
        "io.netty.handler.codec.xml.XmlFrameDecoder.decode()",
        "code function/method call, not a tool",
    ),
    ("offensive_tool", "iouring", "io_uring", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "ioremap", "ioremap()", "code function/method call, not a tool"),
    ("offensive_tool", "ipvsconnnew", "ip_vs_conn_new()", "code function/method call, not a tool"),
    ("offensive_tool", "kobjectrelease", "k_object_release()", "code function/method call, not a tool"),
    ("offensive_tool", "kmallocfixflags", "kmalloc_fix_flags", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "kmemdup", "kmemdup()", "code function/method call, not a tool"),
    ("offensive_tool", "ksmbds", "ksmbd_s...", "template placeholder / artifact string, not a tool"),
    ("offensive_tool", "listdel", "list_del()", "code function/method call, not a tool"),
    ("offensive_tool", "luduswsus", "ludus_wsus", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "macsecencrypt", "macsec_encrypt()", "code function/method call, not a tool"),
    ("offensive_tool", "markhtmlstring", "markHTMLString()", "code function/method call, not a tool"),
    ("offensive_tool", "masscancloud", "masscan[.]cloud", "template placeholder / artifact string, not a tool"),
    ("offensive_tool", "mds", "md5('')", "code function/method call, not a tool"),
    ("offensive_tool", "memomemory", "mem0_memory", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "middleware", "middleware()", "code function/method call, not a tool"),
    ("offensive_tool", "mlxsstidxdata", "mlx5_st_idx_data", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "mongodbmemory", "mongodb_memory", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "pdreadjson", "pd.read_json()", "code function/method call, not a tool"),
    ("offensive_tool", "phpeval", "PHP eval()", "code function/method call, not a tool"),
    ("offensive_tool", "processexit", "process.exit()", "code function/method call, not a tool"),
    ("offensive_tool", "pskbmaypull", "pskb_may_pull()", "code function/method call, not a tool"),
    ("offensive_tool", "qdiscgetrtab", "qdisc_get_rtab()", "code function/method call, not a tool"),
    ("offensive_tool", "qedcxttablesalloc", "qed_cxt_tables_alloc()", "code function/method call, not a tool"),
    ("offensive_tool", "rtlbtparsefirmware", "rtlbt_parse_firmware", "kernel/library code symbol, not a tool"),
    ("offensive_tool", "shellexec", "shell_exec()", "code function/method call, not a tool"),
    ("offensive_tool", "slreallocbufs", "sl_realloc_bufs()", "code function/method call, not a tool"),
    ("offensive_tool", "sleeps", "sleep(5)", "code function/method call, not a tool"),
    ("offensive_tool", "sofgetcontroldata", "sof_get_control_data()", "code function/method call, not a tool"),
    ("offensive_tool", "validatetemplate", "validate_template", "kernel/library code symbol, not a tool"),
    (
        "offensive_tool",
        "wpajaxnoprivsixstoragecreatewpuser",
        "wp_ajax_nopriv_six_storage_create_wp_user",
        "kernel/library code symbol, not a tool",
    ),
    ("offensive_tool", "wpsetauthcookie", "wp_set_auth_cookie()", "code function/method call, not a tool"),
    ("offensive_tool", "wpupdateuser", "wp_update_user()", "code function/method call, not a tool"),
    ("offensive_tool", "wpuseraddrole", "WP_User::add_role()", "code function/method call, not a tool"),
    ("offensive_tool", "wpusersetrole", "WP_User::set_role()", "code function/method call, not a tool"),
    ("offensive_tool", "x2skillbyneigh", "x25_kill_by_neigh()", "code function/method call, not a tool"),
    ("offensive_tool", "dnsfloods", "DNS floods", "generic concept/phrase/physical-object, not an offensive tool"),
    (
        "offensive_tool",
        "deepfaketools",
        "Deepfake tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "aideepfaketools",
        "AI deepfake tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "facechangingsoftware",
        "Face-changing software",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "aivoicecloning",
        "AI voice cloning",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "legitimateadnetworks",
        "Legitimate Ad Networks",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "legitimatepdfapplication",
        "Legitimate PDF Application",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "legitimateremoteaccesstools",
        "Legitimate Remote Access Tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "remotedesktopsoftware",
        "Remote Desktop Software",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "remotemanagementtools",
        "Remote Management Tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    ("offensive_tool", "rmmtools", "RMM tools", "generic concept/phrase/physical-object, not an offensive tool"),
    ("offensive_tool", "dfirtools", "DFIR tools", "generic concept/phrase/physical-object, not an offensive tool"),
    ("offensive_tool", "edrkillers", "EDR Killers", "generic concept/phrase/physical-object, not an offensive tool"),
    (
        "offensive_tool",
        "edrkillertools",
        "EDR-killer tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "edrkillertooling",
        "EDR-killer tooling",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "edrdisablingtoolkit",
        "EDR disabling toolkit",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "gobasedexploittools",
        "Go-based exploit tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "rubybasedexploittools",
        "Ruby-based exploit tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "dnshijackingtools",
        "DNS Hijacking Tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "dnsresolutiontoolsimplied",
        "DNS resolution tools (implied)",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "blockchainanalyticstools",
        "Blockchain analytics tools",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "cybercrimeasaserviceplatforms",
        "Cybercrime-as-a-Service platforms",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "residentialproxynetwork",
        "Residential Proxy Network",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "residentialproxyservices",
        "residential proxy services",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "blockchainbackedservices",
        "Blockchain-backed services",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "cryptocurrencymixers",
        "Cryptocurrency mixers",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "virtualprivatenetworksvpns",
        "Virtual Private Networks (VPNs)",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "customphishingkits",
        "Custom Phishing Kits",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "custombackdoor",
        "custom backdoor",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "customloader",
        "custom loader",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "custominformationharvestingtool",
        "Custom Information Harvesting Tool",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "cityforumcustomgotool",
        "City-Forum custom Go tool",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "cityforumcustomtooling",
        "City-Forum custom tooling",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "cityforumtoolset",
        "City-Forum Toolset",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "privilegeescalationtool",
        "Privilege Escalation Tool",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "rustbasedmalwareloader",
        "Rust-based malware loader",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "javascriptbasedloader",
        "JavaScript-based loader",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "javascriptdropper",
        "JavaScript dropper",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "goreverseshell",
        "Go reverse shell",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "gobasedsshclient",
        "Go-based SSH client",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "pythonrdpclient",
        "Python RDP client",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "reversesocksproxy",
        "Reverse SOCKS Proxy",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "reversesshtunnel",
        "Reverse SSH Tunnel",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "ocrlibraries",
        "OCR libraries",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "nodebuiltins",
        "Node built-ins",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "shellbasedgitclonecommands",
        "shell-based Git clone commands",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "unnamedresearchmodel",
        "Unnamed research model",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "proofofconceptandroidapp",
        "Proof-of-Concept Android App",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "rapidtspythonbasedpoc",
        "Rapid7's Python-based PoC",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    ("offensive_tool", "deohowitzer", "D-30 howitzer", "generic concept/phrase/physical-object, not an offensive tool"),
    (
        "offensive_tool",
        "banderoldrone",
        "Banderol drone",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    ("offensive_tool", "lancetdrone", "Lancet drone", "generic concept/phrase/physical-object, not an offensive tool"),
    (
        "offensive_tool",
        "lightningdrone",
        "Lightning drone",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "mohajerdrone",
        "Mohajer drone",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    ("offensive_tool", "molniya", "Molniya", "generic concept/phrase/physical-object, not an offensive tool"),
    ("offensive_tool", "xs9missile", "X-59 missile", "generic concept/phrase/physical-object, not an offensive tool"),
    ("offensive_tool", "zaladrone", "ZALA drone", "generic concept/phrase/physical-object, not an offensive tool"),
    ("offensive_tool", "tfll", "TFL-1", "generic concept/phrase/physical-object, not an offensive tool"),
    ("offensive_tool", "v2u", "V2U", "generic concept/phrase/physical-object, not an offensive tool"),
    ("offensive_tool", "skynodes", "Skynode S", "generic concept/phrase/physical-object, not an offensive tool"),
    (
        "offensive_tool",
        "leetopcarrierboard",
        "Leetop carrier board",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "abbvariablefrequencydrive",
        "ABB variable frequency drive",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "schneiderelectricvariablefrequencydrive",
        "Schneider Electric variable frequency drive",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "karrsecuritysystem",
        "KARR Security System",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "h96streamingdevice",
        "H96 Streaming Device",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    (
        "offensive_tool",
        "lootsoftwareaoutlookcom",
        "lootsoftware@outlook.com",
        "generic concept/phrase/physical-object, not an offensive tool",
    ),
    ("offensive_tool", "2facn", "2fa.cn", "generic concept/phrase/physical-object, not an offensive tool"),
]


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    op.execute(ENTITY_NORM_FN_SQL)

    for _slug, table in ENTITY_TABLES:
        op.execute(
            f"ALTER TABLE {table} ADD COLUMN normalized_name varchar(255) "
            f"GENERATED ALWAYS AS (entity_norm(name)) STORED"
        )
        op.create_index(f"ix_{table}_normalized_name", table, ["normalized_name"])
        op.execute(f"CREATE INDEX ix_{table}_normalized_trgm ON {table} USING gin (normalized_name gin_trgm_ops)")

    op.create_table(
        "entity_alias_index",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("entity_type", sa.String(30), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("surface", sa.Text(), nullable=False),
        sa.Column("normalized", sa.String(255), nullable=False),
        sa.Column("is_name", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("entity_type", "entity_id", "normalized", name="uq_entity_alias_index_row"),
    )
    op.create_index("ix_entity_alias_index_entity_id", "entity_alias_index", ["entity_id"])
    op.create_index("ix_entity_alias_index_lookup", "entity_alias_index", ["entity_type", "normalized"])
    op.create_index("ix_entity_alias_index_normalized", "entity_alias_index", ["normalized"])
    op.execute("CREATE INDEX ix_entity_alias_index_trgm ON entity_alias_index USING gin (normalized gin_trgm_ops)")

    op.execute(ALIAS_INDEX_TRIGGER_FN_SQL)
    for slug, table in ENTITY_TABLES:
        op.execute(
            f"CREATE TRIGGER trg_{table}_alias_index "
            f"AFTER INSERT OR DELETE OR UPDATE OF name, aliases ON {table} "
            f"FOR EACH ROW EXECUTE FUNCTION sync_entity_alias_index('{slug}')"
        )
        # Backfill existing rows (same shape the trigger produces).
        op.execute(
            f"""
            INSERT INTO entity_alias_index (id, entity_type, entity_id, surface, normalized, is_name)
            SELECT gen_random_uuid(), '{slug}', t.id, f.surface, entity_norm(f.surface), f.is_name
            FROM {table} t
            CROSS JOIN LATERAL (
                SELECT t.name AS surface, true AS is_name
                UNION ALL
                SELECT a, false FROM unnest(COALESCE(t.aliases, '{{}}'::text[])) AS a
            ) f
            WHERE f.surface IS NOT NULL AND entity_norm(f.surface) <> ''
            ON CONFLICT (entity_type, entity_id, normalized) DO NOTHING
            """
        )

    denylist = op.create_table(
        "entity_name_denylist",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("entity_type", sa.String(30), nullable=False),
        sa.Column("normalized_name", sa.String(255), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("source", sa.String(40), nullable=False, server_default="manual"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.UniqueConstraint("entity_type", "normalized_name", name="uq_entity_name_denylist"),
    )
    op.create_index(
        "ix_entity_name_denylist_lookup", "entity_name_denylist", ["entity_type", "normalized_name", "active"]
    )
    op.bulk_insert(
        denylist,
        [
            {
                "entity_type": entity_type,
                "normalized_name": normalized,
                "display_name": display,
                "reason": reason,
                "source": "cleanup_2026_08",
            }
            for entity_type, normalized, display, reason in DENYLIST_SEED
        ],
    )


def downgrade() -> None:
    op.drop_table("entity_name_denylist")
    for _slug, table in ENTITY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{table}_alias_index ON {table}")
    op.execute("DROP FUNCTION IF EXISTS sync_entity_alias_index()")
    op.drop_table("entity_alias_index")
    for _slug, table in ENTITY_TABLES:
        op.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS normalized_name")
    op.execute("DROP FUNCTION IF EXISTS entity_norm(text)")
