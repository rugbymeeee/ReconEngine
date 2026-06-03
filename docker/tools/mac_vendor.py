"""
Lookup constructeur depuis l'adresse MAC (IEEE OUI - Organizationally Unique
Identifier sur les 3 premiers octets).

Deux sources, par ordre de priorité :
  1. Base système complète (~52 000 OUI) si disponible — typiquement
     `/usr/share/nmap/nmap-mac-prefixes`, livrée avec nmap (déjà une dépendance).
     Chargée une seule fois, en cache mémoire.
  2. Liste curée embarquée (ci-dessous) — fabricants les plus fréquents en
     environnement PME / domestique, labels affinés (Hyper-V, QEMU/KVM…).
     Sert de fallback offline sur PCB et **surcharge** la base système pour les
     préfixes qu'elle définit (labels plus parlants pour l'audit).

En plus du constructeur, le module distingue :
  - les MAC **localement administrées** (2ᵉ bit de poids faible du 1ᵉʳ octet) :
    typiquement les MAC **aléatoires** des téléphones (vie privée) ou les
    conteneurs Docker (`02:42:…`) — un lookup OUI y est inutile ;
  - les MAC **multicast/broadcast** (1ᵉʳ bit du 1ᵉʳ octet).
"""
import logging
import os
import re

log = logging.getLogger(__name__)

# Format clé : 6 hex uppercase sans séparateur (3 premiers octets).
# Format valeur : nom court du constructeur.
OUI_PREFIXES: dict[str, str] = {
    # ── Apple ─────────────────────────────────────────────────────────────────
    "000393": "Apple", "000A27": "Apple", "000A95": "Apple", "000D93": "Apple",
    "0010FA": "Apple", "001124": "Apple", "001451": "Apple", "0016CB": "Apple",
    "0017F2": "Apple", "0019E3": "Apple", "001B63": "Apple", "001CB3": "Apple",
    "001D4F": "Apple", "001E52": "Apple", "001EC2": "Apple", "001F5B": "Apple",
    "001FF3": "Apple", "0021E9": "Apple", "002241": "Apple", "002312": "Apple",
    "002332": "Apple", "00236C": "Apple", "0023DF": "Apple", "002436": "Apple",
    "002500": "Apple", "00254B": "Apple", "0025BC": "Apple", "002608": "Apple",
    "00264A": "Apple", "0026B0": "Apple", "0026BB": "Apple", "003065": "Apple",
    "003EE1": "Apple", "0050E4": "Apple", "0056CD": "Apple", "1093E9": "Apple",
    "7C6DF8": "Apple", "A4C361": "Apple", "BC52B7": "Apple", "D49A20": "Apple",
    "F0DBE2": "Apple",

    # ── Microsoft / Surface / Hyper-V / Xbox ──────────────────────────────────
    "00125A": "Microsoft", "0015F2": "Microsoft", "00155D": "Microsoft (Hyper-V)",
    "001DD8": "Microsoft", "0050F2": "Microsoft", "28186D": "Microsoft (Surface)",
    "84A93E": "Microsoft (Surface)", "0024CB": "Microsoft (Xbox)",

    # ── Virtualisation ────────────────────────────────────────────────────────
    "005056": "VMware", "000C29": "VMware", "001C14": "VMware",
    "080027": "VirtualBox (Oracle)", "0A0027": "VirtualBox (Oracle)",
    "525400": "QEMU/KVM",
    "001C42": "Parallels",
    "001585": "Citrix XenServer",

    # ── Raspberry Pi / Single Board Computers ─────────────────────────────────
    "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi", "E45F01": "Raspberry Pi",
    "2CCF67": "Raspberry Pi", "D83ADD": "Raspberry Pi",
    "02FEED": "Orange Pi",

    # ── Réseau d'entreprise ───────────────────────────────────────────────────
    "001A2F": "Cisco", "001B0C": "Cisco", "001E13": "Cisco", "0023AC": "Cisco",
    "00237D": "Cisco", "0024C4": "Cisco", "002584": "Cisco", "002BD7": "Cisco",
    "002A10": "Cisco", "0E25E8": "Cisco", "104F58": "Cisco",
    "001346": "HP",   "001438": "HP",   "002564": "HP",   "0026F1": "HP",
    "001321": "HP Networking", "001A4B": "HP Networking",
    "F40343": "HP / Aruba", "94F128": "HP / Aruba",
    "001B21": "Intel", "001F3C": "Intel", "5C514F": "Intel", "001E64": "Intel",
    "F8348A": "Intel",
    "001E68": "Aruba",
    "000B6B": "Fortinet", "00090F": "Fortinet",
    "001372": "Dell",  "00219B": "Dell",  "00248C": "Dell",  "B8CA3A": "Dell",
    "F8B156": "Dell",
    "00188B": "Lenovo", "002414": "Lenovo", "F8DA0C": "Lenovo",
    "001125": "IBM",  "002255": "IBM",
    "001736": "ASUS", "B06EBF": "ASUS",  "30B4B8": "ASUS",
    "0017A4": "ASUS",
    "0018F3": "ASRock",
    "002522": "Dell",
    "0017F4": "MSI",

    # ── Routeurs / Switches grand public ──────────────────────────────────────
    "001D0F": "TP-Link", "00148E": "TP-Link", "9C5322": "TP-Link", "B0BE76": "TP-Link",
    "00226B": "Linksys", "001839": "Linksys",
    "002129": "Netgear", "0024B2": "Netgear", "10DA43": "Netgear",
    "0023CD": "D-Link", "001CF0": "D-Link", "0019EB": "D-Link",
    "744401": "Ubiquiti", "B4FBE4": "Ubiquiti", "F09FC2": "Ubiquiti",
    "78A351": "MikroTik", "4C5E0C": "MikroTik", "CC2DE0": "MikroTik",
    "001CDF": "Belkin", "08863B": "Belkin", "0024A8": "Belkin",

    # ── NAS / Stockage ────────────────────────────────────────────────────────
    "001132": "Synology", "0011323": "Synology",
    "00089B": "QNAP", "245EBE": "QNAP",
    "0090A9": "Western Digital", "00908A": "Western Digital",
    "0024A5": "Buffalo",

    # ── Imprimantes ───────────────────────────────────────────────────────────
    "001E0B": "HP (printer)", "BCEAFA": "HP (printer)",
    "001485": "Canon", "00BB3A": "Canon",
    "0080A1": "Brother",
    "0023A7": "Epson", "0026AB": "Epson",
    "002086": "Xerox", "000048": "Xerox",
    "001349": "Konica Minolta",

    # ── Google / Nest / Chromecast ────────────────────────────────────────────
    "089E08": "Google", "188B45": "Google", "3C5AB4": "Google",
    "6CADF8": "Google", "9495A0": "Google", "94EB2C": "Google",
    "A47733": "Google", "F4F5D8": "Google", "F4F5E8": "Google",
    "F88FCA": "Google",
    "18B430": "Google (Nest)",

    # ── Amazon (Echo / Ring / Kindle / Fire TV) ───────────────────────────────
    "044BED": "Amazon", "0C47C9": "Amazon", "34D270": "Amazon",
    "40B4CD": "Amazon", "44650D": "Amazon", "50F5DA": "Amazon",
    "6837E9": "Amazon", "6854FD": "Amazon", "8871E5": "Amazon",
    "AC63BE": "Amazon", "B47C9C": "Amazon", "F0272D": "Amazon",
    "F0D2F1": "Amazon", "FCA183": "Amazon",
    "8C0F8F": "Amazon (Ring)",

    # ── Sonos (enceintes multiroom) ───────────────────────────────────────────
    "000E58": "Sonos", "5CAAFD": "Sonos", "78282A": "Sonos",
    "949F3E": "Sonos", "B8E937": "Sonos",

    # ── Roku (streamers TV) ───────────────────────────────────────────────────
    "B0EE45": "Roku", "B83E59": "Roku", "B8A175": "Roku", "DC3A5E": "Roku",

    # ── Philips / Hue / Bose / Beats / Polycom / Sennheiser ──────────────────
    "001788": "Philips Hue", "B0CE18": "Philips",
    "0C8A87": "Bose",
    "0488E2": "Beats Electronics",
    "0004F2": "Polycom", "64167F": "Polycom",

    # ── Fitbit / wearables ────────────────────────────────────────────────────
    "1800DB": "Fitbit",

    # ── GoPro (caméras) ───────────────────────────────────────────────────────
    "D89695": "GoPro", "D8D919": "GoPro", "F4DD9E": "GoPro",

    # ── Hikvision (caméras IP / DVR) ──────────────────────────────────────────
    "1868CB": "Hikvision", "4419B6": "Hikvision",

    # ── JVC / Kenwood (audio auto) ────────────────────────────────────────────
    "E0DADC": "JVC Kenwood",

    # ── Consoles / Multimédia ─────────────────────────────────────────────────
    "001FE2": "Sony PlayStation", "0024BE": "Sony PlayStation",
    "0CFE45": "Sony", "001A80": "Sony",
    "001DBA": "Nintendo", "002709": "Nintendo", "B8AE6E": "Nintendo",
    "9CE635": "Nintendo Switch",
    "001FD7": "LG", "002493": "LG", "0026E2": "LG",
    "001632": "Samsung", "001D25": "Samsung", "002399": "Samsung",
    "F89E94": "Samsung", "BC6E64": "Samsung",

    # ── Téléphonie / Mobile ───────────────────────────────────────────────────
    "001146": "Nokia", "0024BC": "Nokia",
    "001E10": "Huawei", "001882": "Huawei", "00259E": "Huawei",
    "F47B5E": "Huawei", "0CC47A": "Huawei",
    # Xiaomi (multiple OUI — un des plus présents en environnement BYOD)
    "0023CC": "Xiaomi", "14F65A": "Xiaomi", "286C07": "Xiaomi",
    "28E31F": "Xiaomi", "34CE00": "Xiaomi", "38A4ED": "Xiaomi",
    "64B473": "Xiaomi", "64CC2E": "Xiaomi", "742344": "Xiaomi",
    "7451BA": "Xiaomi", "7C1DD9": "Xiaomi", "8CBEBE": "Xiaomi",
    "9C99A0": "Xiaomi", "A086C6": "Xiaomi", "B0E235": "Xiaomi",
    "F0B429": "Xiaomi", "F8A45F": "Xiaomi", "FC64BA": "Xiaomi",
    # OPPO / OnePlus (GUANGDONG OPPO MOBILE)
    "1C77F6": "OPPO", "2C5BB8": "OPPO", "4C48DA": "OPPO",
    "BC3AEA": "OPPO", "CC2D83": "OPPO", "DC6DCD": "OPPO",
    "EC01EE": "OPPO",
    # HTC
    "188796": "HTC", "38E7D8": "HTC", "64A769": "HTC",
    "90E7C4": "HTC", "A0F450": "HTC", "BCCFCC": "HTC",
    "D40B1A": "HTC", "D8B377": "HTC", "E899C4": "HTC",

    # ── Chipsets réseau communs (souvent vu sur des cartes mères / IoT) ───────
    "00E04C": "Realtek",
    "00908F": "Broadcom",
    "001656": "Marvell",
}


# Bases système candidates (la première lisible gagne). Surchargée par
# l'env var RECONENGINE_OUI_DB. Format attendu : « <hex OUI> <nom> » par ligne,
# séparateurs ignorés dans le préfixe (compatible nmap-mac-prefixes et
# arp-scan/ieee-oui.txt).
_SYSTEM_DB_PATHS: tuple[str, ...] = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/arp-scan/ieee-oui.txt",
)

# Préfixe Docker : 02:42 + 4 octets dérivés de l'IP du conteneur. Pas un OUI
# IEEE réel, mais identifiant fiable et fréquent en audit.
_DOCKER_PREFIX = "0242"

_db_cache: dict[str, str] | None = None


def _candidate_paths() -> list[str]:
    paths: list[str] = []
    env = os.environ.get("RECONENGINE_OUI_DB")
    if env:
        paths.append(env)
    paths.extend(_SYSTEM_DB_PATHS)
    return paths


def _load_db() -> dict[str, str]:
    """
    Charge (une fois) la base OUI : système si dispo, puis surcharge curée.

    Fail-safe : si aucun fichier système lisible, retourne la liste curée seule.
    Le résultat est mis en cache pour toute la durée du process.
    """
    global _db_cache
    if _db_cache is not None:
        return _db_cache

    db: dict[str, str] = {}
    for path in _candidate_paths():
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    prefix = re.sub(r"[^0-9A-Fa-f]", "", parts[0]).upper()
                    if len(prefix) != 6:
                        continue
                    name = parts[1].strip()
                    if name:
                        db.setdefault(prefix, name)
        except OSError as e:  # noqa: BLE001
            log.debug("[OUI] Lecture %s échouée : %s", path, e)
            continue
        if db:
            log.debug("[OUI] %d préfixes chargés depuis %s", len(db), path)
            break

    # La liste curée surcharge la base système : labels affinés pour l'audit
    # (Hyper-V, QEMU/KVM, VirtualBox…) plus parlants qu'un nom IEEE brut.
    db.update(OUI_PREFIXES)
    _db_cache = db
    return db


def _norm(mac: str) -> str:
    """Normalise une MAC en 12 hex uppercase sans séparateurs."""
    if not mac:
        return ""
    return re.sub(r"[^0-9A-Fa-f]", "", mac).upper()


def _first_octet(mac: str) -> int | None:
    norm = _norm(mac)
    if len(norm) < 2:
        return None
    try:
        return int(norm[:2], 16)
    except ValueError:
        return None


def is_multicast(mac: str) -> bool:
    """True si la MAC est multicast/broadcast (1ᵉʳ bit du 1ᵉʳ octet à 1)."""
    octet = _first_octet(mac)
    return octet is not None and bool(octet & 0x01)


def is_locally_administered(mac: str) -> bool:
    """
    True si la MAC est localement administrée (2ᵉ bit du 1ᵉʳ octet à 1).

    Couvre les MAC aléatoires des smartphones (Android/iOS — vie privée), les
    conteneurs Docker (02:42:…) et certaines VM. Un lookup OUI IEEE y est vain.
    """
    octet = _first_octet(mac)
    return octet is not None and bool(octet & 0x02)


def vendor(mac: str) -> str:
    """
    Retourne le nom du constructeur depuis une MAC, ou "" si inconnu.

    Args:
        mac: Adresse MAC dans n'importe quel format (xx:xx:xx:xx:xx:xx, xx-xx-..., 12 hex bruts).

    Examples:
        >>> vendor("B8:27:EB:12:34:56")
        'Raspberry Pi'
        >>> vendor("00:50:56:AB:CD:EF")
        'VMware'
        >>> vendor("AA:BB:CC:DD:EE:FF")
        ''
    """
    norm = _norm(mac)
    if len(norm) < 6:
        return ""
    if norm.startswith(_DOCKER_PREFIX):
        return "Docker (conteneur)"
    return _load_db().get(norm[:6], "")


def label(mac: str) -> str:
    """
    Libellé d'identification matérielle lisible pour l'affichage / le rapport.

    Priorité au constructeur (lookup OUI, Docker, VM). À défaut, qualifie la
    nature de la MAC plutôt que de renvoyer du vide :
      - localement administrée → "MAC aléatoire (vie privée)" ;
      - sinon → "" (réellement inconnue).

    Examples:
        >>> label("B8:27:EB:12:34:56")
        'Raspberry Pi'
        >>> label("7E:ED:ED:C6:90:DF")   # bit localement administré
        'MAC aléatoire (vie privée)'
    """
    v = vendor(mac)
    if v:
        return v
    # MAC aléatoire = unicast + localement administrée (les téléphones modernes).
    # On exclut le multicast/broadcast, qui n'identifie jamais un hôte.
    if is_locally_administered(mac) and not is_multicast(mac):
        return "MAC aléatoire (vie privée)"
    return ""
