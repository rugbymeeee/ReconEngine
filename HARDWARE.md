# Bill of Materials — ReconEngine PCB

Build minimaliste et fonctionnel basé sur l'Orange Pi Zero 3. Chaque
composant est justifié par sa fonction réelle dans le pipeline ReconEngine.

> **Pas de :** 5G, GPS, LoRa, TPM, e-Ink, NVMe, OLED, fuel-gauge batterie.
> WeasyPrint tourne nativement avec 2 Go RAM — aucune adaptation logicielle requise.

---

## 1. Unité de calcul

### U1 — Orange Pi Zero 3 (2 Go)
**Allwinner H618 · 4× Cortex-A53 @ 1,5 GHz · 2 Go LPDDR4**

| Spec | Valeur |
|------|--------|
| Architecture | ARM64 (aarch64) |
| RAM | 2 Go LPDDR4 |
| WiFi embarqué (AW859A) | 802.11 a/b/g/n/ac (WiFi 5, 2,4/5 GHz) + BT 5.0 |
| Ethernet | 100 Mbps intégré (jack RJ45 sur le SBC) |
| USB | 1× USB 2.0 Type-C |
| GPIO | 26 broches (I²C, SPI, UART, PWM) |
| Stockage | microSD |
| Consommation | 0,6 W idle · 2,2 W charge max |
| Tension | 5 V |
| Format | 65 × 30 mm |

**Pourquoi :** Form factor compact, 2 Go LPDDR4 (assez pour WeasyPrint
+ matplotlib), 2 connecteurs antenne disponibles (1 onboard, 1 pour la
chip USB d'audit). H618 cloque 20% plus rapide que le BCM2711 du Pi Zero 2W.

> Le SBC fournit lui-même les connecteurs RJ45 et microSD, donc la PCB
> carrier n'a pas besoin de les passer-through.

---

## 2. WiFi d'audit — monitor mode + injection

### U3 — Realtek RTL8188EUS-VH-CG
**802.11n · 2,4 GHz · Monitor mode natif · Injection de paquets**

| Spec | Valeur |
|------|--------|
| Référence LCSC | C2828256 |
| Standard | 802.11b/g/n (max 150 Mbps) |
| Boîtier | LQFN-46 (6.5 × 4.5 mm) |
| Interface | USB 2.0 (côté upstream du hub GL850G) |
| Pilote Linux | `r8188eu` — mainline kernel 5.2+ |
| Monitor mode | Oui (aircrack-ng, Scapy, kismet) |
| Injection paquets | Oui |
| Consommation TX | 400 mA max |
| Antenne | RF2 (SMA femelle 18 GHz, sur PCB) |

**Pourquoi :** Pilote open source stable, monitor mode natif sans patch.
Le WiFi embarqué du Zero 3 (RF1) reste dédié à la connectivité management
(SSH, export, API HTTP). Cette chip gère exclusivement le scan et l'audit
réseau et apparaît en `wlan1` sous Linux.

---

## 3. Hub USB interne

### U11 — Genesys Logic GL850G-HHY60
**USB 2.0 hub 4 ports · Bus-powered**

| Spec | Valeur |
|------|--------|
| Référence LCSC | C7501406 |
| Boîtier | SSOP-28 |
| Ports | 4× USB 2.0 downstream |
| Interface | 1× USB 2.0 upstream (vers Orange Pi Zero 3) |
| Consommation | 80 mA |

**Pourquoi :** L'Orange Pi Zero 3 n'expose qu'un seul port USB-C. Le hub
permet de connecter simultanément la chip RTL8188EUS (audit WiFi) et le
port USB-A externe (USB2 — export des rapports, stockage USB additionnel).

---

## 4. Stockage

### CARD1 — Connecteur microSD TF-01A
**Référence LCSC : C91145**

| Spec | Valeur |
|------|--------|
| Format | microSD push-push |
| Empreinte | TF-SMD_TF-01A |

> La carte microSD elle-même n'est pas dans la BOM PCB. Recommandé :
> Samsung PRO Endurance 32 Go (UHS-I, conçue pour écriture continue,
> ~10 €) pour résister aux écritures fréquentes des logs / rapports.

---

## 5. Connecteurs

| Désignateur | Référence | Fonction | Réf. LCSC |
|---|---|---|---|
| USB1 | TYPE-C 16PIN (SHOU HAN) | Charge + data Type-C | C393939 |
| USB2 | 903-131A1011D10100 | USB-A 2.0 externe (export) | C46407 |
| RF1, RF2 | SMA-KE-5 (cntitle) | Antennes WiFi mgmt + audit (18 GHz) | C20415804 |
| CN1 | B2B-PH-K-S(LF)(SN) (JST) | Connexion cellule 18650 | C131337 |
| H1 | 2.54-1×4P reverse pin header | UART debug / programmation | C91552 |

---

## 6. Gestion de l'alimentation

Chaîne complète : **USB-C 5 V → TP4056 (charge Li-Ion) → Cellule 18650 →
DW01A + double MOSFET (protection) → MT3608 (boost 3,7 V → 5 V) →
Orange Pi Zero 3 (5 V) → AMS1117-3.3 (3,3 V auxiliaire)**

### U5 — TP4056 (charge Li-Ion via USB-C)
| Spec | Valeur |
|------|--------|
| Référence LCSC | C725790 |
| Boîtier | ESOP-8 |
| Courant de charge | 1 A (résistance programmable) |
| Tension batterie | 4,2 V (Li-Ion 1S) |
| Entrée | 5 V via USB1 (Type-C) |

### U8 + Q1/Q2 — Protection de cellule (DW01A + double N-MOSFET)
| Composant | Réf. | LCSC | Rôle |
|---|---|---|---|
| U8 — DW01A | PUOLOP (迪浦) | C351410 | Contrôleur de protection (over-charge, over-discharge, court-circuit) |
| Q1 — PJM8205DNSG | PJSEMI | C2917199 | Double N-MOSFET côté décharge |
| Q2 — FS8205A | TECH PUBLIC | C2830320 | Double N-MOSFET côté charge |

> Q1 et Q2 sont des doubles N-MOSFET en SOT-23-6 (paire commutée par DW01A
> pour couper indépendamment charge et décharge). Pas de fuel gauge — le
> niveau de batterie n'est pas exposé au logiciel.

### U6 — MT3608 (boost 3,7 V → 5 V)
| Spec | Valeur |
|------|--------|
| Référence LCSC | C84817 |
| Boîtier | SOT-23-6 |
| Entrée | 2 V – 24 V |
| Sortie | 5 V réglable, jusqu'à 2 A |
| Efficacité | 93% peak |

### U7 — AMS1117-3.3 (LDO 3,3 V)
| Spec | Valeur |
|------|--------|
| Référence LCSC | C6186 |
| Boîtier | SOT-223-3 |
| Sortie | 3,3 V / 1 A |

> Alimente les rails 3,3 V auxiliaires (chip WiFi audit, hub USB en cas de
> besoin). Le SoC du SBC est alimenté en 5 V via son propre régulateur interne.

### Cellule (hors BOM PCB) — 18650 Li-Ion 1S
Recommandé : **Samsung INR18650-25R (2 500 mAh, 3,7 V, 20 A max décharge,
~4–5 h scan continu)**. Format remplaçable standard, connecté à CN1.

### U9, U10 — Protection : fusibles polymère
| Spec | Valeur |
|------|--------|
| Référence | MF-MSMF200L-2 (BOURNS) — LCSC C89650 |
| Boîtier | F1812 |
| Courant de hold / trip | 2 A / ~3,5 A |

> 2 fusibles PTC ré-armables sur les rails 5 V critiques (entrée USB-C
> et sortie batterie). Évitent toute surconsommation accidentelle d'un
> périphérique branché en USB-A.

---

## 7. Indicateurs visuels

### LED1, LED2 — WS2812B-B/T (RGB adressables)
| Spec | Valeur |
|------|--------|
| Référence LCSC | C2761795 |
| Boîtier | SMD 5×5 mm, 4 broches |
| Pilotage | Chaîne série (DIN→DOUT), protocole one-wire |
| Tension | 5 V |

**Pilotage par ReconEngine** (`docker/tools/status.py`) :
- DIN câblé à **SPI MOSI** (`/dev/spidev1.0` par défaut)
- Encodage 4 bits SPI par bit WS2812B à 6,4 MHz
- États affichés :
  - 🔵 **Pulse bleu** — phase 1 (découverte ARP)
  - 🟠 **Chase orange** — phase 2 (scan nmap)
  - ⚪ **Pulse blanc** — phase 4 (rendu PDF)
  - 🟢 **Vert fixe** — terminé, aucun port critique
  - 🔴 **Rouge fixe** — terminé, au moins un port critique exposé
  - 🔴 **Rouge clignotant** — erreur d'exécution

### LED3, LED4 — LEDs 0402 discrètes
| Designator | Couleur | Fonction (driver status.py) |
|---|---|---|
| LED3 | jaune (0402-RD_YELLOW) | Activité / découverte en cours |
| LED4 | verte (0402-RD_YELLOW empreinte commune) | Power-good / scan OK |

Pilotage via **libgpiod** sur `/dev/gpiochip0` — offsets configurables
via `RECONENGINE_LED_YELLOW_GPIO` / `RECONENGINE_LED_GREEN_GPIO` (défauts :
71 et 76 — à ajuster selon le routage PCB final).

> Le driver `status.py` se désactive **silencieusement** si `gpiod`/`spidev`
> ne sont pas installés ou si les devices ne sont pas présents (dev machine,
> container sans accès `/dev`). Installation sur le PCB :
> ```bash
> pip install reconengine[hardware]
> ```

---

## 8. Passifs et résistances

| Designator | Valeur | Rôle |
|---|---|---|
| C1, C2 | 12 pF (0603) | Découplage / oscillateur |
| L1 | 4,7 µH (0603) | Inductance du boost MT3608 |
| R1 | 2 kΩ (0603) | Polarisation |
| R2, R3 | 1 kΩ (0603) | Pull-up / limitation LED |
| R4 | 10 kΩ (0603) | Pull-up générique |
| R5 | 68 kΩ (0603) | Programmation courant charge TP4056 (~1 A) |
| R6, R7, R10, R11, R12 | 10 kΩ (0603) | Pull-ups / pull-downs |
| R8, R9 | 5,1 kΩ (0603) | Détection rôle USB-C (CC1/CC2) |
| R13 | 12 kΩ (0603) | Diviseur de tension |

---

## 9. PCB

**4 couches · JLCPCB**

| Paramètre | Valeur |
|-----------|--------|
| Couches | 4 (Signal / GND / PWR 5 V / Signal) |
| Épaisseur | 1,6 mm |
| Finition | HASL sans plomb |
| Vias | Standard 0,3 mm drill |
| Impédance contrôlée | 50 Ω sur traces RF (RF1/RF2) uniquement |

> 4 couches suffisent à ce niveau de complexité (pas de PCIe haute vitesse,
> pas de DDR routé). Impédance contrôlée uniquement sur les traces RF.

---

## 10. Interfaces réseau côté logiciel

Une fois sous Linux sur le SBC, les interfaces apparaîtront ainsi :

| Iface Linux | Fonction | Source matérielle |
|---|---|---|
| `end0` (ou `eth0`) | Audit câblé / management | RJ45 onboard OPi Zero 3 |
| `wlan0` | WiFi management (SSH, API, export) | AW859A onboard, RF1 (antenne SMA) |
| `wlan1` | **WiFi audit + monitor mode** | U3 RTL8188EUS, RF2 (antenne SMA) |

L'auto-détection de ReconEngine (`discover._interface_networks()`) énumère
toutes les interfaces avec une IP valide. Pour cibler explicitement
l'interface d'audit :

```bash
sudo python tools/main.py full -i wlan1
# ou via env
RECONENGINE_IFACE=wlan1 sudo python tools/main.py
```

---

## 11. Aucune adaptation logicielle requise sur le pipeline d'audit

Avec 2 Go RAM, **WeasyPrint fonctionne nativement** — rapports PDF complets
avec jauge de risque, graphiques CSS, cartographie réseau matplotlib et
recommandations par port. Le pipeline `discover → scan → rapport` tourne
sans aucune modification sur l'Orange Pi Zero 3.

La seule intégration matérielle dans le code est le module `status.py`
(pilote LED), entièrement optionnel et désactivable.
