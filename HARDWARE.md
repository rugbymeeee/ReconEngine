# Bill of Materials — ReconEngine PCB Budget (~80 €)

Build minimaliste et fonctionnel. Chaque composant est justifié
par sa valeur réelle dans ce budget. Toutes les fonctions critiques
de ReconEngine sont conservées.

> **Compromis vs la build élite :**
> Pas de 5G, pas de GPS, pas de LoRa, pas de TPM, pas d'e-Ink, pas de NVMe.
> WeasyPrint fonctionne nativement avec 2 Go RAM — aucune adaptation logicielle requise.

---

## 1. Unité de calcul

### Orange Pi Zero 3 — 2 Go
**Allwinner H618 · 4× Cortex-A53 @ 1,5 GHz · 2 Go LPDDR4**

| Spec | Valeur |
|------|--------|
| Architecture | ARM64 (aarch64) |
| RAM | 2 Go LPDDR4 |
| WiFi embarqué | 802.11ac (WiFi 5, 2,4/5 GHz) + BT 5.0 |
| Ethernet | 100 Mbps intégré |
| USB | 1× USB 2.0 Type-C |
| GPIO | 26 broches (I²C, SPI, UART, PWM) |
| Stockage | microSD |
| Consommation | 0,6 W idle · 2,2 W charge max |
| Tension | 5V |
| Format | 65 × 30 mm |
| **Prix** | **~25 €** |

**Pourquoi :** Form factor identique au Zero 2W mais 4× plus de RAM (2 Go LPDDR4).
WeasyPrint génère les rapports PDF sans contrainte mémoire. H618 cloque 20% plus rapide
que le BCM2711 du Zero 2W. +7 € vs le Zero 2W — le meilleur investissement du budget.
GPIO 26 broches (vs 40 sur RPi) : adapter le footprint du carrier PCB en conséquence.

---

## 2. WiFi d'audit — monitor mode + injection

### Realtek RTL8188EUS (chip, intégré sur carrier)
**802.11n · 2,4 GHz · Monitor mode natif · Injection de paquets**

| Spec | Valeur |
|------|--------|
| Standard | 802.11b/g/n (150 Mbps) |
| Interface | USB 2.0 interne (via hub CH334) |
| Pilote Linux | `r8188eu` — mainline kernel 5.2+ |
| Monitor mode | Oui (aircrack-ng, Scapy, kismet) |
| Injection paquets | Oui |
| Consommation TX | 400 mA max |
| **Prix chip** | **~4 €** |

**Pourquoi :** Pilote open source stable, monitor mode natif sans patch. Le WiFi embarqué du Zero 2W reste dédié à la connectivité management (SSH, export). Ce chip gère exclusivement le scan et l'audit réseau.

---

## 3. Hub USB interne

### Genesys Logic GL850G
**USB 2.0 hub 4 ports · Bus-powered**

| Spec | Valeur |
|------|--------|
| Ports | 4× USB 2.0 downstream |
| Interface | 1× USB 2.0 upstream (vers Orange Pi Zero 3) |
| Consommation | 80 mA |
| **Prix chip** | **~1 €** |

**Pourquoi :** L'Orange Pi Zero 3 n'expose qu'un seul port USB-C. Le hub permet de connecter simultanément le chip RTL8188EUS (audit WiFi) + le port USB-A externe pour l'export des rapports.

---

## 4. Stockage

### Samsung PRO Endurance microSD 32 Go
**UHS-I · Classe 10 · Conçue pour écriture continue**

| Spec | Valeur |
|------|--------|
| Capacité | 32 Go |
| Lecture séquentielle | 100 Mo/s |
| Écriture séquentielle | 30 Mo/s |
| Endurance | 43 680 h d'écriture continue |
| **Prix** | **~10 €** |

**Pourquoi :** La PRO Endurance est conçue pour les systèmes embarqués qui écrivent en continu (logs, rapports). Une microSD standard claque en 3–6 mois dans ce contexte.

---

## 5. Gestion de l'alimentation

### TP4056 (charge Li-Ion via USB-C)
**Chargeur Li-Ion 1S · 1A · Protection intégrée**

| Spec | Valeur |
|------|--------|
| Courant de charge | 1A (via résistance programmable) |
| Tension batterie | 4,2V (Li-Ion 1S) |
| Protection | Surcharge, sur-décharge, court-circuit |
| Interface entrée | USB-C (5V) |
| **Prix chip** | **~0,50 €** |

### MT3608 (boost converter 3,7V → 5V)
**DC-DC boost · 2A · 93% efficacité**

| Spec | Valeur |
|------|--------|
| Entrée | 2V–24V |
| Sortie | 5V réglable / 2A |
| Efficacité | 93% peak |
| **Prix chip** | **~0,80 €** |

### Cellule Li-Ion — Samsung INR18650-25R
**18650 · 2 500 mAh · 3,7V**

| Spec | Valeur |
|------|--------|
| Capacité | 2 500 mAh (~9,25 Wh) |
| Courant décharge | 20A max (bien au-delà du besoin) |
| Autonomie estimée | 4–5 h scan continu |
| Format | 18650 (standard, remplaçable) |
| **Prix** | **~5 €** |

---

## 6. Affichage

### SSD1306 OLED 128 × 32 px (I²C, 0,91")
Affiche : IP locale, cible en cours, statut scan, % batterie.

| Spec | Valeur |
|------|--------|
| Résolution | 128 × 32 px |
| Interface | I²C (SDA/SCL via GPIO Zero 2W) |
| Consommation | 20 mA |
| **Prix** | **~3 €** |

---

## 7. Indicateurs visuels

### WS2812B × 2 (NeoPixel)
- **Rouge** : vulnérabilité critique détectée
- **Vert** : scan terminé, aucune critique
- **Orange clignotant** : scan en cours

**Prix total : ~0,50 €**

---

## 8. Connecteurs physiques

| Connecteur | Référence | Qté | Fonction | Prix |
|------------|-----------|-----|----------|------|
| USB-C 2.0 | GCT USB4085 | 1 | Charge 5V/2A | ~1 € |
| USB-A 2.0 | Molex 48037 | 1 | Export rapports USB | ~1,50 € |
| SMA femelle | Linx CONSMA003 | 2 | WiFi audit + WiFi mgmt | ~3 € |
| microSD push-push | Molex 104031 | 1 | Stockage OS + données | ~1 € |
| JST-PH 2 mm | JST B2B-PH-K | 1 | Batterie 18650 | ~0,50 € |
| Header 40 broches | Samtec TSM-120 | 1 | Montage Zero 2W | ~1,50 € |

---

## 9. PCB

**4 couches · 80 × 55 mm · JLCPCB · Lot de 5**

| Paramètre | Valeur |
|-----------|--------|
| Couches | 4 (Signal / GND / PWR 5V / Signal) |
| Dimensions | 80 × 55 mm |
| Épaisseur | 1,6 mm |
| Finition | HASL sans plomb |
| Vias | Standard 0,3 mm drill |
| **Prix ×5 plaques** | **~12 €** |

> 4 couches au lieu de 6 : suffisant pour ce niveau de complexité
> (pas de PCIe haute vitesse, pas de DDR). Impédance contrôlée
> uniquement sur les traces RF des antennes SMA (50 Ω).

---

## 10. Passives + divers

Résistances 0402, condensateurs découplage, ferrites, LED CMS,
bouton reset, fusible polyfuse 2A.

**~5 €**

---

## Récapitulatif BOM

| # | Composant | Prix |
|---|-----------|------|
| 1 | Orange Pi Zero 3 — 2 Go | **25,00 €** |
| 2 | Realtek RTL8188EUS (chip WiFi audit) | 4,00 € |
| 3 | Genesys GL850G (hub USB) | 1,00 € |
| 4 | Samsung PRO Endurance 32 Go microSD | **10,00 €** |
| 5 | TP4056 (chargeur Li-Ion) | 0,50 € |
| 6 | MT3608 (boost 5V) | 0,80 € |
| 7 | Samsung INR18650-25R (cellule) | **5,00 €** |
| 8 | SSD1306 OLED 0,91" | 3,00 € |
| 9 | WS2812B ×2 | 0,50 € |
| 10 | Connecteurs (USB-C, USB-A, SMA ×2…) | 8,50 € |
| 11 | PCB 4 couches 80×55 mm (×5) | **12,00 €** |
| 12 | Passives + bouton + fusible | 5,00 € |
| **TOTAL** | | **~75 €** |

> **Budget restant : ~5 €** — ou ajouter une deuxième cellule 18650
> (+5 €) pour passer à **5 000 mAh / ~9 h scan continu**.

---

## Aucune adaptation logicielle requise

Avec 2 Go RAM, **WeasyPrint fonctionne nativement** — rapports PDF complets
avec jauge de risque, graphiques CSS et recommandations par port.
Le code ReconEngine s'exécute sans modification sur l'Orange Pi Zero 3.

---

## Comparatif build Elite vs Budget

| Critère | Elite (~571 €) | Budget (~68 €) |
|---------|---------------|----------------|
| Compute | CM4 / 8 Go / 32 Go eMMC | Orange Pi Zero 3 / 2 Go / microSD |
| Ethernet | Intel I225-V 2,5 GbE | Via Zero 2W (USB Eth dongle) |
| WiFi connectivité | AX210 WiFi 6E | Zero 2W intégré (WiFi n) |
| WiFi audit | MT7915E (WiFi 6, PCIe) | RTL8188EUS (WiFi n, USB) |
| Stockage | WD SN740 NVMe 256 Go | microSD 32 Go |
| 5G | RM500Q-GL | ✗ |
| GPS | NEO-M9N | ✗ |
| LoRa | SX1262 | ✗ |
| TPM 2.0 | SLB 9672 | ✗ |
| Affichage | e-Ink 2,9" | OLED 0,91" |
| Rapport PDF | WeasyPrint (riche) | fpdf2 (léger) |
| Autonomie | 8 h scan | 4–5 h scan |
| PCB | 6 couches | 4 couches |
