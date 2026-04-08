# Guide LFS — ReconEngine sur Linux From Scratch

Ce guide couvre la construction d'un système Linux minimal
dédié à ReconEngine, optimisé pour ARM64 (Cortex-A53/A72).
Basé sur LFS 12.x / BLFS 12.x.

---

## Prérequis : système hôte

Hôte recommandé : Debian 12 ou Ubuntu 22.04 LTS (x86_64 ou ARM64 natif).
Vérifier les outils requis par LFS :

```bash
bash lfs-check.sh   # script fourni dans le livre LFS
```

Outils indispensables : `gcc`, `g++`, `make`, `bison`, `flex`, `texinfo`,
`gawk`, `m4`, `python3`, `ninja`, `meson`, `cmake`.

---

## 1. Variables d'environnement de base

```bash
export LFS=/mnt/lfs
export LFS_TGT=aarch64-lfs-linux-gnu   # pour ARM64 (Cortex-A53/A72/A55)
# Pour ARM 32 bits :
# export LFS_TGT=armv7l-lfs-linux-gnueabihf
export PATH=$LFS/tools/bin:$PATH
export MAKEFLAGS="-j$(nproc)"
```

---

## 2. Chaîne de compilation croisée (cross-toolchain)

Suivre le livre LFS dans cet ordre exact :

| # | Paquet | Version | Notes |
|---|--------|---------|-------|
| 1 | binutils (pass 1) | 2.42 | `--target=$LFS_TGT` |
| 2 | gcc (pass 1) | 13.2.0 | Sans libstdc++, `--target=$LFS_TGT` |
| 3 | linux-headers | 6.7.x | `make headers ARCH=arm64` |
| 4 | glibc | 2.39 | Avec `--host=$LFS_TGT` |
| 5 | libstdc++ | (dans GCC) | `--host=$LFS_TGT` |
| 6 | binutils (pass 2) | 2.42 | Chroot |
| 7 | gcc (pass 2) | 13.2.0 | Chroot, libstdc++ incluse |

---

## 3. Paquets système de base (LFS standard)

Construire dans le chroot `$LFS` dans cet ordre :

```
man-pages, iana-etc, glibc, zlib, bzip2, xz, lz4, zstd,
file, readline, m4, bc, flex, tcl, expect, dejagnu,
pkgconf, binutils, gmp, mpfr, mpc, attr, acl, libcap,
shadow, gcc, ncurses, sed, psmisc, gettext, bison, grep,
bash, libtool, gdbm, gperf, expat, inetutils, less, perl,
xml::parser, intltool, autoconf, automake, openssl,
kmod, elfutils, libffi, wheel, Python (3.12+),
flit-core, ninja, meson, coreutils, diffutils, gawk,
findutils, groff, gzip, iproute2, kbd, libpipeline,
make, patch, tar, texinfo, vim, util-linux, e2fsprogs
```

> **Note :** `libffi` et `openssl` sont requis avant Python.

---

## 4. Configuration du noyau Linux (ARM64 minimal)

```bash
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- menuconfig
```

Options critiques à activer :

```
# Réseau
CONFIG_NET=y
CONFIG_INET=y
CONFIG_PACKET=y          # requis par Scapy (raw sockets)
CONFIG_PACKET_DIAG=y
CONFIG_AF_PACKET=y
CONFIG_TUN=y
CONFIG_VETH=y

# Ethernet
CONFIG_NET_ETHERNET=y
CONFIG_R8169=y           # Realtek RTL8111H
CONFIG_MICROCHIP_PHY=y   # KSZ9031

# WiFi (si module Intel AX200)
CONFIG_IWLWIFI=y
CONFIG_IWLMVM=y
CONFIG_CFG80211=y
CONFIG_MAC80211=y

# Systèmes de fichiers
CONFIG_EXT4_FS=y
CONFIG_TMPFS=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_DEVTMPFS=y

# USB (export de rapports)
CONFIG_USB_SUPPORT=y
CONFIG_USB_XHCI_HCD=y
CONFIG_USB_STORAGE=y
CONFIG_SCSI=y
CONFIG_BLK_DEV_SD=y

# Autres
CONFIG_POSIX_TIMERS=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
```

Construction :
```bash
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules_install INSTALL_MOD_PATH=$LFS
```

---

## 5. BLFS — Dépendances système pour ReconEngine

Ces paquets ne font pas partie du LFS de base mais sont requis par WeasyPrint et Scapy.
Construire dans cet ordre (respecter les dépendances) :

### 5.1 Réseau et sécurité
```
libpcap 1.10.x          # requis par nmap et Scapy
openssl 3.2.x           # TLS (déjà dans LFS base)
```

### 5.2 Pile graphique WeasyPrint
```
freetype 2.13.x         # rendu des polices
fontconfig 2.15.x       # détection et configuration des polices
pixman 0.43.x           # opérations pixel
cairo 1.18.x            # contexte de rendu 2D
glib 2.78.x             # bibliothèque de base GLib (requis par Pango)
harfbuzz 8.3.x          # mise en forme du texte
pango 1.51.x            # rendu de texte avancé
gdk-pixbuf 2.42.x       # chargement d'images (PNG/JPEG dans les rapports)
```

### 5.3 Polices (obligatoire pour les PDF)
```bash
# Installation manuelle dans $LFS/usr/share/fonts/
# Recommandé : Liberation Fonts (équivalents Arial/Times/Courier)
wget https://github.com/liberationfonts/liberation-fonts/releases/download/2.1.5/liberation-fonts-ttf-2.1.5.tar.gz
# Ou : Noto Fonts (Google) pour un rendu Unicode complet
```

Mettre à jour le cache :
```bash
fc-cache -fv
```

### 5.4 Python 3.12+ (si pas encore dans LFS base)
```bash
./configure \
  --prefix=/usr \
  --enable-optimizations \
  --with-ensurepip=yes \
  --enable-shared \
  LDFLAGS="-Wl,-rpath /usr/lib"
make -j$(nproc)
make install
```

Vérifier :
```bash
python3 --version   # doit afficher 3.12.x ou supérieur
python3 -c "import ssl; import ctypes; import zlib"
```

### 5.5 nmap
```bash
./configure --prefix=/usr --without-zenmap --without-ndiff
make -j$(nproc)
make install
```

Vérifier :
```bash
nmap --version
nmap -sn 127.0.0.1   # test sans root
sudo nmap -sS -p22 127.0.0.1  # test avec raw socket
```

---

## 6. Installation des paquets Python

```bash
python3 -m pip install --no-build-isolation \
    scapy==2.6.1 \
    python-nmap==0.7.1 \
    Jinja2==3.1.6 \
    MarkupSafe==3.0.3 \
    weasyprint==68.0 \
    rich>=13.7.0 \
    Pillow==12.1.0 \
    tinycss2 cssselect2 pyphen pydyf fonttools \
    tinyhtml5 webencodings cffi brotli zopfli
```

> **Alternative légère** pour les systèmes très contraints (< 512 Mo RAM) :
> Remplacer `weasyprint` par `fpdf2` et adapter `rapport.py`
> (supprimer les imports WeasyPrint, utiliser `fpdf2` pour le rendu PDF).
> `fpdf2` est pur Python, sans dépendances Cairo/Pango.

---

## 7. Déploiement de ReconEngine

```bash
# Copier les sources
mkdir -p /opt/reconengine
cp -r /chemin/vers/docker/tools/* /opt/reconengine/

# Répertoire des rapports
mkdir -p /opt/reconengine/rapports
chmod 750 /opt/reconengine/rapports

# Configuration (optionnel — fichier TOML)
cat > /etc/reconengine.toml << 'EOF'
output_dir = "/opt/reconengine/rapports"

[scan]
profile = "full"
max_workers = 4
discovery_timeout = 5
EOF

export RECONENGINE_CONFIG=/etc/reconengine.toml
```

---

## 8. Service systemd

```ini
# /etc/systemd/system/reconengine.service
[Unit]
Description=ReconEngine — Audit de sécurité réseau
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/reconengine/main.py full
WorkingDirectory=/opt/reconengine
Environment=RECONENGINE_CONFIG=/etc/reconengine.toml
# Root requis pour ARP et raw sockets nmap
User=root
StandardOutput=journal
StandardError=journal
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable reconengine
systemctl start reconengine
journalctl -u reconengine -f
```

Pour un lancement périodique (audit toutes les 6 heures) :
```ini
# /etc/systemd/system/reconengine.timer
[Unit]
Description=ReconEngine toutes les 6 heures

[Timer]
OnBootSec=2min
OnUnitActiveSec=6h

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now reconengine.timer
```

---

## 9. Gestionnaire de démarrage (ARM64)

### Option A : U-Boot (recommandé pour PCB custom)
```bash
# Construire U-Boot pour la cible
make CROSS_COMPILE=aarch64-linux-gnu- <board>_defconfig
make CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)
# Flasher sur eMMC selon le SoC
```

### Option B : GRUB EFI
```bash
grub-install --target=arm64-efi --efi-directory=/boot/efi --bootloader-id=LFS
grub-mkconfig -o /boot/grub/grub.cfg
```

---

## 10. Checklist de validation finale

```bash
# Droits raw socket
sudo python3 -c "from scapy.all import arping; print('Scapy OK')"

# nmap fonctionne
sudo nmap -sS -p22,80 127.0.0.1

# Python et dépendances
python3 -c "import nmap, jinja2, weasyprint, rich; print('Dépendances OK')"

# Génération d'un rapport test
cd /opt/reconengine
sudo python3 rapport.py   # scan test sur 127.0.0.1

# Vérifier le PDF
ls -lh rapports/
```

---

## Tailles approximatives sur le système final

| Composant | Taille disque |
|-----------|--------------|
| Système LFS de base | ~800 Mo |
| Python 3.12 + pip | ~120 Mo |
| BLFS graphique (Cairo/Pango/etc.) | ~180 Mo |
| nmap + libpcap | ~25 Mo |
| Paquets Python ReconEngine | ~85 Mo |
| Polices (Liberation/Noto) | ~30 Mo |
| **Total** | **~1,2 Go** |

Recommandation stockage : **eMMC 4 Go minimum**, **8 Go recommandé**
(laisser de l'espace pour les rapports PDF et les logs).
