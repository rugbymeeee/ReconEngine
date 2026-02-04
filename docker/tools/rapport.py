from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader
import datetime
import os

# 1. Préparer les données (Simulées ici, mais tu les récupéreras de tes scans)
data = {
    "date_scan": datetime.datetime.now().strftime("%d/%m/%Y à %H:%M"),
    "target_ip": "192.168.1.15",
    "scan_id": "REQ-2023-001",
    "global_risk": "ELEVE", # Options: CRITIQUE, ELEVE, MODERE, FAIBLE
    "summary_text": "Plusieurs services obsolètes ont été détectés, notamment une version vulnérable de SMB et un serveur Web non sécurisé. Une action immédiate est recommandée.",
    "total_ports": 1000,
    "open_ports_count": 3,
    "critical_count": 1,
    "duration": "4 min 32s",
    "vulnerabilities": [
        {
            "port": 22,
            "protocol": "TCP",
            "service": "OpenSSH 7.9",
            "severity_class": "low", # critical, high, medium, low
            "severity_text": "FAIBLE",
            "desc": "Service SSH actif. Version à jour. Recommandation : Désactiver l'authentification par mot de passe."
        },
        {
            "port": 80,
            "protocol": "TCP",
            "service": "Apache httpd",
            "severity_class": "medium",
            "severity_text": "MOYEN",
            "desc": "Serveur Web actif sur port non chiffré. Dossier /admin accessible sans mot de passe."
        },
        {
            "port": 445,
            "protocol": "TCP",
            "service": "Microsoft-DS",
            "severity_class": "critical",
            "severity_text": "CRITIQUE",
            "desc": "Signature SMBv1 détectée. Vulnérable à EternalBlue. Patch immédiat requis."
        }
    ]
}

# 2. Charger le template
script_dir = os.path.dirname(__file__)
env = Environment(loader=FileSystemLoader(script_dir))
template = env.get_template('report_template.html')

# 3. Rendu du HTML avec les données
html_out = template.render(data)

# 4. Conversion en PDF
print("Génération du PDF...")
# base_url=script_dir permet de charger les images si tu en ajoutes plus tard
HTML(string=html_out, base_url=script_dir).write_pdf("Rapport_Audit_ReconEngine.pdf")
print("Terminé ! Fichier : Rapport_Audit_ReconEngine.pdf")