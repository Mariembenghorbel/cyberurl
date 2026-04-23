import subprocess
import re

def run_nmap_scan(ip):
    # -sV : Détection de version
    # --script vulners : Utilise la base de données vulners.com
    command = ["nmap", "-sV", "--script", "vulners", ip]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        return result.stdout
    except Exception as e:
        return f"Erreur lors du scan : {e}"

def parse_vulnerabilities(nmap_output):
    vulnerabilities = []
    current_port = None
    current_service = None

    for line in nmap_output.splitlines():
        # 1. Détecter le port et le service (ex: 80/tcp open http)
        port_match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if port_match:
            current_port = port_match.group(1)
            current_service = port_match.group(2)

        # 2. Détecter la CVE et le score CVSS (ex: CVE-2021-1234  7.5)
        cve_match = re.search(r"(CVE-\d{4}-\d+)\s+(\d+\.\d+)", line)
        if cve_match and current_port:
            cvss_score = float(cve_match.group(2))
            
            # Logique de classification du risque (Standard de l'industrie)
            if cvss_score >= 9.0:
                risk_level = "CRITIQUE"
            elif cvss_score >= 7.0:
                risk_level = "HIGH"
            elif cvss_score >= 4.0:
                risk_level = "MEDIUM"
            else:
                risk_level = "LOW"

            vulnerabilities.append({
                "port": current_port,
                "service": current_service,
                "cve": cve_match.group(1),
                "cvss": cvss_score,
                "risk": risk_level, # Ajout crucial pour ton affichage HTML
                "link": f"https://nvd.nist.gov/vuln/detail/{cve_match.group(1)}"
            })

    return vulnerabilities