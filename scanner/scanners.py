import requests
import base64
import os
import whois
import math
from datetime import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv
from Levenshtein import distance

load_dotenv()

class URLScanner:
    def __init__(self, url):
        self.url = url
        parsed_url = urlparse(url)
        self.domain = parsed_url.netloc.lower().replace("www.", "")
        self.risk_score = 0
        self.flags = []
        self.targets = self.load_brands()

    def load_brands(self):
        # ... (Garde ton code actuel pour charger brands.txt)
        return ["google.com", "facebook.com", "microsoft.com", "amazon.com"]

    # --- NOUVELLE FONCTION : ANALYSE WHOIS ---
    def check_domain_age(self):
        """Vérifie si le domaine est trop récent (Phishing classique)"""
        try:
            w = whois.whois(self.domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                days_old = (datetime.now() - creation_date).days
                if days_old < 30:
                    self.flags.append(f"🚨 Domaine très récent : créé il y a seulement {days_old} jours !")
                    self.risk_score += 15
                elif days_old < 365:
                    self.flags.append(f"⚠️ Domaine jeune : moins d'un an d'existence.")
                    self.risk_score += 5
        except:
            self.flags.append("❓ Impossible de récupérer les informations WHOIS.")

    # --- NOUVELLE FONCTION : CALCUL D'ENTROPIE ---
    def check_entropy(self):
        """Détecte les noms de domaines suspects générés aléatoirement"""
        s = self.domain
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        
        if entropy > 3.8: # Seuil typique pour un domaine suspect
            self.flags.append(f"🧬 Haute entropie ({round(entropy, 2)}) : le nom semble généré aléatoirement.")
            self.risk_score += 7

    # --- NOUVELLE FONCTION : SSL CHECK ---
    def check_ssl(self):
        """Vérifie si la connexion est sécurisée"""
        if not self.url.startswith("https://"):
            self.flags.append("🔓 Connexion non sécurisée (HTTP).")
            self.risk_score += 10
        try:
            requests.get(self.url, timeout=5, verify=True)
        except requests.exceptions.SSLError:
            self.flags.append("❌ Erreur SSL : Le certificat est invalide ou expiré !")
            self.risk_score += 20
        except:
            pass

    # --- TES FONCTIONS EXISTANTES (Améliorées) ---
    def check_typosquatting(self):
        # ... (Ton code Levenshtein actuel)
        pass

    def check_virus_total(self):
        # ... (Ton code VT actuel)
        pass

    def run_full_analysis(self):
        """Lance l'arsenal complet"""
        self.check_ssl()
        self.check_entropy()
        self.check_domain_age()
        self.check_typosquatting()
        self.check_virus_total()
        
        return {
            "score": self.risk_score,
            "flags": self.flags
        }