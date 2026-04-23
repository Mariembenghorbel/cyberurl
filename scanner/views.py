from multiprocessing import context

from django.shortcuts import render
from .scanners import URLScanner  # Import de ton fichier propre
import requests
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import SignUpForm
from django.contrib.auth.decorators import login_required

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            form.save()  # Crée l'utilisateur
            return redirect('login')
    else:
        form = SignUpForm()
    return render(request, 'signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            error = "Nom d’utilisateur ou mot de passe incorrect."
            return render(request, 'login.html', {'error': error})
    return render(request, 'login.html')

def logout_view(request):
    logout(request)
    return redirect('login')

@login_required
def home(request):
    
    pass
def home(request):
    result = None
    scanner = None  # <-- important pour éviter UnboundLocalError

    if request.method == 'POST':
        target_url = request.POST.get('url').strip()
        
        # Initialisation du scanner avec l'URL
        scanner = URLScanner(target_url)
        
        # --- ETAPE 1 : Analyse Statique (Typosquatting) ---
        scanner.check_typosquatting()
        
        # --- ETAPE 2 : Analyse Dynamique (Connexion & Headers) ---
        try:
            response = requests.get(target_url, timeout=7, verify=True)
            cert_status = "Valide"
            scanner.check_security_headers(response.headers)
            
        except requests.exceptions.SSLError:
            cert_status = "Invalide (Erreur SSL/TLS)"
            scanner.flags.append("❌ Certificat SSL invalide ou auto-signé.")
            scanner.risk_score += 5
        except requests.exceptions.ConnectionError:
            cert_status = "Impossible de joindre le serveur"
            scanner.risk_score += 2
        except Exception as e:
            cert_status = f"Erreur : {str(e)}"

        # --- ETAPE 3 : Analyse Externe (VirusTotal) ---
        scanner.check_virus_total()

        # --- ETAPE 4 : Synthèse du Risque ---
        risk_level = "Faible"
        if scanner.risk_score >= 10:
            risk_level = "Critique / Dangereux"
        elif scanner.risk_score >= 5:
            risk_level = "Modéré"

        # Conseils basés sur le risque
        advice = []
        if scanner.risk_score >= 8:
            advice.append("🚫 **DANGER IMMÉDIAT** : Ne saisissez aucune coordonnée bancaire ou mot de passe sur ce site.")
        elif scanner.risk_score >= 4:
            advice.append("⚠️ **PRUDENCE** : Ce site présente des signes suspects. Vérifiez l'expéditeur du lien.")
        else:
            advice.append("✅ **CONFIANCE** : Le site semble suivre les standards de sécurité actuels.")

        result = {
            "url": target_url,
            "risk_level": risk_level,
            "score": scanner.risk_score,
            "flags": scanner.flags,
            "cert": cert_status,
            "domain": scanner.domain,
            "advice": advice
        }

    return render(request, 'home.html', {"result": result})
from .nmap_scanner import run_nmap_scan, parse_vulnerabilities

@login_required
def scan_ip(request):
    services_dict = {}  # On utilise un dictionnaire pour grouper par service
    ip = None

    if request.method == "POST":
        ip = request.POST.get("ip")
        
        # 1. Exécution du scan
        nmap_output = run_nmap_scan(ip)
        
        # 2. Récupération de la liste plate
        raw_vulnerabilities = parse_vulnerabilities(nmap_output)

        # 3. Restructuration : Groupement par Port/Service
        for vuln in raw_vulnerabilities:
            # On crée une clé unique pour chaque service ouvert
            service_key = f"{vuln['port']}/{vuln['service']}"
            
            if service_key not in services_dict:
                services_dict[service_key] = {
                    "port": vuln['port'],
                    "service": vuln['service'],
                    "cves": []
                }
            
            # On ajoute la vulnérabilité à ce service
            services_dict[service_key]["cves"].append(vuln)

    return render(request, "scan_ip.html", {
        "services": services_dict,
        "target_ip": ip
    })
from django.contrib.auth.decorators import login_required
from django.shortcuts import render

@login_required
def dashboard(request):
    context = {
        'user': request.user,
        'scan_count': 5,
        'last_scan': "12/03/2026"
    }
    return render(request, 'dashboard.html', context)