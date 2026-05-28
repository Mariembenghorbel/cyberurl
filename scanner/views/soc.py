import subprocess
import xml.etree.ElementTree as ET
import datetime
import ipaddress

from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.http import require_POST
from django.utils import timezone

from scanner.models import Incident

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import subprocess
import xml.etree.ElementTree as ET
import ipaddress

from django.shortcuts import render
from django.contrib.admin.views.decorators import staff_member_required
from django.utils import timezone

from scanner.models import Incident
from django.shortcuts import get_object_or_404, redirect
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.http import require_POST
from scanner.models import Asset

@staff_member_required
@require_POST
def delete_incident(request, incident_id):
    incident = get_object_or_404(Incident, id=incident_id)
    incident.delete()
    return redirect('dashboard_soc')

# ─────────────────────────────
# CONFIG SOC
# ─────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#d97706",
    "LOW": "#65a30d",
    "INFO": "#6b7280",
}

DANGEROUS_SERVICES = {
    "ssh": "Remote access exposure",
    "telnet": "Unencrypted access",
    "ftp": "File transfer exposure",
    "http": "Web attack surface",
    "https": "Web attack surface",
    "mysql": "DB exposure",
    "mssql": "DB exposure",
    "rdp": "Remote desktop exposure",
}


# ─────────────────────────────
# HELPERS
# ─────────────────────────────
def get_severity(score):
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def service_risk_score(service, port):

    SUSPICIOUS_PORTS = [31337, 4444, 1337, 6667, 9001]

    service = (service or "").lower()

    score = 2

    # 1. services critiques
    if service in DANGEROUS_SERVICES:
        score += 4

    # 2. ports critiques
    if port in [22, 23, 3389, 3306, 1433]:
        score += 3
    elif port in [80, 8080]:
        score += 2
    elif port == 443:
        score += 1

    # 3. suspicious ports (IMPORTANT SIGNAL)
    if port in SUSPICIOUS_PORTS:
        score += 3

    # 4. tcpwrapped = blind service (risk medium/high only)
    if service == "tcpwrapped":
        score += 2

    # 5. upgrade condition (SOC intelligence rule)
    if port in SUSPICIOUS_PORTS and service == "tcpwrapped":
        score += 2  # upgrade only if both match

    return min(score, 10)
def generate_recommendations(service, port):
    service = (service or "").lower()

    rec = []

    if service == "ssh":
        rec += [
            "Disable password authentication, use SSH keys",
            "Restrict SSH access via firewall",
            "Change default SSH port (optional hardening)"
        ]

    elif service in ["http", "https"]:
        rec += [
            "Enable WAF protection",
            "Force HTTPS + secure headers",
            "Disable directory listing"
        ]

    elif service == "ftp":
        rec.append("Replace FTP with SFTP (encrypted protocol)")

    elif service in ["mysql", "mssql"]:
        rec += [
            "Restrict database to private network only",
            "Enforce strong authentication policies"
        ]

    elif service == "telnet":
        rec.append("REMOVE Telnet immediately (unencrypted protocol)")

    else:
        rec.append("Apply least privilege principle")

    # always
    rec.append("Keep services updated and patched")

    # SOC bonus contextual
    if port in [22, 23, 21]:
        rec.append("Monitor brute-force attempts on exposed service")

    return rec
# ─────────────────────────────
# NMAP PARSER FIXÉ
# ─────────────────────────────
def parse_nmap(xml_root):
    results = []

    for host in xml_root.findall("host"):
        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):

            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_id = int(port.get("portid"))
            protocol = port.get("protocol", "tcp")

            service = port.find("service")

            service_name = "unknown"
            product = ""
            version = ""

            if service is not None:
                service_name = service.get("name", "unknown")
                product = service.get("product", "")
                version = service.get("version", "")

            # banner SOC clean
            banner = f"{product} {version}".strip()
            if not banner:
                banner = service_name

            risk = service_risk_score(service_name, port_id)
            severity = get_severity(risk)

            results.append({
                "port": f"{port_id}/{protocol}",
                "service": service_name,
                "banner": banner,
                "risk_score": risk,
                "severity": severity,
                "severity_color": SEVERITY_COLORS.get(severity, "#6b7280"),
                "recommendations": generate_recommendations(service_name, port_id),
            })

    return sorted(results, key=lambda x: x["risk_score"], reverse=True)
# VIEW SOC NMAP (FIX FINAL)
# ─────────────────────────────
@staff_member_required
def nmap_audit_view(request):

    scenarios = []   # ✅ ALWAYS DEFINED (VERY IMPORTANT)
    target_ip = ""
    results = []
    error = None
    scan_stats = {}
    assets = Asset.objects.all()

    if request.method == "POST":
        asset_id = request.POST.get("asset_id")

        try:
            if not asset_id:
                raise ValueError("No asset selected")

            asset = get_object_or_404(Asset, id=asset_id)

            if not asset.ip_address:
                raise ValueError("Asset has no IP address")

            target_ip = asset.ip_address

            cmd = [
                "nmap",
                "-sV",
                "--open",
                "-T4",
                "--host-timeout", "60s",
                "-oX", "-",
                target_ip
            ]

            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=90
            )

            if process.returncode != 0:
                error = process.stderr or "Nmap execution failed"

            else:
                root = ET.fromstring(process.stdout)

                results = parse_nmap(root)

                # ✅ ALWAYS generate scenarios AFTER results
                scenarios = generate_attack_scenarios(results) if results else []

                scan_stats = {
                    "time": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "SUCCESS"
                }

                request.session["last_scan"] = {
                    "target_ip": target_ip,
                    "results": results,
                    "scan_stats": scan_stats,
                    "asset_name": asset.name,
                    "asset_id": asset.id
                }

                alerts = [
                    r for r in results
                    if r["severity"] in ["CRITICAL", "HIGH"]
                ]

                if alerts:
                    Incident.objects.create(
                        employe=request.user,
                        asset=asset,
                        titre=f"SOC ALERT - {asset.name}",
                        description=f"{len(alerts)} high-risk services detected via Nmap scan",
                        statut="PENDING",
                        priority="HIGH"
                    )

        except subprocess.TimeoutExpired:
            error = "Nmap timeout (90s exceeded)"

        except ValueError as e:
            error = str(e)

        except Exception as e:
            error = str(e)

    return render(request, "nmap_report.html", {
        "target_ip": target_ip,
        "results": results,
        "scenarios": scenarios,   # ✅ ALWAYS SENT
        "error_message": error,
        "scan_stats": scan_stats,
        "assets": assets
    })
@staff_member_required
def dashboard_soc_view(request):
    if request.method == 'POST' and 'new_status' in request.POST:
        incident = get_object_or_404(Incident, id=request.POST.get('incident_id'))

        if request.POST.get('new_status') in ['PENDING', 'IN_PROGRESS', 'RESOLVED']:
            incident.statut = request.POST.get('new_status')
            incident.save()

        return redirect(request.path)

    incidents = Incident.objects.all().order_by("-date_creation")
    return render(request, 'dashboard_soc.html', {'incidents': incidents})


def check_new_incidents(request):
    last_id = request.GET.get("last_id", 0)
    return JsonResponse({
        "new_alerts": Incident.objects.filter(id__gt=last_id).count()
    })


@require_POST
def respond_incident(request, incident_id):
    incident = get_object_or_404(Incident, id=incident_id)

    incident.analyst_response = request.POST.get("response")
    incident.statut = request.POST.get("status")
    incident.save()

    return redirect('dashboard_soc')

# ─────────────────────────────
# PDF EXPORT (LIGHT SOC REPORT)
# ─────────────────────────────
@staff_member_required
def export_scan_pdf(request):
    data = request.session.get("last_scan")

    if not data:
        return HttpResponse("No scan data", status=400)

    target_ip = data["target_ip"]
    results = data["results"]

    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="SOC_{target_ip}.pdf"'

    doc = SimpleDocTemplate(response, pagesize=letter)
    styles = getSampleStyleSheet()

    story = []

    # ─────────────────────────────
    # HEADER
    # ─────────────────────────────
    story.append(Paragraph("SOC SECURITY REPORT", styles["Title"]))
    story.append(Paragraph(f"Target: {target_ip}", styles["Heading2"]))
    story.append(Spacer(1, 12))

    # ─────────────────────────────
    # SUMMARY BLOCK
    # ─────────────────────────────
    total = len(results)
    critical = len([r for r in results if r["severity"] == "CRITICAL"])
    high = len([r for r in results if r["severity"] == "HIGH"])

    summary_text = f"""
    <b>Scan Summary</b><br/>
    Total Open Ports: {total}<br/>
    Critical: {critical}<br/>
    High: {high}<br/>
    """

    story.append(Paragraph(summary_text, styles["BodyText"]))
    story.append(Spacer(1, 12))

    # ─────────────────────────────
    # DETAILS PER PORT
    # ─────────────────────────────
    for r in results:

        severity = r["severity"]
        color = r.get("severity_color", "#000")

        block = f"""
        <b>PORT:</b> {r['port']}<br/>
        <b>Service:</b> {r['service']}<br/>
        <b>Risk Score:</b> {r['risk_score']}/10<br/>
        <b>Severity:</b> {severity}<br/>
        <b>Banner:</b> {r.get('banner', 'N/A')}<br/>
        """

        story.append(Paragraph(block, styles["BodyText"]))
        story.append(Spacer(1, 5))

        # Recommendations
        story.append(Paragraph("<b>Hardening Recommendations:</b>", styles["Heading4"]))

        for rec in r["recommendations"]:
            story.append(Paragraph(f"• {rec}", styles["BodyText"]))

        story.append(Spacer(1, 10))

        story.append(Paragraph("----------------------------------------", styles["BodyText"]))
        story.append(Spacer(1, 8))

    doc.build(story)
    return response

def generate_attack_scenarios(results):

    scenarios = []

    for r in results:

        port = int(r["port"].split("/")[0])
        service = r["service"].lower()
        severity = r["severity"]

        # =========================
        # SSH ATTACK PATH
        # =========================
        if port == 22 or service == "ssh":
            scenarios.append({
                "title": "SSH Service (22/tcp)",
                "attack": "Brute force attack → credential compromise → full server access",
                "risk": severity
            })

        # =========================
        # HTTP ATTACK PATH
        # =========================
        elif port in [80, 8080] or service in ["http", "apache"]:
            scenarios.append({
                "title": "Web Server (HTTP)",
                "attack": "Web exploitation (RCE, LFI, SQLi, outdated Apache vulnerabilities)",
                "risk": severity
            })

        # =========================
        # HTTPS ATTACK PATH
        # =========================
        elif port == 443 or service == "https":
            scenarios.append({
                "title": "HTTPS Service",
                "attack": "SSL misconfiguration → MITM attack → session hijacking",
                "risk": severity
            })

        # =========================
        # DATABASE ATTACK PATH
        # =========================
        elif port in [3306, 1433]:
            scenarios.append({
                "title": "Database Exposure",
                "attack": "Direct DB access → data exfiltration → privilege escalation",
                "risk": severity
            })

        # =========================
        # SUSPICIOUS PORTS
        # =========================
        elif port in [31337, 4444, 1337, 6667]:
            scenarios.append({
                "title": f"Suspicious Port ({port})",
                "attack": "Possible backdoor / RAT communication channel → remote control risk",
                "risk": severity
            })

    return scenarios