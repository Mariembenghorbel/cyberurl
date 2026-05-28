from django.db import models
from django.contrib.auth.models import User


# =========================
# ASSET CMDB (IMPORTANT)
# =========================
class Asset(models.Model):

    ASSET_TYPES = [
        ("SERVER", "Server"),
        ("WEB", "Web Application"),
        ("EMPLOYEE", "Employee Endpoint"),
        ("DB", "Database"),
    ]

    CRITICALITY = [
        ("LOW", "Low"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]

    name = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(
    blank=True,
    null=True
    )

    hostname = models.CharField(
    max_length=100,
    null=True,
    blank=True
)
    asset_type = models.CharField(
        max_length=20,
        choices=ASSET_TYPES
    )

    criticality = models.CharField(
        max_length=20,
        choices=CRITICALITY,
        default="LOW"
    )

    def __str__(self):
        return f"{self.name} ({self.ip_address})"


# =========================
# INCIDENT SOC
# =========================
class Incident(models.Model):

    VECTEURS_MENACE = [
        ('PHISHING', 'Phishing / Suspicious Link'),
        ('MALWARE', 'Malware Suspicion'),
        ('NETWORK', 'Network Anomaly'),
        ('HARDWARE', 'Suspicious Device'),
        ('OTHER', 'Other Suspicious Activity'),
    ]

    STATUTS_INCIDENT = [
        ('PENDING', 'Pending'),
        ('IN_PROGRESS', 'In Progress'),
        ('RESOLVED', 'Resolved'),
    ]

    PRIORITIES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    # =========================
    # EMPLOYEE
    # =========================
    employe = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="incidents"
    )

    # =========================
    # INCIDENT DATA
    # =========================
    titre = models.CharField(max_length=200)
    type_menace = models.CharField(
        max_length=20,
        choices=VECTEURS_MENACE,
        default='OTHER'
    )

    description = models.TextField()

    url_associee = models.URLField(
        max_length=500,
        blank=True,
        null=True
    )

    # ❌ SUPPRIMÉ (important)
    # ip_employe = models.GenericIPAddressField()

    # =========================
    # NEW SOC LINK
    # =========================
    asset = models.ForeignKey(
        Asset,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="incidents"
    )

    # =========================
    # SOC WORKFLOW
    # =========================
    statut = models.CharField(
        max_length=20,
        choices=STATUTS_INCIDENT,
        default='PENDING'
    )

    priority = models.CharField(
        max_length=20,
        choices=PRIORITIES,
        default='MEDIUM'
    )

    analyst_response = models.TextField(
        null=True,
        blank=True
    )

    # =========================
    # TIMESTAMP
    # =========================
    date_creation = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-date_creation']

    def __str__(self):
        return f"[{self.statut}] {self.titre}"