from django.db import models
from core.enums import StatutRapport, StatutConformite

class CritereConformite(models.Model):
    id_critere = models.CharField(max_length=50, primary_key=True)
    libelle_critere = models.CharField(max_length=255)
    description = models.CharField(max_length=500, null=True, blank=True)
    est_actif = models.BooleanField(default=True)

    def __str__(self):
        return self.libelle_critere

class RapportEtudiant(models.Model):
    id_rapport_etudiant = models.CharField(max_length=50, primary_key=True)
    libelle_rapport_etudiant = models.CharField(max_length=255)
    theme = models.CharField(max_length=255, null=True, blank=True)
    etudiant = models.ForeignKey('core.Etudiant', on_delete=models.CASCADE)
    stage = models.OneToOneField('core.Stage', on_delete=models.CASCADE)
    nombre_pages = models.IntegerField(null=True, blank=True)
    statut_rapport = models.CharField(max_length=50, choices=StatutRapport.choices, default=StatutRapport.BROUILLON)
    date_soumission = models.DateTimeField(null=True, blank=True)
    directeur_memoire = models.ForeignKey('core.Enseignant', on_delete=models.SET_NULL, null=True, blank=True)
    # Champ pour stocker les commentaires de non-conformité globaux
    commentaires_conformite = models.TextField(null=True, blank=True)
    # Champ pour la note explicative lors de la re-soumission
    note_explicative_correction = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.libelle_rapport_etudiant

class SectionRapport(models.Model):
    rapport_etudiant = models.ForeignKey('core.RapportEtudiant', on_delete=models.CASCADE)
    titre_section = models.CharField(max_length=255)
    contenu_section = models.TextField(null=True, blank=True)
    ordre = models.IntegerField(default=0)

    class Meta:
        unique_together = ('rapport_etudiant', 'titre_section')
        ordering = ['ordre']

class ConformiteRapportDetail(models.Model):
    rapport_etudiant = models.ForeignKey('core.RapportEtudiant', on_delete=models.CASCADE)
    critere = models.ForeignKey('core.CritereConformite', on_delete=models.PROTECT)
    statut_validation = models.CharField(max_length=50, choices=StatutConformite.choices)
    commentaire = models.TextField(null=True, blank=True)
    date_verification = models.DateTimeField(auto_now_add=True)
    verifie_par = models.ForeignKey('core.PersonnelAdministratif', on_delete=models.SET_NULL, null=True, blank=True)

    class Meta:
        unique_together = ('rapport_etudiant', 'critere')