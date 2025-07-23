from django.db import models
from core.enums import StatutPaiement, DecisionPassage, TypePenalite, StatutPenalite

class AnneeAcademique(models.Model):
    id_annee_academique = models.CharField(max_length=50, primary_key=True)
    libelle_annee_academique = models.CharField(max_length=50)
    date_debut = models.DateField(null=True, blank=True)
    date_fin = models.DateField(null=True, blank=True)
    est_active = models.BooleanField(default=False)

    def __str__(self):
        return self.libelle_annee_academique

class NiveauEtude(models.Model):
    id_niveau_etude = models.CharField(max_length=50, primary_key=True)
    libelle_niveau_etude = models.CharField(max_length=100)

    def __str__(self):
        return self.libelle_niveau_etude

class Specialite(models.Model):
    id_specialite = models.CharField(max_length=50, primary_key=True)
    libelle_specialite = models.CharField(max_length=100)
    responsable_specialite = models.ForeignKey('core.Enseignant', on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.libelle_specialite

class Ue(models.Model):
    id_ue = models.CharField(max_length=50, primary_key=True)
    libelle_ue = models.CharField(max_length=100)
    credits_ue = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return self.libelle_ue

class Ecue(models.Model):
    id_ecue = models.CharField(max_length=50, primary_key=True)
    ue = models.ForeignKey('core.Ue', on_delete=models.CASCADE)
    libelle_ecue = models.CharField(max_length=100)
    credits_ecue = models.IntegerField(null=True, blank=True)

    def __str__(self):
        return self.libelle_ecue

class Inscription(models.Model):
    etudiant = models.ForeignKey('core.Etudiant', on_delete=models.CASCADE)
    niveau_etude = models.ForeignKey('core.NiveauEtude', on_delete=models.PROTECT)
    annee_academique = models.ForeignKey('core.AnneeAcademique', on_delete=models.PROTECT)
    montant_inscription = models.DecimalField(max_digits=10, decimal_places=2)
    date_inscription = models.DateTimeField()
    statut_paiement = models.CharField(max_length=50, choices=StatutPaiement.choices)
    date_paiement = models.DateTimeField(null=True, blank=True)
    decision_passage = models.CharField(max_length=50, choices=DecisionPassage.choices, null=True, blank=True)

    class Meta:
        unique_together = ('etudiant', 'niveau_etude', 'annee_academique')

    def __str__(self):
        return f"Inscription de {self.etudiant} en {self.niveau_etude} pour {self.annee_academique}"

class Entreprise(models.Model):
    id_entreprise = models.CharField(max_length=50, primary_key=True)
    libelle_entreprise = models.CharField(max_length=200)
    secteur_activite = models.CharField(max_length=100, null=True, blank=True)

    def __str__(self):
        return self.libelle_entreprise

class Stage(models.Model):
    entreprise = models.ForeignKey('core.Entreprise', on_delete=models.PROTECT)
    etudiant = models.ForeignKey('core.Etudiant', on_delete=models.CASCADE)
    date_debut_stage = models.DateField()
    date_fin_stage = models.DateField(null=True, blank=True)
    sujet_stage = models.TextField(null=True, blank=True)
    nom_tuteur_entreprise = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        unique_together = ('entreprise', 'etudiant', 'date_debut_stage')

    def __str__(self):
        return f"Stage de {self.etudiant} chez {self.entreprise}"

class Penalite(models.Model):
    id_penalite = models.CharField(max_length=50, primary_key=True)
    etudiant = models.ForeignKey('core.Etudiant', on_delete=models.CASCADE)
    annee_academique = models.ForeignKey('core.AnneeAcademique', on_delete=models.PROTECT)
    type_penalite = models.CharField(max_length=50, choices=TypePenalite.choices)
    montant_du = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    motif = models.TextField(null=True, blank=True)
    statut_penalite = models.CharField(max_length=50, choices=StatutPenalite.choices)
    date_creation = models.DateTimeField(auto_now_add=True)
    date_regularisation = models.DateTimeField(null=True, blank=True)
    personnel_traitant = models.ForeignKey('core.PersonnelAdministratif', on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f"Pénalité {self.id_penalite} pour {self.etudiant}"

class Sequence(models.Model):
    nom_sequence = models.CharField(max_length=50)
    annee = models.IntegerField()
    valeur_actuelle = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ('nom_sequence', 'annee')

    def __str__(self):
        return f"{self.nom_sequence} ({self.annee}) - {self.valeur_actuelle}"

class Note(models.Model):
    etudiant = models.ForeignKey('core.Etudiant', on_delete=models.CASCADE)
    ecue = models.ForeignKey('core.Ecue', on_delete=models.PROTECT)
    annee_academique = models.ForeignKey('core.AnneeAcademique', on_delete=models.PROTECT)
    date_evaluation = models.DateTimeField()
    note = models.DecimalField(max_digits=5, decimal_places=2, null=True, blank=True)

    class Meta:
        unique_together = ('etudiant', 'ecue', 'annee_academique')
