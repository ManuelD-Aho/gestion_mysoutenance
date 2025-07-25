from django.db import models
from core.enums import ModeSession, StatutSession, DecisionVote, StatutPV, DecisionValidationPV

class SessionValidation(models.Model):
    id_session = models.CharField(max_length=50, primary_key=True)
    nom_session = models.CharField(max_length=255)
    date_debut_session = models.DateTimeField(null=True, blank=True)
    date_fin_prevue = models.DateTimeField(null=True, blank=True)
    president_session = models.ForeignKey('core.Enseignant', on_delete=models.PROTECT)
    mode_session = models.CharField(max_length=50, choices=ModeSession.choices)
    statut_session = models.CharField(max_length=50, choices=StatutSession.choices, default=StatutSession.PLANIFIEE)
    rapports = models.ManyToManyField('core.RapportEtudiant', related_name='sessions')
    membres = models.ManyToManyField('core.Enseignant', related_name='sessions_commission', blank=True) # Membres de la commission pour cette session
    nombre_votants_requis = models.PositiveSmallIntegerField(default=1) # Pour le quorum

    def __str__(self):
        return self.nom_session

class VoteCommission(models.Model):
    id_vote = models.CharField(max_length=50, primary_key=True)
    session = models.ForeignKey('core.SessionValidation', on_delete=models.CASCADE)
    rapport_etudiant = models.ForeignKey('core.RapportEtudiant', on_delete=models.CASCADE)
    enseignant = models.ForeignKey('core.Enseignant', on_delete=models.CASCADE)
    decision_vote = models.CharField(max_length=50, choices=DecisionVote.choices)
    commentaire_vote = models.TextField(null=True, blank=True)
    date_vote = models.DateTimeField(auto_now_add=True)
    tour_vote = models.IntegerField(default=1)

    class Meta:
        unique_together = ('session', 'rapport_etudiant', 'enseignant', 'tour_vote')

    def __str__(self):
        return f"Vote de {self.enseignant} pour {self.rapport_etudiant} ({self.decision_vote})"

class ProcesVerbal(models.Model):
    id_compte_rendu = models.CharField(max_length=50, primary_key=True)
    session = models.OneToOneField('core.SessionValidation', on_delete=models.CASCADE, null=True, blank=True)
    libelle_compte_rendu = models.TextField()
    date_creation_pv = models.DateTimeField(auto_now_add=True)
    statut_pv = models.CharField(max_length=50, choices=StatutPV.choices, default=StatutPV.BROUILLON)
    redacteur = models.ForeignKey('core.Enseignant', on_delete=models.PROTECT)
    date_finalisation = models.DateTimeField(null=True, blank=True) # Date de validation finale par la commission

    def __str__(self):
        return f"PV de la session {self.session.nom_session if self.session else 'N/A'}"

class ValidationPv(models.Model):
    proces_verbal = models.ForeignKey('core.ProcesVerbal', on_delete=models.CASCADE)
    enseignant = models.ForeignKey('core.Enseignant', on_delete=models.CASCADE)
    decision_validation_pv = models.CharField(max_length=50, choices=DecisionValidationPV.choices)
    date_validation = models.DateTimeField(auto_now_add=True)
    commentaire_validation_pv = models.TextField(null=True, blank=True)

    class Meta:
        unique_together = ('proces_verbal', 'enseignant')

    def __str__(self):
        return f"Validation PV par {self.enseignant} ({self.decision_validation_pv})"