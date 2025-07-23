from django.db import models

class StatutRapport(models.TextChoices):
    BROUILLON = 'RAP_BROUILLON', 'Brouillon'
    SOUMIS = 'RAP_SOUMIS', 'Soumis'
    NON_CONFORME = 'RAP_NON_CONF', 'Non Conforme'
    CONFORME = 'RAP_CONF', 'Conforme'
    EN_COMMISSION = 'RAP_EN_COMMISSION', 'En Commission'
    EN_CORRECTION = 'RAP_CORRECT', 'En Correction'
    REFUSE = 'RAP_REFUSE', 'Refusé'
    VALIDE = 'RAP_VALID', 'Validé'
    ARCHIVE = 'RAP_ARCHIVE', 'Archivé'

class StatutCompte(models.TextChoices):
    ACTIF = 'actif', 'Actif'
    INACTIF = 'inactif', 'Inactif'
    BLOQUE = 'bloque', 'Bloqué'
    EN_ATTENTE_VALIDATION = 'en_attente_validation', 'En attente de validation'
    ARCHIVE = 'archive', 'Archivé'

class TypePenalite(models.TextChoices):
    FINANCIERE = 'Financière', 'Financière'
    ADMINISTRATIVE = 'Administrative', 'Administrative'

class StatutPenalite(models.TextChoices):
    DUE = 'PEN_DUE', 'Due'
    REGLEE = 'PEN_REGLEE', 'Réglée'
    ANNULEE = 'PEN_ANNULEE', 'Annulée'

class StatutPaiement(models.TextChoices):
    EN_ATTENTE = 'PAIE_ATTENTE', 'En attente de paiement'
    PAYE = 'PAIE_OK', 'Payé'
    PARTIEL = 'PAIE_PARTIEL', 'Paiement partiel'
    EN_RETARD = 'PAIE_RETARD', 'En retard de paiement'

class DecisionPassage(models.TextChoices):
    ADMIS = 'DEC_ADMIS', 'Admis'
    AJOURNE = 'DEC_AJOURNE', 'Ajourné'
    REDOUBLANT = 'DEC_REDOUBLANT', 'Redoublant'
    EXCLU = 'DEC_EXCLU', 'Exclu'

class StatutConformite(models.TextChoices):
    CONFORME = 'Conforme', 'Conforme'
    NON_CONFORME = 'Non Conforme', 'Non Conforme'
    NON_APPLICABLE = 'Non Applicable', 'Non Applicable'

class ModeSession(models.TextChoices):
    PRESENTIEL = 'presentiel', 'Présentiel'
    EN_LIGNE = 'en_ligne', 'En Ligne'

class StatutSession(models.TextChoices):
    PLANIFIEE = 'planifiee', 'Planifiée'
    EN_COURS = 'en_cours', 'En cours'
    CLOTUREE = 'cloturee', 'Clôturée'

class DecisionVote(models.TextChoices):
    APPROUVE = 'VOTE_APPROUVE', 'Approuvé'
    REFUSE = 'VOTE_REFUSE', 'Refusé'
    APPROUVE_RESERVE = 'VOTE_APPROUVE_RESERVE', 'Approuvé sous réserve'
    ABSTENTION = 'VOTE_ABSTENTION', 'Abstention'

class StatutPV(models.TextChoices):
    BROUILLON = 'PV_BROUILLON', 'Brouillon'
    ATTENTE_APPROBATION = 'PV_ATTENTE_APPROBATION', "En attente d'approbation"
    VALIDE = 'PV_VALIDE', 'Validé'
    REJETE = 'PV_REJETE', 'Rejeté'

class DecisionValidationPV(models.TextChoices):
    APPROUVE = 'PV_APPROUVE', 'Approuvé'
    MODIF_DEMANDEE = 'PV_MODIF_DEMANDEE', 'Modification Demandée'
    REJETE = 'PV_REJETE', 'Rejeté'

class StatutReclamation(models.TextChoices):
    OUVERTE = 'RECLA_OUVERTE', 'Ouverte'
    EN_COURS = 'RECLA_EN_COURS', 'En cours de traitement'
    RESOLUE = 'RECLA_RESOLUE', 'Résolue'
    CLOTUREE = 'RECLA_CLOTUREE', 'Clôturée'