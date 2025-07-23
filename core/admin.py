# core/admin.py

from django.contrib import admin
from .models import (
    Etudiant, Enseignant, PersonnelAdministratif, RapportEtudiant, SectionRapport,
    CritereConformite, SessionValidation, ProcesVerbal, Penalite, Notification,
    Reclamation, Delegation, DocumentOfficiel, Stage, Inscription, Note, Ecue,
    AnneeAcademique, Specialite, Ue, Grade, Fonction, GradeEnseignant, FonctionEnseignant,
    Entreprise, Sequence, ConformiteRapportDetail, VoteCommission, ValidationPv,
    NiveauEtude
)

# Section Utilisateurs et Profils
admin.site.register(Etudiant)
admin.site.register(Enseignant)
admin.site.register(PersonnelAdministratif)
admin.site.register(Grade)
admin.site.register(Fonction)
admin.site.register(GradeEnseignant)
admin.site.register(FonctionEnseignant)

# Section Académique et Cursus
admin.site.register(AnneeAcademique)
admin.site.register(NiveauEtude) # Assurez-vous que NiveauEtude est importé et enregistré
admin.site.register(Specialite)
admin.site.register(Ue)
admin.site.register(Ecue)
admin.site.register(Inscription)
admin.site.register(Entreprise)
admin.site.register(Stage)
admin.site.register(Penalite)
admin.site.register(Note)
admin.site.register(Sequence) # Si vous voulez gérer les séquences d'ID

# Section Workflow du Rapport
admin.site.register(CritereConformite)
admin.site.register(RapportEtudiant)
admin.site.register(SectionRapport)
admin.site.register(ConformiteRapportDetail)
admin.site.register(SessionValidation)
admin.site.register(VoteCommission)
admin.site.register(ProcesVerbal)
admin.site.register(ValidationPv)

# Section Notifications et Réclamations
admin.site.register(Notification)
admin.site.register(Reclamation)
admin.site.register(Delegation)
admin.site.register(DocumentOfficiel)