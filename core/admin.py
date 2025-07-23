from django.contrib import admin
from .models import *

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
admin.site.register(NiveauEtude)
admin.site.register(Specialite)
admin.site.register(Ue)
admin.site.register(Ecue)
admin.site.register(Inscription)
admin.site.register(Entreprise)
admin.site.register(Stage)
admin.site.register(Penalite)
admin.site.register(Note)

# Section Workflow du Rapport
admin.site.register(CritereConformite)
admin.site.register(RapportEtudiant)
admin.site.register(SectionRapport)
admin.site.register(ConformiteRapportDetail)
admin.site.register(SessionValidation)
admin.site.register(VoteCommission)
admin.site.register(ProcesVerbal)
admin.site.register(ValidationPv)