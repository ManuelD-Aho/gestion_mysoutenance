from django.contrib.auth.models import User, Group # Permission n'est pas directement utilisé ici
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
import datetime
# import random # Supprimé car non utilisé directement dans le seed pour des valeurs aléatoires
import random

from core.enums import (
    StatutRapport, StatutPenalite, StatutPaiement,
    DecisionPassage, StatutConformite, ModeSession, StatutSession, DecisionVote,
    StatutPV, DecisionValidationPV, StatutReclamation # StatutCompte n'est pas utilisé ici
)
from core.models import (
    AnneeAcademique, NiveauEtude, Specialite, Inscription, Entreprise, Stage, Etudiant, Enseignant,
    PersonnelAdministratif, Grade, Fonction, CritereConformite, RapportEtudiant, SectionRapport,
    ConformiteRapportDetail, SessionValidation, VoteCommission, ProcesVerbal, ValidationPv,
    Penalite, Sequence, Notification, Reclamation, Delegation, DocumentOfficiel, Ue, Ecue, Note,
    GradeEnseignant, FonctionEnseignant
)
from core.services import UniqueIdGeneratorService

class Command(BaseCommand):
    help = 'Peuple la base de données avec un jeu de données complet et exhaustif pour GestionMySoutenance.'

    @transaction.atomic
    def handle(self, *args, **kwargs):
        self.stdout.write('Début du peuplement de la base de données...')

        self._clean_data()
        self._create_groups()
        self._create_referentials()
        users = self._create_users_and_profiles()
        self._create_academic_data(users)
        self._create_reports_and_workflow_data(users)
        self._create_notifications_and_reclamations(users)
        self._create_delegations(users)
        self._create_notes_and_documents(users)

        self.stdout.write(self.style.SUCCESS('Peuplement de la base de données terminé avec succès !'))

    def _clean_data(self):
        self.stdout.write('Nettoyage des données existantes...')
        DocumentOfficiel.objects.all().delete()
        Reclamation.objects.all().delete()
        Notification.objects.all().delete()
        Delegation.objects.all().delete()
        Note.objects.all().delete()
        ValidationPv.objects.all().delete()
        ProcesVerbal.objects.all().delete()
        VoteCommission.objects.all().delete()
        SessionValidation.objects.all().delete()
        ConformiteRapportDetail.objects.all().delete()
        SectionRapport.objects.all().delete()
        RapportEtudiant.objects.all().delete()
        Penalite.objects.all().delete()
        Inscription.objects.all().delete()
        Stage.objects.all().delete()
        Entreprise.objects.all().delete()
        Ecue.objects.all().delete()
        Ue.objects.all().delete()
        Specialite.objects.all().delete()
        NiveauEtude.objects.all().delete()
        AnneeAcademique.objects.all().delete()
        CritereConformite.objects.all().delete()
        FonctionEnseignant.objects.all().delete()
        GradeEnseignant.objects.all().delete()
        Enseignant.objects.all().delete()
        PersonnelAdministratif.objects.all().delete()
        Etudiant.objects.all().delete()
        Fonction.objects.all().delete()
        Grade.objects.all().delete()
        Sequence.objects.all().delete()
        User.objects.filter(is_superuser=False).delete()
        Group.objects.all().delete()
        self.stdout.write('Nettoyage terminé.')

    def _create_groups(self):
        self.stdout.write('Création des groupes utilisateurs...')
        Group.objects.create(name="Administrateur Système")
        Group.objects.create(name="Étudiant")
        Group.objects.create(name="Agent de Conformité")
        Group.objects.create(name="Membre de Commission")
        Group.objects.create(name="Responsable Scolarité")
        Group.objects.create(name="Enseignant")
        self.stdout.write('Groupes créés.')

    def _create_referentials(self):
        self.stdout.write('Création des données de référentiels...')
        self.annee_2023_2024 = AnneeAcademique.objects.create(id_annee_academique='ANNEE-2023-2024', libelle_annee_academique='2023-2024', date_debut='2023-09-01', date_fin='2024-08-31', est_active=False)
        self.annee_2024_2025 = AnneeAcademique.objects.create(id_annee_academique='ANNEE-2024-2025', libelle_annee_academique='2024-2025', date_debut='2024-09-01', date_fin='2025-08-31', est_active=True)
        self.annee_2025_2026 = AnneeAcademique.objects.create(id_annee_academique='ANNEE-2025-2026', libelle_annee_academique='2025-2026', date_debut='2025-09-01', date_fin='2026-08-31', est_active=False)

        self.m2 = NiveauEtude.objects.create(id_niveau_etude='M2', libelle_niveau_etude='Master 2')
        self.m1 = NiveauEtude.objects.create(id_niveau_etude='M1', libelle_niveau_etude='Master 1')
        self.l3 = NiveauEtude.objects.create(id_niveau_etude='L3', libelle_niveau_etude='Licence 3')

        self.miage = Specialite.objects.create(id_specialite='MIAGE', libelle_specialite="Méthodes Informatiques Appliquées à la Gestion des Entreprises")
        self.cybersec = Specialite.objects.create(id_specialite='CYBERSEC', libelle_specialite='Cybersécurité et Réseaux')
        self.ia_data = Specialite.objects.create(id_specialite='IA_DATA', libelle_specialite='Intelligence Artificielle et Science des Données')

        self.professeur = Grade.objects.create(id_grade='GRD_PR', libelle_grade='Professeur des Universités')
        self.maitre_conf = Grade.objects.create(id_grade='GRD_MCF', libelle_grade='Maître de Conférences')
        self.assistant = Grade.objects.create(id_grade='GRD_ASS', libelle_grade='Assistant')
        self.doctorant = Grade.objects.create(id_grade='GRD_DOC', libelle_grade='Doctorant')

        self.resp_scolarite_fct = Fonction.objects.create(id_fonction='FCT_RESP_SCO', libelle_fonction='Responsable Scolarité')
        self.agent_conformite_fct = Fonction.objects.create(id_fonction='FCT_AGENT_CONF', libelle_fonction='Agent de Conformité')
        self.dir_etudes_fct = Fonction.objects.create(id_fonction='FCT_DIR_ETUDES', libelle_fonction='Directeur des Études')
        self.pres_comm_fct = Fonction.objects.create(id_fonction='FCT_PRES_COMM', libelle_fonction='Président de Commission')

        CritereConformite.objects.create(id_critere='PAGE_GARDE', libelle_critere='Respect de la page de garde', description="La page de garde contient-elle le logo, le titre, le nom de l'étudiant, le nom du tuteur et l'année académique ?", est_actif=True)
        CritereConformite.objects.create(id_critere='PRESENCE_RESUME', libelle_critere='Présence du résumé', description="Un résumé (abstract) en français et en anglais est-il présent au début du document ?", est_actif=True)
        CritereConformite.objects.create(id_critere='BIBLIO_FORMAT', libelle_critere='Bibliographie formatée', description="La bibliographie respecte-t-elle la norme APA 7ème édition ?", est_actif=True)
        CritereConformite.objects.create(id_critere='VALIDITE_STAGE', libelle_critere='Validité du stage associée', description="Le stage est-il enregistré et validé par le service de scolarité ?", est_actif=True)

        self.entreprise1 = Entreprise.objects.create(id_entreprise='ENT-001', libelle_entreprise='Tech Solutions Inc.', secteur_activite='Informatique')
        self.entreprise2 = Entreprise.objects.create(id_entreprise='ENT-002', libelle_entreprise='Global Finance Corp.', secteur_activite='Finance')
        self.entreprise3 = Entreprise.objects.create(id_entreprise='ENT-003', libelle_entreprise='Innovate Labs', secteur_activite='Recherche & Développement')

        self.ue_prog = Ue.objects.create(id_ue='UE_PROG', libelle_ue='Programmation Avancée', credits_ue=6)
        self.ue_bd = Ue.objects.create(id_ue='UE_BD', libelle_ue='Bases de Données', credits_ue=5)

        self.ecue_python = Ecue.objects.create(id_ecue='ECUE_PYTHON', ue=self.ue_prog, libelle_ecue='Python pour la Data Science', credits_ecue=3)
        self.ecue_java = Ecue.objects.create(id_ecue='ECUE_JAVA', ue=self.ue_prog, libelle_ecue='Développement Java EE', credits_ecue=3)
        self.ecue_sql = Ecue.objects.create(id_ecue='ECUE_SQL', ue=self.ue_bd, libelle_ecue='SQL Avancé', credits_ecue=2)
        self.ecue_nosql = Ecue.objects.create(id_ecue='ECUE_NOSQL', ue=self.ue_bd, libelle_ecue='NoSQL et Big Data', credits_ecue=3)

        self.stdout.write('Référentiels créés.')

    def _create_users_and_profiles(self):
        self.stdout.write('Création des utilisateurs et profils...')
        users = {}

        admin_group = Group.objects.get(name='Administrateur Système')
        etudiant_group = Group.objects.get(name='Étudiant')
        agent_conf_group = Group.objects.get(name='Agent de Conformité')
        membre_comm_group = Group.objects.get(name='Membre de Commission')
        resp_scol_group = Group.objects.get(name='Responsable Scolarité')
        enseignant_group = Group.objects.get(name='Enseignant')

        admin_user, created = User.objects.get_or_create(username='ahopaul',
                                                   defaults={'first_name': 'Paul', 'last_name': 'AHO',
                                                             'email': 'ahopaul18@gmail.com', 'is_staff': True,
                                                             'is_superuser': True, 'email_valide': True})
        admin_user.set_password('password123')
        admin_user.groups.add(admin_group)
        admin_user.save()
        users['admin_user'] = admin_user

        rs_user = User.objects.create_user(username='nguessan.c', first_name="Christian", last_name="N'GUESSAN A.",
                                           email='christian.nguessan@example.com', password='password123',
                                           is_staff=True, email_valide=True)
        rs_user.groups.add(resp_scol_group)
        PersonnelAdministratif.objects.create(utilisateur=rs_user, nom=rs_user.last_name, prenom=rs_user.first_name,
                                              email_professionnel=rs_user.email)
        users['rs_user'] = rs_user

        ac_user = User.objects.create_user(username='guei.f', first_name='Flora', last_name='GUEI T.',
                                           email='flora.guei@example.com', password='password123', is_staff=True,
                                           email_valide=True)
        ac_user.groups.add(agent_conf_group)
        PersonnelAdministratif.objects.create(utilisateur=ac_user, nom=ac_user.last_name, prenom=ac_user.first_name,
                                              email_professionnel=ac_user.email)
        users['ac_user'] = ac_user

        prof_magloire_user = User.objects.create_user(username='kouassi.m', first_name='Magloire', last_name='KOUASSI A.',
                                                 email='magloire.kouassi@example.com', password='password123', email_valide=True)
        prof_magloire_user.groups.add(enseignant_group)
        prof_magloire_user.groups.add(membre_comm_group)
        prof_magloire = Enseignant.objects.create(utilisateur=prof_magloire_user, nom=prof_magloire_user.last_name,
                                  prenom=prof_magloire_user.first_name, email_professionnel=prof_magloire_user.email)
        GradeEnseignant.objects.create(enseignant=prof_magloire, grade=self.professeur, date_acquisition='2020-09-01')
        FonctionEnseignant.objects.create(enseignant=prof_magloire, fonction=self.pres_comm_fct, date_debut_occupation='2023-09-01')
        self.miage.responsable_specialite = prof_magloire
        self.miage.save()
        users['prof_magloire'] = prof_magloire_user

        prof_yvette_user = User.objects.create_user(username='yapo.y', first_name='Yvette', last_name='YAPO A.',
                                               email='yvette.yapo@example.com', password='password123', email_valide=True)
        prof_yvette_user.groups.add(enseignant_group)
        prof_yvette_user.groups.add(membre_comm_group)
        prof_yvette = Enseignant.objects.create(utilisateur=prof_yvette_user, nom=prof_yvette_user.last_name,
                                  prenom=prof_yvette_user.first_name, email_professionnel=prof_yvette_user.email)
        GradeEnseignant.objects.create(enseignant=prof_yvette, grade=self.maitre_conf, date_acquisition='2022-01-15')
        users['prof_yvette'] = prof_yvette_user

        prof_jean_user = User.objects.create_user(username='kone.j', first_name='Jean', last_name='KONE',
                                               email='jean.kone@example.com', password='password123', email_valide=True)
        prof_jean_user.groups.add(enseignant_group)
        prof_jean_user.groups.add(membre_comm_group)
        prof_jean = Enseignant.objects.create(utilisateur=prof_jean_user, nom=prof_jean_user.last_name,
                                  prenom=prof_jean_user.first_name, email_professionnel=prof_jean_user.email)
        GradeEnseignant.objects.create(enseignant=prof_jean, grade=self.maitre_conf, date_acquisition='2021-03-01')
        users['prof_jean'] = prof_jean_user

        etudiant_alla_user = User.objects.create_user(username='alla.c', first_name='Christ-Amour', last_name='ALLA Y.',
                                                 email='christ.alla@example.com', password='password123', email_valide=False)
        etudiant_alla_user.groups.add(etudiant_group)
        etudiant_alla = Etudiant.objects.create(utilisateur=etudiant_alla_user, nom=etudiant_alla_user.last_name, prenom=etudiant_alla_user.first_name, est_eligible_soumission=False)
        users['etudiant_alla'] = etudiant_alla_user

        etudiant_aka_user = User.objects.create_user(username='aka.e', first_name='Evrard', last_name='AKA A.',
                                                email='evrard.aka@example.com', password='password123', email_valide=True, is_active=True)
        etudiant_aka_user.groups.add(etudiant_group)
        etudiant_aka = Etudiant.objects.create(utilisateur=etudiant_aka_user, nom=etudiant_aka_user.last_name, prenom=etudiant_aka_user.first_name, est_eligible_soumission=True)
        users['etudiant_aka'] = etudiant_aka_user

        etudiant_marie_user = User.objects.create_user(username='konan.m', first_name='Marie', last_name='KONAN',
                                                email='marie.konan@example.com', password='password123', email_valide=True, is_active=True)
        etudiant_marie_user.groups.add(etudiant_group)
        etudiant_marie = Etudiant.objects.create(utilisateur=etudiant_marie_user, nom=etudiant_marie_user.last_name, prenom=etudiant_marie_user.first_name, est_eligible_soumission=True)
        users['etudiant_marie'] = etudiant_marie_user

        self.stdout.write('Utilisateurs et profils créés.')
        return users

    def _create_academic_data(self, users):
        self.stdout.write('Création des données académiques (inscriptions, stages, pénalités)...')

        etudiant_alla_profil = Etudiant.objects.get(utilisateur=users['etudiant_alla'])
        etudiant_aka_profil = Etudiant.objects.get(utilisateur=users['etudiant_aka'])
        etudiant_marie_profil = Etudiant.objects.get(utilisateur=users['etudiant_marie'])

        Inscription.objects.create(
            etudiant=etudiant_alla_profil,
            niveau_etude=self.m2,
            annee_academique=self.annee_2024_2025,
            montant_inscription=500000,
            date_inscription=timezone.now(),
            statut_paiement=StatutPaiement.EN_ATTENTE
        )
        Inscription.objects.create(
            etudiant=etudiant_aka_profil,
            niveau_etude=self.m2,
            annee_academique=self.annee_2024_2025,
            montant_inscription=500000,
            date_inscription=timezone.now(),
            statut_paiement=StatutPaiement.PAYE
        )
        Inscription.objects.create(
            etudiant=etudiant_marie_profil,
            niveau_etude=self.m2,
            annee_academique=self.annee_2024_2025,
            montant_inscription=500000,
            date_inscription=timezone.now(),
            statut_paiement=StatutPaiement.PAYE
        )
        Inscription.objects.create(
            etudiant=etudiant_alla_profil,
            niveau_etude=self.m2,
            annee_academique=self.annee_2023_2024,
            montant_inscription=500000,
            date_inscription=timezone.make_aware(datetime.datetime(2023, 9, 1)),
            statut_paiement=StatutPaiement.PAYE,
            decision_passage=DecisionPassage.AJOURNE
        )

        self.stage_alla_1 = Stage.objects.create(
            entreprise=self.entreprise1,
            etudiant=etudiant_alla_profil,
            date_debut_stage='2025-03-01',
            date_fin_stage='2025-08-31',
            sujet_stage="Développement d'une plateforme de gestion académique",
            est_valide=False
        )
        self.stage_aka_1 = Stage.objects.create(
            entreprise=self.entreprise2,
            etudiant=etudiant_aka_profil,
            date_debut_stage='2025-02-01',
            date_fin_stage='2025-07-31',
            sujet_stage="Analyse et sécurisation des systèmes d'information",
            est_valide=True
        )
        self.stage_aka_2 = Stage.objects.create(
            entreprise=self.entreprise1,
            etudiant=etudiant_aka_profil,
            date_debut_stage='2024-09-01',
            date_fin_stage='2025-01-31',
            sujet_stage="Optimisation des performances d'une base de données NoSQL",
            est_valide=True
        )
        self.stage_marie_1 = Stage.objects.create(
            entreprise=self.entreprise3,
            etudiant=etudiant_marie_profil,
            date_debut_stage='2025-01-15',
            date_fin_stage='2025-06-30',
            sujet_stage="Optimisation d'algorithmes d'apprentissage automatique",
            est_valide=True
        )
        self.stage_marie_2 = Stage.objects.create(
            entreprise=self.entreprise2,
            etudiant=etudiant_marie_profil,
            date_debut_stage='2024-08-01',
            date_fin_stage='2024-12-31',
            sujet_stage="Impact de l'IA sur l'emploi et l'éthique",
            est_valide=True
        )

        Penalite.objects.create(
            id_penalite=UniqueIdGeneratorService.generate('PEN'),
            etudiant=etudiant_alla_profil,
            annee_academique=self.annee_2023_2024,
            type_penalite=TypePenalite.FINANCIERE,
            montant_du=100000,
            motif="Dépassement de délai de soumission du rapport (année N+1)",
            statut_penalite=StatutPenalite.DUE,
            date_creation=timezone.make_aware(datetime.datetime(2024, 9, 15))
        )
        self.stdout.write('Données académiques créées.')

    def _create_reports_and_workflow_data(self, users):
        self.stdout.write('Création des rapports et données de workflow...')

        etudiant_alla_profil = Etudiant.objects.get(utilisateur=users['etudiant_alla'])
        etudiant_aka_profil = Etudiant.objects.get(utilisateur=users['etudiant_aka'])
        etudiant_marie_profil = Etudiant.objects.get(utilisateur=users['etudiant_marie'])
        prof_magloire_enseignant = Enseignant.objects.get(utilisateur=users['prof_magloire'])
        prof_yvette_enseignant = Enseignant.objects.get(utilisateur=users['prof_yvette'])
        prof_jean_enseignant = Enseignant.objects.get(utilisateur=users['prof_jean'])
        ac_personnel = PersonnelAdministratif.objects.get(utilisateur=users['ac_user'])

        rapport_alla_brouillon = RapportEtudiant.objects.create(
            id_rapport_etudiant=UniqueIdGeneratorService.generate('RAP'),
            libelle_rapport_etudiant="Brouillon de rapport sur la gestion de projet Agile",
            theme="Gestion de projet",
            etudiant=etudiant_alla_profil,
            stage=self.stage_alla_1,
            statut_rapport=StatutRapport.BROUILLON,
            nombre_pages=None
        )
        SectionRapport.objects.create(rapport_etudiant=rapport_alla_brouillon, titre_section="Introduction", contenu_section="Ceci est l'introduction du brouillon.", ordre=1)
        SectionRapport.objects.create(rapport_etudiant=rapport_alla_brouillon, titre_section="Conclusion", contenu_section="Ceci est la conclusion du brouillon.", ordre=5)

        rapport_aka_soumis = RapportEtudiant.objects.create(
            id_rapport_etudiant=UniqueIdGeneratorService.generate('RAP'),
            libelle_rapport_etudiant="Rapport sur la Cybersécurité en PME",
            theme="Cybersécurité",
            etudiant=etudiant_aka_profil,
            stage=self.stage_aka_1,
            statut_rapport=StatutRapport.SOUMIS,
            date_soumission=timezone.now() - datetime.timedelta(days=5),
            nombre_pages=65
        )
        SectionRapport.objects.create(rapport_etudiant=rapport_aka_soumis, titre_section="Introduction", contenu_section="Introduction du rapport sur la cybersécurité.", ordre=1)
        SectionRapport.objects.create(rapport_etudiant=rapport_aka_soumis, titre_section="Analyse des risques", contenu_section="Détail de l'analyse des risques.", ordre=2)
        SectionRapport.objects.create(rapport_etudiant=rapport_aka_soumis, titre_section="Conclusion", contenu_section="Conclusion du rapport.", ordre=5)

        rapport_marie_non_conf = RapportEtudiant.objects.create(
            id_rapport_etudiant=UniqueIdGeneratorService.generate('RAP'),
            libelle_rapport_etudiant="Rapport sur l'IA et le Machine Learning",
            theme="Intelligence Artificielle",
            etudiant=etudiant_marie_profil,
            stage=self.stage_marie_1,
            statut_rapport=StatutRapport.NON_CONFORME,
            date_soumission=timezone.now() - datetime.timedelta(days=10),
            commentaires_conformite="Page de garde non conforme, bibliographie manquante.",
            nombre_pages=80
        )
        SectionRapport.objects.create(rapport_etudiant=rapport_marie_non_conf, titre_section="Introduction", contenu_section="Introduction du rapport IA.", ordre=1)
        SectionRapport.objects.create(rapport_etudiant=rapport_marie_non_conf, titre_section="Algorithmes", contenu_section="Détail des algorithmes utilisés.", ordre=2)
        ConformiteRapportDetail.objects.create(rapport_etudiant=rapport_marie_non_conf, critere=CritereConformite.objects.get(id_critere='PAGE_GARDE'), statut_validation=StatutConformite.NON_CONFORME, commentaire="Logo manquant", verifie_par=ac_personnel)
        ConformiteRapportDetail.objects.create(rapport_etudiant=rapport_marie_non_conf, critere=CritereConformite.objects.get(id_critere='BIBLIO_FORMAT'), statut_validation=StatutConformite.NON_CONFORME, commentaire="Section bibliographie absente", verifie_par=ac_personnel)
        ConformiteRapportDetail.objects.create(rapport_etudiant=rapport_marie_non_conf, critere=CritereConformite.objects.get(id_critere='PRESENCE_RESUME'), statut_validation=StatutConformite.CONFORME, verifie_par=ac_personnel)
        ConformiteRapportDetail.objects.create(rapport_etudiant=rapport_marie_non_conf, critere=CritereConformite.objects.get(id_critere='VALIDITE_STAGE'), statut_validation=StatutConformite.CONFORME, verifie_par=ac_personnel)


        rapport_aka_conf = RapportEtudiant.objects.create(
            id_rapport_etudiant=UniqueIdGeneratorService.generate('RAP'),
            libelle_rapport_etudiant="Rapport sur l'optimisation des bases de données NoSQL",
            theme="Bases de données",
            etudiant=etudiant_aka_profil,
            stage=self.stage_aka_2,
            statut_rapport=StatutRapport.CONFORME,
            date_soumission=timezone.now() - datetime.timedelta(days=15),
            nombre_pages=70
        )
        SectionRapport.objects.create(rapport_etudiant=rapport_aka_conf, titre_section="Introduction", contenu_section="Introduction du rapport NoSQL.", ordre=1)
        SectionRapport.objects.create(rapport_etudiant=rapport_aka_conf, titre_section="Optimisation", contenu_section="Techniques d'optimisation.", ordre=2)
        ConformiteRapportDetail.objects.create(rapport_etudiant=rapport_aka_conf, critere=CritereConformite.objects.get(id_critere='PAGE_GARDE'), statut_validation=StatutConformite.CONFORME, verifie_par=ac_personnel)
        ConformiteRapportDetail.objects.create(rapport_etudiant=rapport_aka_conf, critere=CritereConformite.objects.get(id_critere='BIBLIO_FORMAT'), statut_validation=StatutConformite.CONFORME, verifie_par=ac_personnel)
        ConformiteRapportDetail.objects.create(rapport_etudiant=rapport_aka_conf, critere=CritereConformite.objects.get(id_critere='PRESENCE_RESUME'), statut_validation=StatutConformite.CONFORME, verifie_par=ac_personnel)
        ConformiteRapportDetail.objects.create(rapport_etudiant=rapport_aka_conf, critere=CritereConformite.objects.get(id_critere='VALIDITE_STAGE'), statut_validation=StatutConformite.CONFORME, verifie_par=ac_personnel)


        session_planifiee = SessionValidation.objects.create(
            id_session=UniqueIdGeneratorService.generate('SES'),
            nom_session="Session de validation des rapports - Janvier 2026",
            date_debut_session=timezone.make_aware(datetime.datetime(2026, 1, 10, 9, 0)),
            date_fin_prevue=timezone.make_aware(datetime.datetime(2026, 1, 10, 17, 0)),
            president_session=prof_magloire_enseignant,
            mode_session=ModeSession.PRESENTIEL,
            statut_session=StatutSession.PLANIFIEE,
            nombre_votants_requis=2
        )
        session_planifiee.rapports.add(rapport_aka_conf)
        session_planifiee.membres.add(prof_magloire_enseignant, prof_yvette_enseignant, prof_jean_enseignant)

        session_cloturee = SessionValidation.objects.create(
            id_session=UniqueIdGeneratorService.generate('SES'),
            nom_session="Session de validation des rapports - Décembre 2024",
            date_debut_session=timezone.make_aware(datetime.datetime(2024, 12, 5, 9, 0)),
            date_fin_prevue=timezone.make_aware(datetime.datetime(2024, 12, 5, 17, 0)),
            president_session=prof_magloire_enseignant,
            mode_session=ModeSession.EN_LIGNE,
            statut_session=StatutSession.CLOTUREE,
            nombre_votants_requis=2
        )
        rapport_valide = RapportEtudiant.objects.create(
            id_rapport_etudiant=UniqueIdGeneratorService.generate('RAP'),
            libelle_rapport_etudiant="Rapport sur l'impact de l'IA sur l'emploi",
            theme="IA et Société",
            etudiant=etudiant_marie_profil,
            stage=self.stage_marie_2,
            statut_rapport=StatutRapport.VALIDE,
            date_soumission=timezone.now() - datetime.timedelta(days=60),
            directeur_memoire=prof_yvette_enseignant,
            nombre_pages=90
        )
        session_cloturee.rapports.add(rapport_valide)
        session_cloturee.membres.add(prof_magloire_enseignant, prof_yvette_enseignant)

        VoteCommission.objects.create(
            id_vote=UniqueIdGeneratorService.generate('VOT'),
            session=session_cloturee,
            rapport_etudiant=rapport_valide,
            enseignant=prof_magloire_enseignant,
            decision_vote=DecisionVote.APPROUVE,
            commentaire_vote="Excellent travail, bien structuré.",
            tour_vote=1
        )
        VoteCommission.objects.create(
            id_vote=UniqueIdGeneratorService.generate('VOT'),
            session=session_cloturee,
            rapport_etudiant=rapport_valide,
            enseignant=prof_yvette_enseignant,
            decision_vote=DecisionVote.APPROUVE_RESERVE,
            commentaire_vote="Quelques coquilles mineures à corriger, mais le fond est solide.",
            tour_vote=1
        )

        pv_cloture = ProcesVerbal.objects.create(
            id_compte_rendu=UniqueIdGeneratorService.generate('PV_'),
            session=session_cloturee,
            libelle_compte_rendu="Procès-Verbal de la session de Décembre 2024. Rapport de Marie KONAN validé avec mention.",
            statut_pv=StatutPV.VALIDE,
            redacteur=prof_magloire_enseignant,
            date_finalisation=timezone.make_aware(datetime.datetime(2024, 12, 5, 18, 0))
        )
        ValidationPv.objects.create(proces_verbal=pv_cloture, enseignant=prof_magloire_enseignant, decision_validation_pv=DecisionValidationPV.APPROUVE)
        ValidationPv.objects.create(proces_verbal=pv_cloture, enseignant=prof_yvette_enseignant, decision_validation_pv=DecisionValidationPV.APPROUVE)

        self.stdout.write('Rapports et données de workflow créés.')

    def _create_notifications_and_reclamations(self, users):
        self.stdout.write('Création des notifications et réclamations...')

        etudiant_alla_user = users['etudiant_alla']
        etudiant_aka_user = users['etudiant_aka']
        ac_user = users['ac_user']
        rs_user = users['rs_user']

        Notification.objects.create(
            destinataire=etudiant_alla_user,
            message="Votre adresse email n'est pas validée. Veuillez cliquer sur le lien dans l'email de confirmation.",
            type_notification="email_non_valide",
            lien_action="/etudiant/profil",
            est_lue=False
        )
        Notification.objects.create(
            destinataire=etudiant_alla_user,
            message="Vous avez une pénalité de retard à régulariser pour la soumission de votre rapport.",
            type_notification="penalite_due",
            lien_action="/etudiant/penalites",
            est_lue=False
        )

        Notification.objects.create(
            destinataire=etudiant_aka_user,
            message="Votre rapport 'Rapport sur la Cybersécurité en PME' a été soumis avec succès.",
            type_notification="rapport_soumis",
            lien_action="/etudiant/rapports/detail/" + RapportEtudiant.objects.get(etudiant=etudiant_aka_user.profil_etudiant, statut_rapport=StatutRapport.SOUMIS).id_rapport_etudiant,
            est_lue=True
        )

        Notification.objects.create(
            destinataire=ac_user,
            message=f"Un nouveau rapport ({RapportEtudiant.objects.get(etudiant=etudiant_aka_user.profil_etudiant, statut_rapport=StatutRapport.SOUMIS).libelle_rapport_etudiant}) est en attente de vérification de conformité.",
            type_notification="nouveau_rapport_conformite",
            lien_action="/personnel/conformite/dashboard",
            est_lue=False
        )

        Reclamation.objects.create(
            etudiant=etudiant_alla_user.profil_etudiant,
            sujet="Problème d'accès à la plateforme",
            description="Je n'arrive pas à me connecter, mon compte semble bloqué.",
            date_soumission=timezone.now() - datetime.timedelta(days=2),
            statut=StatutReclamation.OUVERTE,
            assigne_a=rs_user
        )
        Reclamation.objects.create(
            etudiant=etudiant_aka_user.profil_etudiant,
            sujet="Demande de relevé de notes officiel",
            description="J'aurais besoin d'un relevé de notes officiel pour ma candidature.",
            date_soumission=timezone.now() - datetime.timedelta(days=7),
            statut=StatutReclamation.RESOLUE,
            assigne_a=rs_user,
            date_resolution=timezone.now() - datetime.timedelta(days=5),
            commentaire_resolution="Relevé généré et disponible dans l'espace étudiant."
        )
        self.stdout.write('Notifications et réclamations créées.')

    def _create_delegations(self, users):
        self.stdout.write('Création des délégations...')
        prof_magloire_user = users['prof_magloire']
        prof_yvette_user = users['prof_yvette']
        ac_user = users['ac_user']
        rs_user = users['rs_user']

        Delegation.objects.create(
            delegant=prof_magloire_user,
            delegue=prof_yvette_user,
            permissions_delegues=['core.change_procesverbal', 'core.add_validationpv'],
            date_debut=timezone.now().date() - datetime.timedelta(days=5),
            date_fin=timezone.now().date() + datetime.timedelta(days=10),
            est_active=True
        )

        Delegation.objects.create(
            delegant=ac_user,
            delegue=rs_user,
            permissions_delegues=['core.change_rapportetudiant', 'core.add_conformiterapportdetail'],
            date_debut=timezone.now().date() - datetime.timedelta(days=30),
            date_fin=timezone.now().date() - datetime.timedelta(days=20),
            est_active=False
        )
        self.stdout.write('Délégations créées.')

    def _create_notes_and_documents(self, users):
        self.stdout.write('Création des notes et documents officiels...')
        etudiant_aka_profil = Etudiant.objects.get(utilisateur=users['etudiant_aka'])
        etudiant_marie_profil = Etudiant.objects.get(utilisateur=users['etudiant_marie'])
        rs_personnel = PersonnelAdministratif.objects.get(utilisateur=users['rs_user'])

        Note.objects.create(etudiant=etudiant_aka_profil, ecue=self.ecue_python, annee_academique=self.annee_2024_2025, date_evaluation=timezone.now(), note=16.5)
        Note.objects.create(etudiant=etudiant_aka_profil, ecue=self.ecue_sql, annee_academique=self.annee_2024_2025, date_evaluation=timezone.now(), note=14.0)

        Note.objects.create(etudiant=etudiant_marie_profil, ecue=self.ecue_java, annee_academique=self.annee_2024_2025, date_evaluation=timezone.now(), note=18.0)
        Note.objects.create(etudiant=etudiant_marie_profil, ecue=self.ecue_nosql, annee_academique=self.annee_2024_2025, date_evaluation=timezone.now(), note=17.5)

        DocumentOfficiel.objects.create(
            id_document=UniqueIdGeneratorService.generate('DOC'),
            etudiant=etudiant_aka_profil,
            type_document='Bulletin',
            annee_academique=self.annee_2024_2025,
            chemin_fichier='/documents/bulletins/AKA-2024-2025-v1.pdf',
            est_officiel=True,
            genere_par=rs_personnel
        )
        DocumentOfficiel.objects.create(
            id_document=UniqueIdGeneratorService.generate('DOC'),
            etudiant=etudiant_aka_profil,
            type_document='AttestationScolarite',
            annee_academique=self.annee_2024_2025,
            chemin_fichier='/documents/attestations/AKA-2024-2025-attestation.pdf',
            est_officiel=True,
            genere_par=rs_personnel
        )
        pv_marie = ProcesVerbal.objects.get(session__rapports__etudiant=etudiant_marie_profil, statut_pv=StatutPV.VALIDE)
        DocumentOfficiel.objects.create(
            id_document=UniqueIdGeneratorService.generate('DOC'),
            etudiant=etudiant_marie_profil,
            type_document='ProcesVerbal',
            annee_academique=self.annee_2024_2025,
            chemin_fichier=f'/documents/pv/{pv_marie.id_compte_rendu}.pdf', # <-- CORRECTION ICI
            est_officiel=True,
            genere_par=rs_personnel
        )

        self.stdout.write('Notes et documents officiels créés.')