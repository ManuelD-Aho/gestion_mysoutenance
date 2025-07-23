from django.contrib.auth.models import User, Group
from django.core.management.base import BaseCommand
from django.db import transaction

from core.enums import *
from core.models import (
    AnneeAcademique, NiveauEtude, Specialite, Inscription, Entreprise, Stage, Etudiant, Enseignant,
    PersonnelAdministratif, Grade, Fonction, CritereConformite
)


class Command(BaseCommand):
    help = 'Peuple la base de données avec un jeu de données complet et exhaustif.'

    @transaction.atomic
    def handle(self, *args, **kwargs):
        self.stdout.write('Début du peuplement de la base de données...')

        self._clean_data()
        self._create_groups()
        self._create_referentials()
        users = self._create_users_and_profiles()
        self._create_academic_data(users)

        self.stdout.write(self.style.SUCCESS('Peuplement de la base de données terminé avec succès !'))

    def _clean_data(self):
        self.stdout.write('Nettoyage des données existantes...')
        User.objects.filter(is_superuser=False).delete()
        Group.objects.all().delete()
        AnneeAcademique.objects.all().delete()
        NiveauEtude.objects.all().delete()
        Specialite.objects.all().delete()
        Grade.objects.all().delete()
        Fonction.objects.all().delete()
        Entreprise.objects.all().delete()

    def _create_groups(self):
        self.stdout.write('Création des groupes utilisateurs...')
        Group.objects.create(name="Administrateur Système")
        Group.objects.create(name="Étudiant")
        Group.objects.create(name="Agent de Conformité")
        Group.objects.create(name="Membre de Commission")
        Group.objects.create(name="Responsable Scolarité")
        Group.objects.create(name="Enseignant")

    def _create_referentials(self):
        self.stdout.write('Création des données de référentiels...')
        AnneeAcademique.objects.create(id_annee_academique='ANNEE-2023-2024', libelle_annee_academique='2023-2024',
                                       date_debut='2023-09-01', date_fin='2024-08-31', est_active=False)
        AnneeAcademique.objects.create(id_annee_academique='ANNEE-2024-2025', libelle_annee_academique='2024-2025',
                                       date_debut='2024-09-01', date_fin='2025-08-31', est_active=True)
        AnneeAcademique.objects.create(id_annee_academique='ANNEE-2025-2026', libelle_annee_academique='2025-2026',
                                       date_debut='2025-09-01', date_fin='2026-08-31', est_active=False)

        NiveauEtude.objects.create(id_niveau_etude='M2', libelle_niveau_etude='Master 2')
        NiveauEtude.objects.create(id_niveau_etude='M1', libelle_niveau_etude='Master 1')
        NiveauEtude.objects.create(id_niveau_etude='L3', libelle_niveau_etude='Licence 3')

        Specialite.objects.create(id_specialite='MIAGE',
                                  libelle_specialite="Méthodes Informatiques Appliquées à la Gestion des Entreprises")
        Specialite.objects.create(id_specialite='CYBERSEC', libelle_specialite='Cybersécurité et Réseaux')
        Specialite.objects.create(id_specialite='IA_DATA',
                                  libelle_specialite='Intelligence Artificielle et Science des Données')

        Grade.objects.create(id_grade='GRD_PR', libelle_grade='Professeur des Universités')
        Grade.objects.create(id_grade='GRD_MCF', libelle_grade='Maître de Conférences')
        Grade.objects.create(id_grade='GRD_ASS', libelle_grade='Assistant')
        Grade.objects.create(id_grade='GRD_DOC', libelle_grade='Doctorant')

        Fonction.objects.create(id_fonction='FCT_RESP_SCO', libelle_fonction='Responsable Scolarité')
        Fonction.objects.create(id_fonction='FCT_AGENT_CONF', libelle_fonction='Agent de Conformité')
        Fonction.objects.create(id_fonction='FCT_DIR_ETUDES', libelle_fonction='Directeur des Études')
        Fonction.objects.create(id_fonction='FCT_PRES_COMM', libelle_fonction='Président de Commission')

        CritereConformite.objects.create(id_critere='PAGE_GARDE', libelle_critere='Respect de la page de garde',
                                         description="La page de garde contient-elle le logo, le titre, le nom de l'étudiant, le nom du tuteur et l'année académique ?",
                                         est_actif=True)
        CritereConformite.objects.create(id_critere='PRESENCE_RESUME', libelle_critere='Présence du résumé',
                                         description="Un résumé (abstract) en français et en anglais est-il présent au début du document ?",
                                         est_actif=True)
        CritereConformite.objects.create(id_critere='BIBLIO_FORMAT', libelle_critere='Bibliographie formatée',
                                         description="La bibliographie respecte-t-elle la norme APA 7ème édition ?",
                                         est_actif=True)

        Entreprise.objects.create(id_entreprise='ENT-001', libelle_entreprise='Tech Solutions Inc.',
                                  secteur_activite='Informatique')
        Entreprise.objects.create(id_entreprise='ENT-002', libelle_entreprise='Global Finance Corp.',
                                  secteur_activite='Finance')

    def _create_users_and_profiles(self):
        self.stdout.write('Création des utilisateurs et profils...')
        users = {}

        admin_user, _ = User.objects.get_or_create(username='ahopaul',
                                                   defaults={'first_name': 'Paul', 'last_name': 'AHO',
                                                             'email': 'ahopaul18@gmail.com', 'is_staff': True,
                                                             'is_superuser': True})
        admin_user.set_password('password123')
        admin_user.groups.add(Group.objects.get(name='Administrateur Système'))
        admin_user.save()
        users['admin_user'] = admin_user

        rs_user = User.objects.create_user(username='nguessan.c', first_name="Christian", last_name="N'GUESSAN A.",
                                           email='christian.nguessan@example.com', password='password123',
                                           is_staff=True)
        rs_user.groups.add(Group.objects.get(name='Responsable Scolarité'))
        users['rs_user'] = rs_user
        PersonnelAdministratif.objects.create(utilisateur=rs_user, nom=rs_user.last_name, prenom=rs_user.first_name)

        ac_user = User.objects.create_user(username='guei.f', first_name='Flora', last_name='GUEI T.',
                                           email='flora.guei@example.com', password='password123', is_staff=True)
        ac_user.groups.add(Group.objects.get(name='Agent de Conformité'))
        users['ac_user'] = ac_user
        PersonnelAdministratif.objects.create(utilisateur=ac_user, nom=ac_user.last_name, prenom=ac_user.first_name)

        prof_magloire = User.objects.create_user(username='kouassi.m', first_name='Magloire', last_name='KOUASSI A.',
                                                 email='magloire.kouassi@example.com', password='password123')
        prof_magloire.groups.add(Group.objects.get(name='Enseignant'))
        prof_magloire.groups.add(Group.objects.get(name='Membre de Commission'))
        users['prof_magloire'] = prof_magloire
        Enseignant.objects.create(utilisateur=prof_magloire, nom=prof_magloire.last_name,
                                  prenom=prof_magloire.first_name)

        prof_yvette = User.objects.create_user(username='yapo.y', first_name='Yvette', last_name='YAPO A.',
                                               email='yvette.yapo@example.com', password='password123')
        prof_yvette.groups.add(Group.objects.get(name='Enseignant'))
        users['prof_yvette'] = prof_yvette
        Enseignant.objects.create(utilisateur=prof_yvette, nom=prof_yvette.last_name, prenom=prof_yvette.first_name)

        etudiant_alla = User.objects.create_user(username='alla.c', first_name='Christ-Amour', last_name='ALLA Y.',
                                                 email='christ.alla@example.com', password='password123')
        etudiant_alla.groups.add(Group.objects.get(name='Étudiant'))
        users['etudiant_alla'] = etudiant_alla
        Etudiant.objects.create(utilisateur=etudiant_alla, nom=etudiant_alla.last_name, prenom=etudiant_alla.first_name)

        etudiant_aka = User.objects.create_user(username='aka.e', first_name='Evrard', last_name='AKA A.',
                                                email='evrard.aka@example.com', password='password123')
        etudiant_aka.groups.add(Group.objects.get(name='Étudiant'))
        users['etudiant_aka'] = etudiant_aka
        Etudiant.objects.create(utilisateur=etudiant_aka, nom=etudiant_aka.last_name, prenom=etudiant_aka.first_name)

        return users

    def _create_academic_data(self, users):
        self.stdout.write('Création des données académiques (inscriptions, stages)...')

        annee_active = AnneeAcademique.objects.get(est_active=True)
        niveau_m2 = NiveauEtude.objects.get(id_niveau_etude='M2')
        Specialite.objects.get(id_specialite='MIAGE')

        etudiant_alla_profil = Etudiant.objects.get(utilisateur=users['etudiant_alla'])
        etudiant_aka_profil = Etudiant.objects.get(utilisateur=users['etudiant_aka'])

        Inscription.objects.create(
            etudiant=etudiant_alla_profil,
            niveau_etude=niveau_m2,
            annee_academique=annee_active,
            montant_inscription=500000,
            date_inscription='2024-10-15',
            statut_paiement=StatutPaiement.PAYE
        )

        Inscription.objects.create(
            etudiant=etudiant_aka_profil,
            niveau_etude=niveau_m2,
            annee_academique=annee_active,
            montant_inscription=500000,
            date_inscription='2024-10-20',
            statut_paiement=StatutPaiement.PAYE
        )

        entreprise1 = Entreprise.objects.get(id_entreprise='ENT-001')

        Stage.objects.create(
            entreprise=entreprise1,
            etudiant=etudiant_alla_profil,
            date_debut_stage='2025-03-01',
            date_fin_stage='2025-08-31',
            sujet_stage="Développement d'une plateforme de gestion académique"
        )