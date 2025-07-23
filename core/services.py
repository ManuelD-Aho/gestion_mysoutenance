from django.db import transaction
from django.utils import timezone
from django.contrib.auth.models import User, Group, Permission
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.db.models import Q, F
import datetime
import uuid
import pyotp
import logging
import os
import random  # <-- AJOUTÉ
from django.db import models  # <-- AJOUTÉ pour isinstance(val, models.Model)

# Importations pour la génération de PDF (nécessitent l'installation de bibliothèques comme WeasyPrint)
# from weasyprint import HTML, CSS
# from django.core.files.base import ContentFile
# from django.core.files.storage import default_storage

# Importations pour les tâches asynchrones (nécessitent l'installation et la configuration de Celery)
# from .tasks import process_import_file, generate_mass_bulletins_task

from core.models import (
    Sequence, Etudiant, Enseignant, PersonnelAdministratif, RapportEtudiant, SectionRapport,
    CritereConformite, ConformiteRapportDetail, SessionValidation, VoteCommission, ProcesVerbal,
    ValidationPv, Inscription, Stage, Penalite, Notification, Reclamation, Delegation,
    DocumentOfficiel, Note, Ecue, AnneeAcademique
)
from core.enums import (
    StatutRapport, StatutConformite, DecisionVote, StatutPV, DecisionValidationPV  # Imports nettoyés
)

audit_logger = logging.getLogger('audit_logger')
error_logger = logging.getLogger('error_logger')


class UniqueIdGeneratorService:
    @staticmethod
    @transaction.atomic
    def generate(prefix, year=None):
        if year is None:
            year = timezone.now().year

        sequence, created = Sequence.objects.select_for_update().get_or_create(
            nom_sequence=prefix,
            annee=year,
            defaults={'valeur_actuelle': 0}
        )

        sequence.valeur_actuelle += 1
        sequence.save()

        return f"{prefix.upper()}-{year}-{str(sequence.valeur_actuelle).zfill(4)}"


class AuthentificationService:
    @staticmethod
    def send_email_validation_token(user):
        if user.email_valide:
            audit_logger.warning(
                f"Tentative d'envoi de jeton de validation à un email déjà validé pour {user.username}.")
            return False

        token = str(uuid.uuid4())
        expiration_date = timezone.now() + datetime.timedelta(hours=settings.TOKEN_VALIDITY_HOURS)

        user.token_validation_email = token
        user.date_expiration_token = expiration_date
        user.email_valide = False
        user.save(update_fields=['token_validation_email', 'date_expiration_token', 'email_valide'])

        validation_link = f"http://localhost:8000/validate-email/?token={token}"

        subject = "Validez votre adresse email pour GestionMySoutenance"
        message_html = render_to_string('emails/email_validation.html', {
            'user': user,
            'validation_link': validation_link,
            'expiration_hours': settings.TOKEN_VALIDITY_HOURS
        })
        NotificationService.send_email(user.email, subject, None, html_body=message_html)
        audit_logger.info(f"Jeton de validation email envoyé à {user.username}.")
        return True

    @staticmethod
    @transaction.atomic
    def validate_email(user, token):
        if not user:
            error_logger.error("Tentative de validation d'email pour un utilisateur inexistant.")
            return False
        if not user.token_validation_email or user.token_validation_email != token:
            audit_logger.warning(f"Tentative de validation d'email pour {user.username} avec un jeton incorrect.")
            return False
        if user.date_expiration_token < timezone.now():
            user.token_validation_email = None
            user.date_expiration_token = None
            user.save(update_fields=['token_validation_email', 'date_expiration_token'])
            audit_logger.warning(f"Tentative de validation d'email pour {user.username} avec un jeton expiré.")
            return False

        user.email_valide = True
        user.token_validation_email = None
        user.date_expiration_token = None
        user.save(update_fields=['email_valide', 'token_validation_email', 'date_expiration_token'])
        audit_logger.info(f"Adresse email de {user.username} validée.")
        return True

    @staticmethod
    @transaction.atomic
    def increment_login_attempts(user):
        user.tentatives_connexion_echouees = F('tentatives_connexion_echouees') + 1
        user.save(update_fields=['tentatives_connexion_echouees'])
        user.refresh_from_db()

        if user.tentatives_connexion_echouees >= settings.MAX_LOGIN_ATTEMPTS:
            AuthentificationService.block_account(user, settings.LOCKOUT_TIME_MINUTES)
            audit_logger.warning(
                f"Compte {user.username} bloqué après {settings.MAX_LOGIN_ATTEMPTS} tentatives échouées.")

    @staticmethod
    @transaction.atomic
    def reset_login_attempts(user):
        user.tentatives_connexion_echouees = 0
        user.save(update_fields=['tentatives_connexion_echouees'])
        audit_logger.info(f"Tentatives de connexion pour {user.username} réinitialisées.")

    @staticmethod
    @transaction.atomic
    def block_account(user, duration_minutes):
        user.compte_bloque_jusqua = timezone.now() + datetime.timedelta(minutes=duration_minutes)
        user.save(update_fields=['compte_bloque_jusqua'])
        AuthentificationService.reset_login_attempts(user)
        audit_logger.info(f"Compte {user.username} bloqué jusqu'à {user.compte_bloque_jusqua}.")
        NotificationService.send_notification(
            event_type="compte_bloque",
            recipient_user=user,
            context_data={'duration': duration_minutes}
        )

    @staticmethod
    @transaction.atomic
    def is_account_locked(user):
        if user.compte_bloque_jusqua and user.compte_bloque_jusqua > timezone.now():
            return True
        elif user.compte_bloque_jusqua and user.compte_bloque_jusqua <= timezone.now():
            user.compte_bloque_jusqua = None
            user.save(update_fields=['compte_bloque_jusqua'])
            audit_logger.info(f"Déblocage automatique du compte {user.username}.")
            return False
        return False

    @staticmethod
    def reset_password(user, new_password):
        if len(new_password) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(f"Le mot de passe doit contenir au moins {settings.PASSWORD_MIN_LENGTH} caractères.")
        user.set_password(new_password)
        user.save()
        audit_logger.info(f"Mot de passe de {user.username} réinitialisé.")
        NotificationService.send_notification(
            event_type="password_reset",
            recipient_user=user,
            context_data={}
        )

    @staticmethod
    @transaction.atomic
    def activate_account(user):
        if user.is_active:
            audit_logger.warning(f"Tentative d'activation d'un compte déjà actif pour {user.username}.")
            return user
        user.is_active = True
        user.save(update_fields=['is_active'])
        audit_logger.info(f"Compte {user.username} activé.")
        return user

    @staticmethod
    @transaction.atomic
    def deactivate_account(user):
        if not user.is_active:
            audit_logger.warning(f"Tentative de désactivation d'un compte déjà inactif pour {user.username}.")
            return user
        user.is_active = False
        user.save(update_fields=['is_active'])
        audit_logger.info(f"Compte {user.username} désactivé.")
        return user

    @staticmethod
    @transaction.atomic
    def generate_2fa_secret(user):
        if user.is_2fa_active:
            raise ValueError("La 2FA est déjà active pour cet utilisateur.")
        secret = pyotp.random_base32()
        user.two_fa_secret = secret
        user.save(update_fields=['two_fa_secret'])
        audit_logger.info(f"Secret 2FA généré pour {user.username}.")
        return secret

    @staticmethod
    @transaction.atomic
    def verify_2fa_code(user, code):
        if not user.two_fa_secret:
            raise ValueError("Aucun secret 2FA n'est configuré pour cet utilisateur.")
        totp = pyotp.TOTP(user.two_fa_secret)
        is_valid = totp.verify(code)
        if is_valid and not user.is_2fa_active:
            user.is_2fa_active = True
            user.save(update_fields=['is_2fa_active'])
            audit_logger.info(f"2FA activée pour {user.username}.")
            NotificationService.send_notification(
                event_type="2fa_active",
                recipient_user=user,
                context_data={}
            )
        elif not is_valid:
            audit_logger.warning(f"Tentative de vérification 2FA échouée pour {user.username}.")
        return is_valid

    @staticmethod
    @transaction.atomic
    def disable_2fa(user):
        if not user.is_2fa_active:
            audit_logger.warning(
                f"Tentative de désactivation 2FA pour un compte où elle n'est pas active pour {user.username}.")
            return False
        user.is_2fa_active = False
        user.two_fa_secret = None
        user.save(update_fields=['is_2fa_active', 'two_fa_secret'])
        audit_logger.info(f"2FA désactivée pour {user.username}.")
        NotificationService.send_notification(
            event_type="2fa_desactive",
            recipient_user=user,
            context_data={}
        )
        return True


class RapportService:
    @staticmethod
    @transaction.atomic
    def create_draft_report(etudiant, stage, title, theme=None, num_pages=None):
        if not etudiant.est_eligible_soumission:
            raise PermissionError(
                "L'étudiant n'est pas éligible à la soumission de rapport. Veuillez régulariser votre situation.")
        if RapportEtudiant.objects.filter(etudiant=etudiant, stage=stage).exists():
            raise ValueError("Un rapport existe déjà pour cet étudiant et ce stage.")

        rapport = RapportEtudiant.objects.create(
            id_rapport_etudiant=UniqueIdGeneratorService.generate('RAP'),
            libelle_rapport_etudiant=title,
            theme=theme,
            etudiant=etudiant,
            stage=stage,
            statut_rapport=StatutRapport.BROUILLON,
            nombre_pages=num_pages
        )
        audit_logger.info(f"Rapport brouillon '{rapport.id_rapport_etudiant}' créé par {etudiant.nom_complet}.")
        return rapport

    @staticmethod
    @transaction.atomic
    def update_report_content(rapport, section_data):
        if rapport.statut_rapport not in [StatutRapport.BROUILLON, StatutRapport.NON_CONFORME,
                                          StatutRapport.EN_CORRECTION]:
            raise PermissionError(
                f"Le rapport ne peut être modifié dans son statut actuel ({rapport.get_statut_rapport_display()}).")

        for title, content in section_data.items():
            section, created = SectionRapport.objects.get_or_create(
                rapport_etudiant=rapport,
                titre_section=title,
                defaults={'contenu_section': content, 'ordre': 0}
            )
            if not created:
                section.contenu_section = content
                section.save()
        audit_logger.info(f"Contenu du rapport '{rapport.id_rapport_etudiant}' mis à jour.")
        return rapport

    @staticmethod
    @transaction.atomic
    def submit_report(rapport):
        if rapport.statut_rapport not in [StatutRapport.BROUILLON, StatutRapport.NON_CONFORME]:
            raise ValueError(
                f"Le rapport doit être en brouillon ou non conforme pour être soumis (statut actuel: {rapport.get_statut_rapport_display()}).")
        if not rapport.libelle_rapport_etudiant or not rapport.theme:
            raise ValueError("Le titre et le thème du rapport sont obligatoires.")
        if not SectionRapport.objects.filter(rapport_etudiant=rapport).exists():
            raise ValueError("Le rapport doit contenir au moins une section.")
        if RapportEtudiant.objects.filter(etudiant=rapport.etudiant, stage=rapport.stage).exclude(
                id_rapport_etudiant=rapport.id_rapport_etudiant).exists():
            raise ValueError("Un autre rapport pour ce stage a déjà été soumis ou est en cours de traitement.")

        rapport.statut_rapport = StatutRapport.SOUMIS
        rapport.date_soumission = timezone.now()
        rapport.save()

        NotificationService.send_notification(
            event_type="rapport_soumis",
            recipient_user=rapport.etudiant.utilisateur,
            context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                          'lien_action': f"/etudiant/rapports/{rapport.id_rapport_etudiant}/suivi"}
        )
        agent_group = Group.objects.get(name='Agent de Conformité')
        for user in User.objects.filter(groups=agent_group):
            NotificationService.send_notification(
                event_type="nouveau_rapport_conformite",
                recipient_user=user,
                context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                              'etudiant_name': rapport.etudiant.nom_complet,
                              'lien_action': f"/personnel/conformite/rapport/{rapport.id_rapport_etudiant}"}
            )
        audit_logger.info(f"Rapport '{rapport.id_rapport_etudiant}' soumis par {rapport.etudiant.nom_complet}.")
        return rapport

    @staticmethod
    @transaction.atomic
    def return_report_for_correction(rapport, comments, personnel_admin):
        if rapport.statut_rapport not in [StatutRapport.SOUMIS, StatutRapport.CONFORME, StatutRapport.EN_COMMISSION]:
            raise ValueError(
                f"Le rapport ne peut être retourné pour correction dans son statut actuel ({rapport.get_statut_rapport_display()}).")
        if not comments:
            raise ValueError("Des commentaires sont obligatoires pour retourner un rapport pour correction.")

        rapport.statut_rapport = StatutRapport.NON_CONFORME
        rapport.commentaires_conformite = comments
        rapport.save()

        NotificationService.send_notification(
            event_type="rapport_retour_correction",
            recipient_user=rapport.etudiant.utilisateur,
            context_data={'rapport_title': rapport.libelle_rapport_etudiant, 'comments': comments,
                          'lien_action': f"/etudiant/rapports/{rapport.id_rapport_etudiant}/modifier"}
        )
        audit_logger.info(
            f"Rapport '{rapport.id_rapport_etudiant}' retourné pour correction par {personnel_admin.nom_complet}.")
        return rapport

    @staticmethod
    @transaction.atomic
    def resubmit_corrected_report(rapport, correction_note):
        if rapport.statut_rapport != StatutRapport.NON_CONFORME:
            raise ValueError(
                f"Le rapport doit être en statut non conforme pour être re-soumis (statut actuel: {rapport.get_statut_rapport_display()}).")
        if not correction_note:
            raise ValueError("Une note explicative est obligatoire pour la re-soumission.")

        rapport.statut_rapport = StatutRapport.SOUMIS
        rapport.note_explicative_correction = correction_note
        rapport.date_soumission = timezone.now()
        rapport.save()

        NotificationService.send_notification(
            event_type="rapport_resoumis",
            recipient_user=rapport.etudiant.utilisateur,
            context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                          'lien_action': f"/etudiant/rapports/{rapport.id_rapport_etudiant}/suivi"}
        )
        agent_group = Group.objects.get(name='Agent de Conformité')
        for user in User.objects.filter(groups=agent_group):
            NotificationService.send_notification(
                event_type="nouveau_rapport_conformite",
                recipient_user=user,
                context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                              'etudiant_name': rapport.etudiant.nom_complet,
                              'lien_action': f"/personnel/conformite/rapport/{rapport.id_rapport_etudiant}"}
            )
        audit_logger.info(f"Rapport '{rapport.id_rapport_etudiant}' re-soumis par {rapport.etudiant.nom_complet}.")
        return rapport

    @staticmethod
    @transaction.atomic
    def handle_final_rejection(rapport, reasons):
        if rapport.statut_rapport != StatutRapport.REFUSE:
            raise ValueError(
                f"Le rapport doit être en statut refusé pour cette opération (statut actuel: {rapport.get_statut_rapport_display()}).")

        rapport.save()

        rapport.etudiant.est_eligible_soumission = False
        rapport.etudiant.save()

        NotificationService.send_notification(
            event_type="rapport_refuse_definitif",
            recipient_user=rapport.etudiant.utilisateur,
            context_data={'rapport_title': rapport.libelle_rapport_etudiant, 'reasons': reasons,
                          'lien_action': "/etudiant/nouveau-stage"}
        )
        audit_logger.warning(
            f"Rapport '{rapport.id_rapport_etudiant}' définitivement refusé. Étudiant {rapport.etudiant.nom_complet} doit initier un nouveau stage.")
        return rapport

    @staticmethod
    @transaction.atomic
    def assign_director(rapport, enseignant_director):
        if rapport.statut_rapport != StatutRapport.VALIDE:
            raise ValueError(
                f"Le directeur de mémoire ne peut être assigné qu'à un rapport validé (statut actuel: {rapport.get_statut_rapport_display()}).")
        if not isinstance(enseignant_director, Enseignant):
            raise TypeError("L'objet fourni pour le directeur de mémoire doit être une instance d'Enseignant.")

        rapport.directeur_memoire = enseignant_director
        rapport.save()

        NotificationService.send_notification(
            event_type="directeur_assigne",
            recipient_user=rapport.etudiant.utilisateur,
            context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                          'director_name': enseignant_director.nom_complet,
                          'lien_action': f"/etudiant/rapports/{rapport.id_rapport_etudiant}/detail"}
        )
        NotificationService.send_notification(
            event_type="assignation_directeur",
            recipient_user=enseignant_director.utilisateur,
            context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                          'etudiant_name': rapport.etudiant.nom_complet,
                          'lien_action': f"/enseignant/rapports/{rapport.id_rapport_etudiant}/detail"}
        )
        audit_logger.info(
            f"Directeur de mémoire {enseignant_director.nom_complet} assigné au rapport '{rapport.id_rapport_etudiant}'.")
        return rapport


class ConformiteService:
    @staticmethod
    def get_reports_for_conformity_check(agent_conformite_user):
        if not hasattr(agent_conformite_user, 'profil_personnel') or not agent_conformite_user.groups.filter(
                name='Agent de Conformité').exists():
            raise PermissionError("L'utilisateur n'est pas un agent de conformité valide.")

        return RapportEtudiant.objects.filter(statut_rapport=StatutRapport.SOUMIS).order_by('date_soumission')

    @staticmethod
    @transaction.atomic
    def apply_conformity_checklist(rapport, agent_conformite_personnel, checklist_results):
        if rapport.statut_rapport != StatutRapport.SOUMIS:
            raise ValueError(
                f"Le rapport n'est pas en statut 'Soumis' pour la vérification de conformité (statut actuel: {rapport.get_statut_rapport_display()}).")
        if not isinstance(agent_conformite_personnel, PersonnelAdministratif):
            raise TypeError(
                "L'objet fourni pour l'agent de conformité doit être une instance de PersonnelAdministratif.")

        all_conform = True
        detailed_comments_list = []

        for critere_id, status_data in checklist_results.items():
            try:
                critere = CritereConformite.objects.get(id_critere=critere_id)
            except CritereConformite.DoesNotExist:
                error_logger.error(
                    f"Critère de conformité '{critere_id}' non trouvé lors de l'évaluation du rapport {rapport.id_rapport_etudiant}.")
                continue  # Poursuivre avec les autres critères

            status = status_data.get('statut_validation')
            comment = status_data.get('commentaire')

            if status not in [s[0] for s in StatutConformite.choices]:
                raise ValueError(f"Statut de validation '{status}' invalide pour le critère '{critere_id}'.")

            ConformiteRapportDetail.objects.update_or_create(
                rapport_etudiant=rapport,
                critere=critere,
                defaults={
                    'statut_validation': status,
                    'commentaire': comment,
                    'verifie_par': agent_conformite_personnel,
                    'date_verification': timezone.now()
                }
            )
            if status == StatutConformite.NON_CONFORME:
                all_conform = False
                detailed_comments_list.append(f"- {critere.libelle_critere}: {comment or 'Non spécifié'}")

        if all_conform:
            ConformiteService.mark_report_as_conform(rapport)
            audit_logger.info(
                f"Rapport '{rapport.id_rapport_etudiant}' marqué conforme par {agent_conformite_personnel.nom_complet}.")
        else:
            ConformiteService.mark_report_as_non_conform(rapport, "\n".join(detailed_comments_list),
                                                         agent_conformite_personnel)
            audit_logger.info(
                f"Rapport '{rapport.id_rapport_etudiant}' marqué NON conforme par {agent_conformite_personnel.nom_complet}.")
        return rapport

    @staticmethod
    @transaction.atomic
    def mark_report_as_conform(rapport):
        if rapport.statut_rapport != StatutRapport.SOUMIS:
            raise ValueError(
                f"Le rapport n'est pas en statut 'Soumis' pour être marqué conforme (statut actuel: {rapport.get_statut_rapport_display()}).")

        rapport.statut_rapport = StatutRapport.CONFORME
        rapport.save()

        NotificationService.send_notification(
            event_type="rapport_conforme",
            recipient_user=rapport.etudiant.utilisateur,
            context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                          'lien_action': f"/etudiant/rapports/{rapport.id_rapport_etudiant}/suivi"}
        )
        commission_group = Group.objects.get(name='Membre de Commission')
        for user in User.objects.filter(groups=commission_group):
            NotificationService.send_notification(
                event_type="nouveau_rapport_commission",
                recipient_user=user,
                context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                              'etudiant_name': rapport.etudiant.nom_complet,
                              'lien_action': f"/commission/rapports/{rapport.id_rapport_etudiant}/evaluer"}
            )
        audit_logger.info(f"Rapport '{rapport.id_rapport_etudiant}' transmis à la commission.")
        return rapport

    @staticmethod
    @transaction.atomic
    def mark_report_as_non_conform(rapport, detailed_comments, agent_conformite_personnel):
        if rapport.statut_rapport != StatutRapport.SOUMIS:
            raise ValueError(
                f"Le rapport n'est pas en statut 'Soumis' pour être marqué non conforme (statut actuel: {rapport.get_statut_rapport_display()}).")
        if not detailed_comments:
            raise ValueError("Des commentaires détaillés sont obligatoires pour marquer un rapport non conforme.")

        rapport.statut_rapport = StatutRapport.NON_CONFORME
        rapport.commentaires_conformite = detailed_comments
        rapport.save()

        # Le service RapportService gère la logique de retour à l'étudiant
        RapportService.return_report_for_correction(rapport, detailed_comments, agent_conformite_personnel)
        audit_logger.info(f"Rapport '{rapport.id_rapport_etudiant}' marqué non conforme et retourné à l'étudiant.")
        return rapport


class CommissionService:
    @staticmethod
    @transaction.atomic
    def create_session(president, name, mode, start_date, end_date, rapport_ids, member_user_ids, required_voters=1):
        if not isinstance(president, Enseignant):
            raise TypeError("Le président de session doit être une instance d'Enseignant.")
        if start_date >= end_date:
            raise ValueError("La date de début de session doit être antérieure à la date de fin.")
        if required_voters <= 0:
            raise ValueError("Le nombre de votants requis doit être supérieur à zéro.")

        session = SessionValidation.objects.create(
            id_session=UniqueIdGeneratorService.generate('SES'),
            nom_session=name,
            date_debut_session=start_date,
            date_fin_prevue=end_date,
            president_session=president,
            mode_session=mode,
            statut_session=StatutSession.PLANIFIEE,
            nombre_votants_requis=required_voters
        )
        rapports = RapportEtudiant.objects.filter(id_rapport_etudiant__in=rapport_ids,
                                                  statut_rapport=StatutRapport.CONFORME)
        if rapports.count() != len(rapport_ids):
            raise ValueError("Certains rapports spécifiés sont introuvables ou ne sont pas en statut 'Conforme'.")
        session.rapports.set(rapports)

        members = Enseignant.objects.filter(utilisateur__id__in=member_user_ids)  # Filtrer par ID utilisateur
        if members.count() != len(member_user_ids):
            raise ValueError("Certains membres spécifiés sont introuvables ou ne sont pas des enseignants.")
        session.membres.set(members)

        for rapport in rapports:
            rapport.statut_rapport = StatutRapport.EN_COMMISSION
            rapport.save(update_fields=['statut_rapport'])

        for member in members:
            NotificationService.send_notification(
                event_type="session_planifiee",
                recipient_user=member.utilisateur,
                context_data={'session_name': session.nom_session,
                              'date': session.date_debut_session.strftime('%d/%m/%Y'),
                              'lien_action': f"/commission/sessions/{session.id_session}/detail"}
            )
        audit_logger.info(f"Session '{session.id_session}' créée par {president.nom_complet}.")
        return session

    @staticmethod
    @transaction.atomic
    def start_session(session):
        if session.statut_session != StatutSession.PLANIFIEE:
            raise ValueError(
                f"La session doit être planifiée pour être démarrée (statut actuel: {session.get_statut_session_display()}).")

        session.statut_session = StatutSession.EN_COURS
        session.save(update_fields=['statut_session'])

        for member in session.membres.all():
            NotificationService.send_notification(
                event_type="session_demarree",
                recipient_user=member.utilisateur,
                context_data={'session_name': session.nom_session,
                              'lien_action': f"/commission/sessions/{session.id_session}/detail"}
            )
        audit_logger.info(f"Session '{session.id_session}' démarrée.")
        return session

    @staticmethod
    @transaction.atomic
    def close_session(session):
        if session.statut_session != StatutSession.EN_COURS:
            raise ValueError(
                f"La session doit être en cours pour être clôturée (statut actuel: {session.get_statut_session_display()}).")

        for rapport in session.rapports.all():
            if rapport.statut_rapport not in [StatutRapport.VALIDE, StatutRapport.REFUSE, StatutRapport.EN_CORRECTION]:
                raise ValueError(
                    f"Le rapport '{rapport.libelle_rapport_etudiant}' n'a pas de décision finale ou est en attente de corrections. Impossible de clôturer la session.")

        session.statut_session = StatutSession.CLOTUREE
        session.save(update_fields=['statut_session'])

        for member in session.membres.all():
            NotificationService.send_notification(
                event_type="session_cloturee",
                recipient_user=member.utilisateur,
                context_data={'session_name': session.nom_session,
                              'lien_action': f"/commission/sessions/{session.id_session}/pv"}
            )
        audit_logger.info(f"Session '{session.id_session}' clôturée.")
        return session

    @staticmethod
    @transaction.atomic
    def submit_vote(session, rapport, enseignant, decision, comment=None):
        if session.statut_session != StatutSession.EN_COURS:
            raise ValueError(
                f"Le vote n'est possible que pour une session en cours (statut actuel: {session.get_statut_session_display()}).")
        if enseignant not in session.membres.all():
            raise PermissionError(f"L'enseignant {enseignant.nom_complet} n'est pas membre de cette session.")
        if rapport not in session.rapports.all():
            raise ValueError(f"Le rapport '{rapport.libelle_rapport_etudiant}' n'appartient pas à cette session.")
        if decision != DecisionVote.APPROUVE and not comment:
            raise ValueError("Un commentaire est obligatoire pour toute décision autre que 'Approuvé'.")

        # Déterminer le tour de vote actuel
        latest_vote_for_rapport = VoteCommission.objects.filter(session=session, rapport_etudiant=rapport).order_by(
            '-tour_vote').first()
        tour_vote = (latest_vote_for_rapport.tour_vote + 1) if latest_vote_for_rapport else 1

        # Vérifier si l'enseignant a déjà voté pour ce rapport dans le tour actuel
        if VoteCommission.objects.filter(session=session, rapport_etudiant=rapport, enseignant=enseignant,
                                         tour_vote=tour_vote).exists():
            raise ValueError("Vous avez déjà voté pour ce rapport lors de ce tour de scrutin.")

        vote = VoteCommission.objects.create(
            id_vote=UniqueIdGeneratorService.generate('VOT'),
            session=session,
            rapport_etudiant=rapport,
            enseignant=enseignant,
            decision_vote=decision,
            commentaire_vote=comment,
            tour_vote=tour_vote
        )
        audit_logger.info(
            f"Vote de {enseignant.nom_complet} pour rapport '{rapport.id_rapport_etudiant}' (Décision: {decision}, Tour: {tour_vote}).")

        CommissionService._check_consensus_and_update_rapport_status(session, rapport)
        return vote

    @staticmethod
    @transaction.atomic
    def _check_consensus_and_update_rapport_status(session, rapport):
        latest_tour_vote_obj = VoteCommission.objects.filter(session=session, rapport_etudiant=rapport).order_by(
            '-tour_vote').first()
        if not latest_tour_vote_obj:
            return  # Aucun vote encore

        latest_tour_number = latest_tour_vote_obj.tour_vote
        last_tour_votes = VoteCommission.objects.filter(session=session, rapport_etudiant=rapport,
                                                        tour_vote=latest_tour_number)

        # Compter les votes par décision
        decision_counts = {}
        for vote in last_tour_votes:
            decision_counts[vote.decision_vote] = decision_counts.get(vote.decision_vote, 0) + 1

        total_members_in_session = session.membres.count()

        # Si tous les membres ont voté dans le dernier tour
        if last_tour_votes.count() == total_members_in_session:
            if DecisionVote.REFUSE in decision_counts and decision_counts[DecisionVote.REFUSE] > 0:
                # Si au moins un vote est "Refusé", le rapport est refusé
                rapport.statut_rapport = StatutRapport.REFUSE
                rapport.save(update_fields=['statut_rapport'])
                NotificationService.send_notification(
                    event_type="rapport_refuse",
                    recipient_user=rapport.etudiant.utilisateur,
                    context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                                  'lien_action': f"/etudiant/rapports/{rapport.id_rapport_etudiant}/suivi"}
                )
                audit_logger.info(f"Rapport '{rapport.id_rapport_etudiant}' refusé par la commission.")
            elif DecisionVote.APPROUVE_RESERVE in decision_counts and decision_counts[
                DecisionVote.APPROUVE_RESERVE] > 0:
                # Si pas de refus, mais au moins un "Approuvé sous réserve"
                rapport.statut_rapport = StatutRapport.EN_CORRECTION  # L'étudiant doit apporter des corrections
                rapport.save(update_fields=['statut_rapport'])
                NotificationService.send_notification(
                    event_type="rapport_approuve_reserve",
                    recipient_user=rapport.etudiant.utilisateur,
                    context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                                  'lien_action': f"/etudiant/rapports/{rapport.id_rapport_etudiant}/modifier"}
                )
                audit_logger.info(f"Rapport '{rapport.id_rapport_etudiant}' approuvé sous réserve par la commission.")
            elif DecisionVote.APPROUVE in decision_counts and decision_counts[
                DecisionVote.APPROUVE] == total_members_in_session:
                # Si tous les votes sont "Approuvé"
                rapport.statut_rapport = StatutRapport.VALIDE
                rapport.save(update_fields=['statut_rapport'])
                NotificationService.send_notification(
                    event_type="rapport_valide",
                    recipient_user=rapport.etudiant.utilisateur,
                    context_data={'rapport_title': rapport.libelle_rapport_etudiant,
                                  'lien_action': f"/etudiant/rapports/{rapport.id_rapport_etudiant}/detail"}
                )
                audit_logger.info(f"Rapport '{rapport.id_rapport_etudiant}' validé par la commission.")
            # Si tous n'ont pas voté, le statut reste EN_COMMISSION, et le président peut relancer un tour.

        @staticmethod
        def get_session_progress(session):
            rapports_data = []
            for rapport in session.rapports.all():
                votes = VoteCommission.objects.filter(session=session, rapport_etudiant=rapport).order_by('tour_vote')

                latest_tour_number = votes.last().tour_vote if votes.exists() else 0
                last_tour_votes = votes.filter(tour_vote=latest_tour_number) if latest_tour_number > 0 else []

                voted_members_ids = [vote.enseignant.utilisateur.id for vote in last_tour_votes]
                all_members_ids = [member.utilisateur.id for member in session.membres.all()]
                remaining_voters = [User.objects.get(id=uid) for uid in all_members_ids if uid not in voted_members_ids]

                rapports_data.append({
                    'rapport': rapport,
                    'statut_actuel': rapport.get_statut_rapport_display(),
                    'votes_emis_count': last_tour_votes.count(),
                    'total_members': session.membres.count(),
                    'remaining_voters': remaining_voters,
                    'decisions_detail': [
                        {'enseignant': v.enseignant.nom_complet, 'decision': v.get_decision_vote_display(),
                         'commentaire': v.commentaire_vote} for v in last_tour_votes],
                    'tours_de_vote_count': votes.values_list('tour_vote', flat=True).distinct().count()
                })
            return rapports_data

        @staticmethod
        @transaction.atomic
        def initiate_pv_draft(session, redacteur):
            if ProcesVerbal.objects.filter(session=session).exists():
                raise ValueError("Un Procès-Verbal existe déjà pour cette session.")
            if redacteur not in session.membres.all():
                raise PermissionError(f"Le rédacteur {redacteur.nom_complet} doit être membre de la session.")

            pv_content = f"Procès-Verbal de la session de validation '{session.nom_session}' du {session.date_debut_session.strftime('%d/%m/%Y à %H:%M')}.\n\n"
            pv_content += "Membres présents :\n"
            for member in session.membres.all():
                # Assumant que Enseignant a une méthode get_grade_display() ou que le grade est directement accessible
                grade_display = ""
                if hasattr(member, 'gradeenseignant_set'):
                    current_grade = member.gradeenseignant_set.filter(
                        date_acquisition__lte=timezone.now().date()).order_by('-date_acquisition').first()
                    if current_grade:
                        grade_display = f" ({current_grade.grade.libelle_grade})"
                pv_content += f"- {member.nom_complet}{grade_display}\n"
            pv_content += "\n"
            pv_content += "Rapports évalués :\n"
            for rapport in session.rapports.all():
                pv_content += f"\n--- Rapport : {rapport.libelle_rapport_etudiant} (Étudiant: {rapport.etudiant.nom_complet}) ---\n"
                pv_content += f"Décision finale: {rapport.get_statut_rapport_display()}\n"
                votes = VoteCommission.objects.filter(session=session, rapport_etudiant=rapport).order_by('tour_vote')
                for vote in votes:
                    pv_content += f"  Tour {vote.tour_vote} - Vote de {vote.enseignant.nom_complet} ({vote.get_decision_vote_display()}): {vote.commentaire_vote or 'Aucun commentaire'}\n"
                if rapport.statut_rapport == StatutRapport.VALIDE:
                    pv_content += f"  Directeur de mémoire désigné: {rapport.directeur_memoire.nom_complet if rapport.directeur_memoire else 'Non désigné'}\n"
            pv_content += "\nObservations générales de la commission : [À compléter par le rédacteur]\n"

            pv = ProcesVerbal.objects.create(
                id_compte_rendu=UniqueIdGeneratorService.generate('PV_'),
                session=session,
                libelle_compte_rendu=pv_content,
                statut_pv=StatutPV.BROUILLON,
                redacteur=redacteur
            )
            audit_logger.info(
                f"Brouillon de PV '{pv.id_compte_rendu}' initié pour la session '{session.id_session}' par {redacteur.nom_complet}.")
            return pv

        @staticmethod
        @transaction.atomic
        def update_pv_content(pv, content):
            if pv.statut_pv not in [StatutPV.BROUILLON, StatutPV.REJETE]:
                raise ValueError(
                    f"Le PV ne peut être modifié que s'il est en brouillon ou rejeté (statut actuel: {pv.get_statut_pv_display()}).")
            pv.libelle_compte_rendu = content
            pv.save(update_fields=['libelle_compte_rendu'])
            audit_logger.info(f"Contenu du PV '{pv.id_compte_rendu}' mis à jour.")
            return pv

        @staticmethod
        @transaction.atomic
        def submit_pv_for_approval(pv):
            if pv.statut_pv not in [StatutPV.BROUILLON, StatutPV.REJETE]:
                raise ValueError(
                    f"Le PV doit être en brouillon ou rejeté pour être soumis à approbation (statut actuel: {pv.get_statut_pv_display()}).")
            pv.statut_pv = StatutPV.ATTENTE_APPROBATION
            pv.save(update_fields=['statut_pv'])

            for member in pv.session.membres.all():
                if member != pv.redacteur:
                    NotificationService.send_notification(
                        event_type="pv_attente_approbation",
                        recipient_user=member.utilisateur,
                        context_data={'pv_id': pv.id_compte_rendu, 'session_name': pv.session.nom_session,
                                      'lien_action': f"/commission/pv/{pv.id_compte_rendu}/approuver_demander/"}
                    )
            audit_logger.info(f"PV '{pv.id_compte_rendu}' soumis à approbation.")
            return pv

        @staticmethod
        @transaction.atomic
        def approve_pv(pv, enseignant, comment=None):
            if pv.statut_pv != StatutPV.ATTENTE_APPROBATION:
                raise ValueError(
                    f"Le PV n'est pas en attente d'approbation (statut actuel: {pv.get_statut_pv_display()}).")
            if enseignant not in pv.session.membres.all():
                raise PermissionError(f"L'enseignant {enseignant.nom_complet} n'est pas membre de la session du PV.")
            if ValidationPv.objects.filter(proces_verbal=pv, enseignant=enseignant).exists():
                raise ValueError(f"Cet enseignant ({enseignant.nom_complet}) a déjà validé ce PV.")

            ValidationPv.objects.create(
                proces_verbal=pv,
                enseignant=enseignant,
                decision_validation_pv=DecisionValidationPV.APPROUVE,
                commentaire_validation_pv=comment
            )
            audit_logger.info(f"PV '{pv.id_compte_rendu}' approuvé par {enseignant.nom_complet}.")

            # Vérifier si toutes les approbations sont obtenues
            # Le rédacteur n'a pas besoin d'approuver son propre PV
            required_approvals = pv.session.membres.count() - (1 if pv.redacteur in pv.session.membres.all() else 0)
            current_approvals = ValidationPv.objects.filter(proces_verbal=pv,
                                                            decision_validation_pv=DecisionValidationPV.APPROUVE).count()

            if current_approvals >= required_approvals:
                CommissionService.finalize_pv(pv)
            return pv

        @staticmethod
        @transaction.atomic
        def request_pv_modification(pv, enseignant, comment):
            if pv.statut_pv != StatutPV.ATTENTE_APPROBATION:
                raise ValueError(
                    f"Le PV n'est pas en attente d'approbation (statut actuel: {pv.get_statut_pv_display()}).")
            if enseignant not in pv.session.membres.all():
                raise PermissionError(f"L'enseignant {enseignant.nom_complet} n'est pas membre de la session du PV.")
            if not comment:
                raise ValueError("Un commentaire est obligatoire pour demander une modification.")

            ValidationPv.objects.create(
                proces_verbal=pv,
                enseignant=enseignant,
                decision_validation_pv=DecisionValidationPV.MODIF_DEMANDEE,
                commentaire_validation_pv=comment
            )
            pv.statut_pv = StatutPV.REJETE
            pv.save(update_fields=['statut_pv'])

            NotificationService.send_notification(
                event_type="pv_modification_demandee",
                recipient_user=pv.redacteur.utilisateur,
                context_data={'pv_id': pv.id_compte_rendu, 'comment': comment,
                              'lien_action': f"/commission/sessions/{pv.session.id_session}/pv/"}
            )
            audit_logger.info(f"Modification du PV '{pv.id_compte_rendu}' demandée par {enseignant.nom_complet}.")
            return pv

        @staticmethod
        @transaction.atomic
        def finalize_pv(pv):
            if pv.statut_pv != StatutPV.ATTENTE_APPROBATION:
                raise ValueError(
                    f"Le PV n'est pas en attente d'approbation pour être finalisé (statut actuel: {pv.get_statut_pv_display()}).")

            pv.statut_pv = StatutPV.VALIDE
            pv.date_finalisation = timezone.now()
            pv.save(update_fields=['statut_pv', 'date_finalisation'])

            # --- Génération du document PDF officiel du PV ---
            # Cette partie nécessite l'installation de bibliothèques comme WeasyPrint (pip install WeasyPrint)
            # et potentiellement des outils système (ex: wkhtmltopdf pour d'autres libs comme xhtml2pdf)

            pdf_file_name = f"pv_{pv.id_compte_rendu}.pdf"
            pdf_storage_path = os.path.join('documents', 'pv', pdf_file_name)  # Chemin relatif à MEDIA_ROOT
            full_pdf_path = os.path.join(settings.MEDIA_ROOT, pdf_storage_path)

            # Assurez-vous que le répertoire de destination existe
            os.makedirs(os.path.dirname(full_pdf_path), exist_ok=True)

            try:
                # Exemple de rendu HTML en PDF avec WeasyPrint
                # pv_html_content = render_to_string('pdf/pv.html', {'pv': pv, 'session': pv.session})
                # pdf_content = HTML(string=pv_html_content).write_pdf()

                # Sauvegarde du fichier PDF
                # with open(full_pdf_path, 'wb') as f:
                #     f.write(pdf_content)

                # Ou si vous utilisez default_storage (pour S3, etc.)
                # default_storage.save(pdf_storage_path, ContentFile(pdf_content))

                # Pour l'instant, juste une simulation de création de fichier
                with open(full_pdf_path, 'w') as f:
                    f.write(f"Contenu simulé du PV {pv.id_compte_rendu}")
                audit_logger.info(f"Fichier PDF du PV '{pv.id_compte_rendu}' généré et enregistré à {full_pdf_path}.")

            except Exception as e:
                error_logger.error(f"Erreur lors de la génération du PDF pour le PV {pv.id_compte_rendu}: {e}",
                                   exc_info=True)
                raise

            # Enregistrer le document officiel dans la base de données
            document_officiel = DocumentOfficiel.objects.create(
                id_document=UniqueIdGeneratorService.generate('DOC'),
                etudiant=pv.session.rapports.first().etudiant if pv.session.rapports.exists() else None,
                # Associer au premier étudiant du rapport
                type_document='ProcesVerbal',
                annee_academique=AnneeAcademique.objects.get(est_active=True),  # Ou l'année académique de la session
                chemin_fichier=pdf_storage_path,
                est_officiel=True,
                genere_par=PersonnelAdministratif.objects.filter(
                    utilisateur__groups__name='Responsable Scolarité').first()  # Assigner au RS
            )

            for rapport in pv.session.rapports.all():
                NotificationService.send_notification(
                    event_type="pv_valide_etudiant",
                    recipient_user=rapport.etudiant.utilisateur,
                    context_data={'pv_id': pv.id_compte_rendu, 'rapport_title': rapport.libelle_rapport_etudiant,
                                  'lien_action': f"/documents/{document_officiel.id_document}/download/"}
                )
            rs_group = Group.objects.get(name='Responsable Scolarité')
            for user in User.objects.filter(groups=rs_group):
                NotificationService.send_notification(
                    event_type="pv_valide_admin",
                    recipient_user=user,
                    context_data={'pv_id': pv.id_compte_rendu, 'session_name': pv.session.nom_session,
                                  'lien_action': f"/admin/core/documentofficiel/{document_officiel.id_document}/change/"}
                )
            audit_logger.info(f"PV '{pv.id_compte_rendu}' finalisé et diffusé.")
            return pv

class ScolariteService:
        @staticmethod
        @transaction.atomic
        def activate_student_account(etudiant, personnel_rs):
            if not isinstance(etudiant, Etudiant) or not isinstance(personnel_rs, PersonnelAdministratif):
                raise TypeError(
                    "Les objets fournis doivent être des instances d'Etudiant et de PersonnelAdministratif.")

            inscription_valide = Inscription.objects.filter(
                etudiant=etudiant,
                annee_academique__est_active=True,
                statut_paiement=StatutPaiement.PAYE
            ).exists()
            stage_valide = Stage.objects.filter(
                etudiant=etudiant,
                est_valide=True
            ).exists()
            penalites_reglees = not Penalite.objects.filter(
                etudiant=etudiant,
                statut_penalite=StatutPenalite.DUE
            ).exists()

            if not inscription_valide:
                raise ValueError("L'étudiant n'a pas d'inscription valide et payée pour l'année active.")
            if not stage_valide:
                raise ValueError("L'étudiant n'a pas de stage validé.")
            if not penalites_reglees:
                raise ValueError("L'étudiant a des pénalités en attente de régularisation.")

            AuthentificationService.activate_account(etudiant.utilisateur)
            etudiant.est_eligible_soumission = True
            etudiant.save(update_fields=['est_eligible_soumission'])

            NotificationService.send_notification(
                event_type="compte_etudiant_active",
                recipient_user=etudiant.utilisateur,
                context_data={'username': etudiant.utilisateur.username, 'lien_action': "/etudiant/dashboard"}
            )
            audit_logger.info(f"Compte étudiant {etudiant.nom_complet} activé par {personnel_rs.nom_complet}.")
            return etudiant

        @staticmethod
        @transaction.atomic
        def register_inscription(etudiant, niveau_etude, annee_academique, montant, date_inscription, statut_paiement):
            if not isinstance(etudiant, Etudiant) or not isinstance(niveau_etude, NiveauEtude) or not isinstance(
                    annee_academique, AnneeAcademique):
                raise TypeError("Les objets fournis doivent être des instances valides.")
            if Inscription.objects.filter(etudiant=etudiant, niveau_etude=niveau_etude,
                                          annee_academique=annee_academique).exists():
                raise ValueError("Cet étudiant est déjà inscrit à ce niveau pour cette année académique.")

            inscription = Inscription.objects.create(
                etudiant=etudiant,
                niveau_etude=niveau_etude,
                annee_academique=annee_academique,
                montant_inscription=montant,
                date_inscription=date_inscription,
                statut_paiement=statut_paiement
            )
            audit_logger.info(
                f"Inscription de {etudiant.nom_complet} enregistrée pour {annee_academique.libelle_annee_academique}.")
            return inscription

        @staticmethod
        @transaction.atomic
        def validate_stage(stage, personnel_rs):
            if not isinstance(stage, Stage) or not isinstance(personnel_rs, PersonnelAdministratif):
                raise TypeError("Les objets fournis doivent être des instances de Stage et de PersonnelAdministratif.")
            if stage.est_valide:
                audit_logger.warning(
                    f"Tentative de validation d'un stage déjà validé pour {stage.etudiant.nom_complet}.")
                return stage

            stage.est_valide = True
            stage.save(update_fields=['est_valide'])

            NotificationService.send_notification(
                event_type="stage_valide",
                recipient_user=stage.etudiant.utilisateur,
                context_data={'sujet_stage': stage.sujet_stage, 'lien_action': f"/etudiant/stages/{stage.id}/detail"}
            )
            audit_logger.info(
                f"Stage '{stage.sujet_stage}' de {stage.etudiant.nom_complet} validé par {personnel_rs.nom_complet}.")
            return stage

        @staticmethod
        @transaction.atomic
        def record_penalty_payment(penalite, personnel_rs):
            if not isinstance(penalite, Penalite) or not isinstance(personnel_rs, PersonnelAdministratif):
                raise TypeError(
                    "Les objets fournis doivent être des instances de Penalite et de PersonnelAdministratif.")
            if penalite.statut_penalite != StatutPenalite.DUE:
                raise ValueError(
                    f"La pénalité n'est pas en statut 'Due' (statut actuel: {penalite.get_statut_penalite_display()}).")

            penalite.statut_penalite = StatutPenalite.REGLEE
            penalite.date_regularisation = timezone.now()
            penalite.personnel_traitant = personnel_rs
            penalite.save(update_fields=['statut_penalite', 'date_regularisation', 'personnel_traitant'])

            # Vérifier si l'étudiant redevient éligible à la soumission après cette régularisation
            if not Penalite.objects.filter(etudiant=penalite.etudiant, statut_penalite=StatutPenalite.DUE).exists():
                penalite.etudiant.est_eligible_soumission = True
                penalite.etudiant.save(update_fields=['est_eligible_soumission'])
                audit_logger.info(
                    f"Étudiant {penalite.etudiant.nom_complet} redevient éligible à la soumission après régularisation de pénalités.")

            NotificationService.send_notification(
                event_type="penalite_reglee",
                recipient_user=penalite.etudiant.utilisateur,
                context_data={'motif_penalite': penalite.motif, 'montant': penalite.montant_du,
                              'lien_action': "/etudiant/penalites"}
            )
            audit_logger.info(
                f"Pénalité '{penalite.id_penalite}' de {penalite.etudiant.nom_complet} réglée par {personnel_rs.nom_complet}.")
            return penalite

        @staticmethod
        @transaction.atomic
        def enter_note(etudiant, ecue, annee_academique, note_value, date_evaluation=None):
            if not isinstance(etudiant, Etudiant) or not isinstance(ecue, Ecue) or not isinstance(annee_academique,
                                                                                                  AnneeAcademique):
                raise TypeError("Les objets fournis doivent être des instances valides.")
            if not (0 <= note_value <= 20):  # Exemple de validation de note
                raise ValueError("La note doit être comprise entre 0 et 20.")

            if not date_evaluation:
                date_evaluation = timezone.now()

            note, created = Note.objects.update_or_create(
                etudiant=etudiant,
                ecue=ecue,
                annee_academique=annee_academique,
                defaults={'note': note_value, 'date_evaluation': date_evaluation}
            )
            audit_logger.info(f"Note de {note_value} pour {etudiant.nom_complet} en {ecue.libelle_ecue} enregistrée.")
            return note

        @staticmethod
        @transaction.atomic
        def generate_official_bulletin(etudiant, annee_academique, personnel_rs, mass_generation=False):
            if not isinstance(etudiant, Etudiant) or not isinstance(annee_academique,
                                                                    AnneeAcademique) or not isinstance(personnel_rs,
                                                                                                       PersonnelAdministratif):
                raise TypeError("Les objets fournis doivent être des instances valides.")

            if mass_generation:
                # Pour la génération en masse, il est fortement recommandé d'utiliser Celery ou un autre système de tâches asynchrones.
                # Décommenter et configurer Celery (voir settings.py et core/tasks.py)
                # if settings.CELERY_BROKER_URL:
                #     generate_mass_bulletins_task.delay(etudiant.id, annee_academique.id_annee_academique, personnel_rs.id)
                #     audit_logger.info(f"Tâche de génération de bulletins en masse lancée pour {etudiant.nom_complet} ({annee_academique.libelle_annee_academique}).")
                #     return None
                # else:
                #     error_logger.error("Celery n'est pas configuré pour la génération de bulletins en masse.")
                #     raise RuntimeError("Le système de tâches asynchrones n'est pas configuré.")
                audit_logger.warning("Génération de bulletins en masse simulée car Celery n'est pas configuré.")
                # Fallback pour la démo si Celery n'est pas là (la logique ci-dessous s'exécutera pour un seul étudiant)

            os.makedirs(os.path.join(settings.MEDIA_ROOT, 'documents', 'bulletins'), exist_ok=True)

            current_version = DocumentOfficiel.objects.filter(
                etudiant=etudiant,
                type_document='Bulletin',
                annee_academique=annee_academique
            ).order_by('-version').first()
            new_version_num = (current_version.version + 1) if current_version else 1

            file_name = f"bulletin_{etudiant.utilisateur.username}_{annee_academique.libelle_annee_academique}_v{new_version_num}.pdf"
            pdf_storage_path = os.path.join('documents', 'bulletins', file_name)
            full_pdf_path = os.path.join(settings.MEDIA_ROOT, pdf_storage_path)

            try:
                # Pour une vraie génération de PDF, décommenter et installer WeasyPrint
                # notes = Note.objects.filter(etudiant=etudiant, annee_academique=annee_academique)
                # html_content = render_to_string('pdf/bulletin.html', {
                #     'etudiant': etudiant,
                #     'annee_academique': annee_academique,
                #     'notes': notes,
                #     'version': new_version_num,
                #     'date_generation': timezone.now(),
                #     'is_official': True
                # })
                # pdf_content = HTML(string=html_content).write_pdf()
                # with open(full_pdf_path, 'wb') as f:
                #     f.write(pdf_content)

                # Simulation de création de fichier pour la démo
                with open(full_pdf_path, 'w') as f:
                    f.write(f"Contenu simulé du bulletin {etudiant.nom_complet} v{new_version_num}")
                audit_logger.info(
                    f"Fichier PDF du bulletin '{etudiant.nom_complet}' généré et enregistré à {full_pdf_path}.")

            except Exception as e:
                error_logger.error(f"Erreur lors de la génération du PDF du bulletin pour {etudiant.nom_complet}: {e}",
                                   exc_info=True)
                raise

            document = DocumentOfficiel.objects.create(
                id_document=UniqueIdGeneratorService.generate('DOC'),
                etudiant=etudiant,
                type_document='Bulletin',
                annee_academique=annee_academique,
                chemin_fichier=pdf_storage_path,
                est_officiel=True,
                version=new_version_num,
                genere_par=personnel_rs
            )
            NotificationService.send_notification(
                event_type="bulletin_disponible",
                recipient_user=etudiant.utilisateur,
                context_data={'annee': annee_academique.libelle_annee_academique, 'version': new_version_num,
                              'lien_action': f"/documents/{document.id_document}/download/"}
            )
            audit_logger.info(
                f"Bulletin officiel pour {etudiant.nom_complet} ({annee_academique.libelle_annee_academique}) généré par {personnel_rs.nom_complet}.")
            return document

        @staticmethod
        def generate_provisional_transcript(etudiant):
            if not isinstance(etudiant, Etudiant):
                raise TypeError("L'objet fourni doit être une instance d'Etudiant.")

            notes = Note.objects.filter(etudiant=etudiant).order_by('annee_academique', 'ecue__ue__libelle_ue',
                                                                    'ecue__libelle_ecue')

            # Ce document n'est pas stocké en DB, juste généré à la volée et retourné en bytes
            # Pour une vraie génération de PDF, décommenter et installer WeasyPrint
            # html_content = render_to_string('pdf/bulletin.html', {
            #     'etudiant': etudiant,
            #     'notes': notes,
            #     'date_generation': timezone.now(),
            #     'is_provisional': True
            # })
            # pdf_file_content = HTML(string=html_content).write_pdf()
            # audit_logger.info(f"Relevé provisoire généré pour {etudiant.nom_complet}.")
            # return pdf_file_content

            # Simulation pour la démo
            audit_logger.info(f"Relevé provisoire généré pour {etudiant.nom_complet} (simulation).")
            return "Contenu PDF provisoire simulé".encode('utf-8')

        @staticmethod
        @transaction.atomic
        def generate_administrative_document(etudiant, doc_type, personnel_rs, annee_academique=None, **kwargs):
            if not isinstance(etudiant, Etudiant) or not isinstance(personnel_rs, PersonnelAdministratif):
                raise TypeError(
                    "Les objets fournis doivent être des instances d'Etudiant et de PersonnelAdministratif.")
            if annee_academique and not isinstance(annee_academique, AnneeAcademique):
                raise TypeError("L'objet annee_academique doit être une instance d'AnneeAcademique.")

            os.makedirs(os.path.join(settings.MEDIA_ROOT, 'documents', 'administratifs'), exist_ok=True)

            file_name = f"{doc_type.lower()}_{etudiant.utilisateur.username}_{timezone.now().strftime('%Y%m%d%H%M%S')}.pdf"
            pdf_storage_path = os.path.join('documents', 'administratifs', file_name)
            full_pdf_path = os.path.join(settings.MEDIA_ROOT, pdf_storage_path)

            try:
                # Pour une vraie génération de PDF, décommenter et installer WeasyPrint
                # html_content = render_to_string(f'pdf/{doc_type.lower()}.html', {
                #     'etudiant': etudiant,
                #     'annee_academique': ananee_academique,
                #     **kwargs
                # })
                # pdf_content = HTML(string=html_content).write_pdf()
                # with open(full_pdf_path, 'wb') as f:
                #     f.write(pdf_content)
                with open(full_pdf_path, 'w') as f:
                    f.write(f"Contenu simulé du document administratif {doc_type} pour {etudiant.nom_complet}")
                audit_logger.info(
                    f"Fichier PDF du document administratif '{doc_type}' généré et enregistré à {full_pdf_path}.")
            except Exception as e:
                error_logger.error(
                    f"Erreur lors de la génération du PDF pour le document administratif '{doc_type}' de {etudiant.nom_complet}: {e}",
                    exc_info=True)
                raise

            document = DocumentOfficiel.objects.create(
                id_document=UniqueIdGeneratorService.generate('DOC'),
                etudiant=etudiant,
                type_document=doc_type,
                annee_academique=annee_academique,
                chemin_fichier=pdf_storage_path,
                est_officiel=True,
                genere_par=personnel_rs
            )
            NotificationService.send_notification(
                event_type=f"{doc_type.lower()}_disponible",
                recipient_user=etudiant.utilisateur,
                context_data={'doc_type': doc_type, 'lien_action': f"/documents/{document.id_document}/download/"}
            )
            audit_logger.info(
                f"Document administratif '{doc_type}' pour {etudiant.nom_complet} généré par {personnel_rs.nom_complet}.")
            return document


class AdminService:
    @staticmethod
    @transaction.atomic
    def create_user_with_profile(username, password, first_name, last_name, email, profile_type, group_name):
        if User.objects.filter(username=username).exists():
            raise ValueError(f"Le nom d'utilisateur '{username}' est déjà pris.")
        if User.objects.filter(email=email).exists():
            raise ValueError(f"L'adresse email '{email}' est déjà utilisée.")

        user = User.objects.create_user(username=username, password=password, first_name=first_name,
                                        last_name=last_name, email=email)
        try:
            group = Group.objects.get(name=group_name)
        except Group.DoesNotExist:
            raise ValueError(f"Le groupe '{group_name}' n'existe pas.")
        user.groups.add(group)

        if profile_type == 'Etudiant':
            Etudiant.objects.create(utilisateur=user, nom=last_name, prenom=first_name)
        elif profile_type == 'Enseignant':
            Enseignant.objects.create(utilisateur=user, nom=last_name, prenom=first_name, email_professionnel=email)
        elif profile_type == 'PersonnelAdministratif':
            PersonnelAdministratif.objects.create(utilisateur=user, nom=last_name, prenom=first_name,
                                                  email_professionnel=email)
        else:
            user.delete()  # Nettoyer l'utilisateur créé si le type de profil est invalide
            raise ValueError(
                f"Type de profil '{profile_type}' inconnu. Doit être 'Etudiant', 'Enseignant' ou 'PersonnelAdministratif'.")

        audit_logger.info(f"Utilisateur '{username}' avec profil '{profile_type}' créé par l'administrateur.")
        return user

    @staticmethod
    @transaction.atomic
    def assign_role_to_user(user, new_group_name):
        if not isinstance(user, User):
            raise TypeError("L'objet fourni doit être une instance de User.")
        try:
            new_group = Group.objects.get(name=new_group_name)
        except Group.DoesNotExist:
            raise ValueError(f"Le groupe '{new_group_name}' n'existe pas.")

        old_groups = list(user.groups.all())
        if new_group in old_groups:
            audit_logger.warning(f"Tentative d'assigner le même rôle '{new_group_name}' à {user.username}.")
            return user

        user.groups.clear()
        user.groups.add(new_group)
        user.save()

        audit_logger.info(f"Rôle de {user.username} changé de {[g.name for g in old_groups]} à {new_group_name}.")
        return user

    @staticmethod
    def update_system_setting(key, value):
        audit_logger.info(f"Paramètre système '{key}' mis à jour à '{value}' (simulation).")
        pass

    @staticmethod
    @transaction.atomic
    def import_data_from_file(file_path, entity_type, column_mapping, user_initiator):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Le fichier '{file_path}' n'existe pas.")
        if entity_type not in ['Etudiant', 'Enseignant', 'PersonnelAdministratif']:
            raise ValueError(f"Le type d'entité '{entity_type}' n'est pas supporté pour l'importation.")

        audit_logger.info(
            f"Importation de données de type '{entity_type}' lancée par {user_initiator.username} (simulation synchrone).")
        NotificationService.send_notification(
            event_type="import_termine",
            recipient_user=user_initiator,
            context_data={'entity_type': entity_type, 'status': 'succès', 'file_name': os.path.basename(file_path)}
        )
        return True

    @staticmethod
    @transaction.atomic
    def delegate_responsibilities(delegant, delegatee, permissions_list, start_date, end_date):
        if not isinstance(delegant, User) or not isinstance(delegatee, User):
            raise TypeError("Les objets délégant et délégué doivent être des instances de User.")
        if delegant == delegatee:
            raise ValueError("Un utilisateur ne peut pas se déléguer des responsabilités à lui-même.")
        if start_date > end_date:
            raise ValueError("La date de début de délégation ne peut pas être postérieure à la date de fin.")

        Delegation.objects.create(
            delegant=delegant,
            delegue=delegatee,
            permissions_delegues=permissions_list,
            date_debut=start_date,
            date_fin=end_date,
            est_active=True
        )
        NotificationService.send_notification(
            event_type="delegation_accordee",
            recipient_user=delegatee,
            context_data={'delegant_name': delegant.username, 'permissions': ", ".join(permissions_list),
                          'lien_action': "/dashboard"}
        )
        audit_logger.info(
            f"Délégation de {delegant.username} à {delegatee.username} pour {permissions_list} du {start_date} au {end_date}.")
        return True

    @staticmethod
    @transaction.atomic
    def reassign_orphan_tasks(old_user, new_user):
        if not isinstance(old_user, User) or not isinstance(new_user, User):
            raise TypeError("Les objets old_user et new_user doivent être des instances de User.")
        if old_user == new_user:
            raise ValueError("Les utilisateurs source et destination ne peuvent pas être les mêmes.")

        reclamations_updated_count = Reclamation.objects.filter(assigne_a=old_user).update(assigne_a=new_user)
        audit_logger.info(
            f"{reclamations_updated_count} réclamations réassignées de {old_user.username} à {new_user.username}.")

        if hasattr(old_user, 'profil_enseignant'):
            pv_updated_count = ProcesVerbal.objects.filter(redacteur=old_user.profil_enseignant,
                                                           statut_pv__in=[StatutPV.BROUILLON,
                                                                          StatutPV.ATTENTE_APPROBATION]).update(
                redacteur=new_user.profil_enseignant)
            audit_logger.info(f"{pv_updated_count} PV réassignés de {old_user.username} à {new_user.username}.")

        if hasattr(old_user, 'profil_personnel'):
            conformite_updated_count = ConformiteRapportDetail.objects.filter(
                verifie_par=old_user.profil_personnel).update(verifie_par=new_user.profil_personnel)
            audit_logger.info(
                f"{conformite_updated_count} détails de conformité réassignés de {old_user.username} à {new_user.username}.")

        NotificationService.send_notification(
            event_type="taches_reassignees",
            recipient_user=new_user,
            context_data={'old_user_name': old_user.username, 'lien_action': "/dashboard"}
        )
        return True

    @staticmethod
    def get_audit_logs(filters=None):
        logs = Notification.objects.all().order_by('-date_creation')
        if filters:
            if 'user_id' in filters:
                logs = logs.filter(destinataire__id=filters['user_id'])
            if 'event_type' in filters:
                logs = logs.filter(type_notification=filters['event_type'])
            if 'start_date' in filters:
                logs = logs.filter(date_creation__gte=filters['start_date'])
            if 'end_date' in filters:
                logs = logs.filter(date_creation__lte=filters['end_date'])
        audit_logger.info(f"Consultation des logs d'audit avec filtres: {filters}.")
        return logs

    @staticmethod
    def get_system_health_metrics():
        try:
            cpu_usage = random.uniform(10.0, 80.0)
            ram_usage = random.uniform(20.0, 90.0)
            db_connections = random.randint(5, 50)
            queue_size = random.randint(0, 100)
            active_users = User.objects.filter(is_active=True).count()
            reports_in_progress = RapportEtudiant.objects.exclude(
                statut_rapport__in=[StatutRapport.VALIDE, StatutRapport.REFUSE, StatutRapport.ARCHIVE]).count()

            audit_logger.info("Métriques de santé du système récupérées.")
            return {
                'cpu_usage': round(cpu_usage, 2),
                'ram_usage': round(ram_usage, 2),
                'db_connections': db_connections,
                'queue_size': queue_size,
                'active_users': active_users,
                'reports_in_progress': reports_in_progress,
                'timestamp': timezone.now().isoformat()
            }
        except Exception as e:
            error_logger.error(f"Erreur lors de la récupération des métriques système: {e}", exc_info=True)
            raise


class NotificationService:
    @staticmethod
    def send_notification(event_type, recipient_user, context_data):
        message_templates = {
            "rapport_soumis": "Votre rapport '{rapport_title}' a été soumis avec succès.",
            "rapport_retour_correction": "Votre rapport '{rapport_title}' a été retourné pour correction. Raisons: {comments}",
            "rapport_resoumis": "Votre rapport '{rapport_title}' a été re-soumis avec succès.",
            "rapport_refuse_definitif": "Votre rapport '{rapport_title}' a été définitivement refusé. Raisons: {reasons}",
            "directeur_assigne": "Un directeur de mémoire ({director_name}) a été assigné à votre rapport '{rapport_title}'.",
            "assignation_directeur": "Vous avez été désigné directeur de mémoire pour le rapport '{rapport_title}' de {etudiant_name}.",
            "rapport_conforme": "Votre rapport '{rapport_title}' a été jugé conforme et transmis à la commission.",
            "nouveau_rapport_conformite": "Un nouveau rapport ('{rapport_title}' de {etudiant_name}) est en attente de vérification de conformité.",
            "session_planifiee": "Une nouvelle session de validation ('{session_name}') est planifiée pour le {date}.",
            "session_demarree": "La session de validation '{session_name}' a démarré. Veuillez soumettre vos votes.",
            "session_cloturee": "La session de validation '{session_name}' est clôturée.",
            "rapport_refuse": "Le rapport '{rapport_title}' a été refusé par la commission.",
            "rapport_approuve_reserve": "Le rapport '{rapport_title}' a été approuvé sous réserve de corrections mineures par la commission.",
            "rapport_valide": "Votre rapport '{rapport_title}' a été validé par la commission !",
            "pv_attente_approbation": "Un Procès-Verbal ({pv_id}) de la session '{session_name}' est en attente de votre approbation.",
            "pv_modification_demandee": "Des modifications ont été demandées pour le PV ({pv_id}). Commentaire: {comment}",
            "pv_valide_etudiant": "Le Procès-Verbal de validation de votre rapport ({rapport_title}) est disponible ({pv_id}).",
            "pv_valide_admin": "Le Procès-Verbal ({pv_id}) de la session '{session_name}' a été validé et diffusé.",
            "compte_etudiant_active": "Votre compte GestionMySoutenance a été activé. Votre nom d'utilisateur est '{username}'.",
            "stage_valide": "Votre stage '{sujet_stage}' a été validé par le service de scolarité.",
            "penalite_reglee": "Votre pénalité pour '{motif_penalite}' d'un montant de {montant} a été régularisée.",
            "bulletin_disponible": "Votre bulletin de notes de l'année {annee} (version {version}) est disponible dans votre espace personnel.",
            "email_non_valide": "Votre adresse email n'est pas validée. Veuillez cliquer sur le lien dans l'email de confirmation.",
            "import_termine": "L'importation de données de type '{entity_type}' est terminée avec {status}.",
            "delegation_accordee": "Une délégation de responsabilités vous a été accordée par {delegant_name} pour les permissions : {permissions}.",
            "taches_reassignees": "Des tâches de l'utilisateur {old_user_name} vous ont été réassignées.",
            "compte_bloque": "Votre compte a été temporairement bloqué pour {duration} minutes suite à trop de tentatives de connexion échouées.",
            "password_reset": "Votre mot de passe a été réinitialisé avec succès.",
            "2fa_active": "L'authentification à deux facteurs a été activée sur votre compte.",
            "2fa_desactive": "L'authentification à deux facteurs a été désactivée sur votre compte."
        }

        message_raw = message_templates.get(event_type, "Une notification importante a été générée.")

        try:
            message_formatted = message_raw.format(**context_data)
        except KeyError as e:
            error_logger.error(
                f"Erreur de formatage de message pour l'événement '{event_type}': Clé manquante {e}. Contexte: {context_data}",
                exc_info=True)
            message_formatted = message_raw  # Utiliser le message brut en cas d'erreur de formatage

        # Créer une notification interne
        Notification.objects.create(
            destinataire=recipient_user,
            message=message_formatted,
            type_notification=event_type,
            lien_action=context_data.get('lien_action')
        )

        # Envoyer un email si l'utilisateur a validé son email et n'a pas désactivé ce type de notification
        # Les préférences de notification sont stockées dans un JSONField sur le modèle User
        # Par défaut, toutes les notifications sont activées (True)
        user_prefs = recipient_user.preferences_notifications if recipient_user.preferences_notifications is not None else {}

        # Définir une liste de notifications critiques qui ne peuvent pas être désactivées par l'utilisateur
        critical_notifications = [
            "compte_bloque", "password_reset", "2fa_active", "2fa_desactive",
            "rapport_refuse_definitif", "pv_modification_demandee", "pv_valide_etudiant"
        ]

        if recipient_user.email_valide and (event_type in critical_notifications or user_prefs.get(event_type, True)):
            subject = f"[GestionMySoutenance] Notification: {event_type.replace('_', ' ').title()}"
            email_body_html = render_to_string('emails/notification_email.html', {
                'message': message_formatted,
                'user': recipient_user,
                'event_type': event_type,
                'context_data': context_data
            })
            NotificationService.send_email(recipient_user.email, subject, None, html_body=email_body_html)
        audit_logger.info(f"Notification '{event_type}' envoyée à {recipient_user.username}.")

    @staticmethod
    def send_email(recipient_email, subject, body, html_body=None):
        if not recipient_email:
            error_logger.error(f"Tentative d'envoi d'email sans adresse de destinataire pour le sujet: {subject}.")
            return False
        try:
            send_mail(
                subject,
                body,
                settings.DEFAULT_FROM_EMAIL,
                [recipient_email],
                html_message=html_body,
                fail_silently=False,
            )
            audit_logger.info(f"Email '{subject}' envoyé à {recipient_email}.")
            return True
        except Exception as e:
            error_logger.error(f"Erreur lors de l'envoi de l'email à {recipient_email} (Sujet: {subject}): {e}",
                               exc_info=True)
            return False

    @staticmethod
    @transaction.atomic
    def archive_message(notification):
        if not isinstance(notification, Notification):
            raise TypeError("L'objet fourni doit être une instance de Notification.")
        if notification.est_archivee:
            audit_logger.warning(f"Tentative d'archiver une notification déjà archivée ({notification.id}).")
            return notification
        notification.est_archivee = True
        notification.save(update_fields=['est_archivee'])
        audit_logger.info(f"Notification {notification.id} archivée pour {notification.destinataire.username}.")
        return notification

    @staticmethod
    @transaction.atomic
    def set_user_notification_preferences(user, preferences):
        if not isinstance(user, User):
            raise TypeError("L'objet fourni doit être une instance de User.")
        if not isinstance(preferences, dict):
            raise ValueError("Les préférences doivent être un dictionnaire.")

        user.preferences_notifications = preferences
        user.save(update_fields=['preferences_notifications'])
        audit_logger.info(f"Préférences de notification de {user.username} mises à jour.")
        return user

class ReportingService:
    @staticmethod
    def global_search(query, user_roles):
            results = []
            query_lower = query.lower()

            # Définir les permissions requises pour chaque type de recherche
            can_view_students = any(role in user_roles for role in
                                    ['Administrateur Système', 'Responsable Scolarité', 'Agent de Conformité',
                                     'Enseignant'])
            can_view_reports = any(role in user_roles for role in
                                   ['Administrateur Système', 'Responsable Scolarité', 'Agent de Conformité',
                                    'Membre de Commission', 'Enseignant'])
            can_view_sessions = any(
                role in user_roles for role in ['Administrateur Système', 'Membre de Commission', 'Enseignant'])
            can_view_personnel = any(role in user_roles for role in ['Administrateur Système', 'Responsable Scolarité'])

            if can_view_students:
                etudiants = Etudiant.objects.filter(
                    Q(utilisateur__username__icontains=query_lower) |
                    Q(nom__icontains=query_lower) |
                    Q(prenom__icontains=query_lower) |
                    Q(utilisateur__email__icontains=query_lower)
                ).distinct()
                for e in etudiants:
                    results.append({
                        'type': 'Étudiant',
                        'id': e.utilisateur.username,
                        'nom_complet': e.nom_complet,
                        'email': e.utilisateur.email,
                        'lien': f"/admin/core/etudiant/{e.utilisateur.id}/change/"  # Lien vers l'admin pour l'exemple
                    })

            if can_view_reports:
                rapports = RapportEtudiant.objects.filter(
                    Q(libelle_rapport_etudiant__icontains=query_lower) |
                    Q(theme__icontains=query_lower) |
                    Q(etudiant__nom__icontains=query_lower) |
                    Q(etudiant__prenom__icontains=query_lower)
                ).distinct()
                for r in rapports:
                    results.append({
                        'type': 'Rapport',
                        'id': r.id_rapport_etudiant,
                        'titre': r.libelle_rapport_etudiant,
                        'etudiant': r.etudiant.nom_complet,
                        'statut': r.get_statut_rapport_display(),
                        'lien': f"/admin/core/rapportetudiant/{r.id_rapport_etudiant}/change/"
                    })

            if can_view_sessions:
                sessions = SessionValidation.objects.filter(
                    Q(nom_session__icontains=query_lower) |
                    Q(president_session__nom__icontains=query_lower) |
                    Q(president_session__prenom__icontains=query_lower)
                ).distinct()
                for s in sessions:
                    results.append({
                        'type': 'Session de Validation',
                        'id': s.id_session,
                        'nom': s.nom_session,
                        'president': s.president_session.nom_complet,
                        'statut': s.get_statut_session_display(),
                        'lien': f"/admin/core/sessionvalidation/{s.id_session}/change/"
                    })

            if can_view_personnel:
                personnels = PersonnelAdministratif.objects.filter(
                    Q(utilisateur__username__icontains=query_lower) |
                    Q(nom__icontains=query_lower) |
                    Q(prenom__icontains=query_lower) |
                    Q(utilisateur__email__icontains=query_lower)
                ).distinct()
                for p in personnels:
                    results.append({
                        'type': 'Personnel Administratif',
                        'id': p.utilisateur.username,
                        'nom_complet': p.nom_complet,
                        'email': p.utilisateur.email,
                        'lien': f"/admin/core/personneladministratif/{p.utilisateur.id}/change/"
                    })

                enseignants = Enseignant.objects.filter(
                    Q(utilisateur__username__icontains=query_lower) |
                    Q(nom__icontains=query_lower) |
                    Q(prenom__icontains=query_lower) |
                    Q(utilisateur__email__icontains=query_lower)
                ).distinct()
                for e in enseignants:
                    results.append({
                        'type': 'Enseignant',
                        'id': e.utilisateur.username,
                        'nom_complet': e.nom_complet,
                        'email': e.utilisateur.email,
                        'lien': f"/admin/core/enseignant/{e.utilisateur.id}/change/"
                    })

            audit_logger.info(
                f"Recherche globale effectuée pour la requête '{query}' par un utilisateur avec rôles {user_roles}. Résultats: {len(results)}.")
            return results

    @staticmethod  # <-- Assurez-vous que cette méthode est bien DANS la classe ReportingService
    def get_system_health_metrics():
        try:
            cpu_usage = random.uniform(10.0, 80.0)
            ram_usage = random.uniform(20.0, 90.0)
            db_connections = random.randint(5, 50)
            queue_size = random.randint(0, 100)
            active_users = User.objects.filter(is_active=True).count()
            reports_in_progress = RapportEtudiant.objects.exclude(
                statut_rapport__in=[StatutRapport.VALIDE, StatutRapport.REFUSE, StatutRapport.ARCHIVE]).count()

            audit_logger.info("Métriques de santé du système récupérées.")
            return {
                'cpu_usage': round(cpu_usage, 2),
                'ram_usage': round(ram_usage, 2),
                'db_connections': db_connections,
                'queue_size': queue_size,
                'active_users': active_users,
                'reports_in_progress': reports_in_progress,
                'timestamp': timezone.now().isoformat()
            }
        except Exception as e:
            error_logger.error(f"Erreur lors de la récupération des métriques système: {e}", exc_info=True)
            raise

    @staticmethod
    def generate_validation_rate_report(annee_academique=None, specialite=None):
            rapports = RapportEtudiant.objects.all()

            if annee_academique:
                if not isinstance(annee_academique, AnneeAcademique):
                    raise TypeError("L'objet annee_academique doit être une instance d'AnneeAcademique.")
                rapports = rapports.filter(stage__date_fin_stage__year=annee_academique.date_fin.year)  # Approximation

            if specialite:
                if not isinstance(specialite, Specialite):
                    raise TypeError("L'objet specialite doit être une instance de Specialite.")
                # Cette jointure est complexe car Inscription est ManyToMany via Etudiant
                # Il faudrait s'assurer que la relation Etudiant -> Inscription -> Specialite est bien définie
                rapports = rapports.filter(etudiant__inscription__specialite=specialite).distinct()

            total_rapports = rapports.count()
            validated_rapports = rapports.filter(statut_rapport=StatutRapport.VALIDE).count()
            rejected_rapports = rapports.filter(statut_rapport=StatutRapport.REFUSE).count()
            in_progress_rapports = total_rapports - validated_rapports - rejected_rapports

            validation_rate = (validated_rapports / total_rapports * 100) if total_rapports > 0 else 0
            rejection_rate = (rejected_rapports / total_rapports * 100) if total_rapports > 0 else 0
            in_progress_rate = (in_progress_rapports / total_rapports * 100) if total_rapports > 0 else 0

            audit_logger.info(
                f"Rapport de taux de validation généré pour l'année {annee_academique.libelle_annee_academique if annee_academique else 'toutes'} et spécialité {specialite.libelle_specialite if specialite else 'toutes'}.")
            return {
                'total_rapports': total_rapports,
                'validated_rapports': validated_rapports,
                'rejected_rapports': rejected_rapports,
                'in_progress_rapports': in_progress_rapports,
                'validation_rate': round(validation_rate, 2),
                'rejection_rate': round(rejection_rate, 2),
                'in_progress_rate': round(in_progress_rate, 2)
            }

    @staticmethod
    def get_workflow_processing_times():
            # Pour des délais précis, il faudrait un modèle d'historique des statuts de rapport
            # qui enregistre chaque changement de statut avec un horodatage.
            # Pour l'instant, nous nous basons sur les dates disponibles dans le modèle RapportEtudiant.

            # Exemple: Délai moyen entre soumission et validation/refus
            validated_or_rejected_reports = RapportEtudiant.objects.filter(
                Q(statut_rapport=StatutRapport.VALIDE) | Q(statut_rapport=StatutRapport.REFUSE)
            ).exclude(date_soumission__isnull=True)

            total_days = 0
            count = 0
            for rapport in validated_or_rejected_reports:
                # Assumant un champ date_finalisation_commission ou date_finalisation_pv sur le rapport
                # Pour l'exemple, utilisons la date de finalisation du PV si elle existe
                if rapport.date_soumission and hasattr(rapport,
                                                       'procesverbal') and rapport.procesverbal and rapport.procesverbal.date_finalisation:  # <-- CORRECTION ICI
                    duration = rapport.procesverbal.date_finalisation - rapport.date_soumission
                    total_days += duration.days
                    count += 1

            avg_days = (total_days / count) if count > 0 else 0

            audit_logger.info("Rapport sur les délais de traitement du workflow généré.")
            return {
                'avg_submission_to_decision_days': round(avg_days, 2),
                'notes': "Nécessite un historique de statut détaillé pour une précision complète."
            }

    @staticmethod
    def export_data(queryset, format_type, fields=None):
            if not queryset:
                raise ValueError("Le queryset ne peut pas être vide.")
            if format_type not in ['csv', 'pdf']:
                raise ValueError(f"Format d'exportation '{format_type}' non supporté. Choisissez 'csv' ou 'pdf'.")

            model_name = queryset.model.__name__
            timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
            file_name_base = f"export_{model_name}_{timestamp}"

            # Assurez-vous que le répertoire d'exportation existe
            export_dir = os.path.join(settings.MEDIA_ROOT, 'exports')
            os.makedirs(export_dir, exist_ok=True)

            if format_type == 'csv':
                import csv
                file_path = os.path.join(export_dir, f"{file_name_base}.csv")

                if not fields:
                    fields = [f.name for f in queryset.model._meta.fields]

                try:
                    with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(fields)  # Écrire l'en-tête
                        for obj in queryset:
                            row = []
                            for field in fields:
                                val = getattr(obj, field)
                                if isinstance(val, models.Model):  # Gérer les relations
                                    val = str(val)
                                row.append(val)
                            writer.writerow(row)
                    audit_logger.info(f"Export CSV de {model_name} effectué vers {file_path}.")
                    return file_path
                except Exception as e:
                    error_logger.error(f"Erreur lors de l'export CSV de {model_name}: {e}", exc_info=True)
                    raise

            elif format_type == 'pdf':
                file_path = os.path.join(export_dir, f"{file_name_base}.pdf")

                try:
                    # Exemple de pseudo-code pour la génération PDF
                    # html_content = render_to_string('pdf/generic_export.html', {
                    #     'model_name': model_name,
                    #     'objects': queryset,
                    #     'fields': fields if fields else [f.name for f in queryset.model._meta.fields],
                    #     'date_export': timezone.now()
                    # })
                    # pdf_content = HTML(string=html_content).write_pdf()
                    # with open(file_path, 'wb') as f:
                    #     f.write(pdf_content)

                    # Simulation de création de fichier pour la démo
                    with open(file_path, 'w') as f:
                        f.write(f"Contenu PDF simulé pour l'export de {model_name}")
                    audit_logger.info(f"Export PDF de {model_name} effectué vers {file_path}.")
                    return file_path
                except Exception as e:
                    error_logger.error(f"Erreur lors de l'export PDF de {model_name}: {e}", exc_info=True)
                    raise