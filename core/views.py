from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
# from django.urls import reverse # Supprimé car non utilisé
# from django.http import HttpResponseForbidden, JsonResponse # Supprimé car non utilisé
from django.http import HttpResponse, Http404  # Gardé HttpResponse, Http404
# from django.template.loader import render_to_string # Déjà importé dans services, mais peut être utile ici si des rendus directs sont faits
from django.db import transaction
from django.conf import settings
from django.db.models import Q 
from django.core.exceptions import PermissionDenied
import datetime
# import json # Supprimé car non utilisé
import os

from django.contrib.auth.models import User, Group, Permission

from django.utils import timezone

from .forms import (
    LoginForm, PasswordResetEmailForm, SetNewPasswordForm, TwoFactorSetupForm,
    UserProfileForm, EtudiantProfileForm, RapportEtudiantForm, ConformityChecklistForm,
    ProcesVerbalForm, PVApprovalForm, NoteForm,  # Imports nettoyés
    ReclamationForm, ReclamationResponseForm, DelegationForm, UserCreationForm,
    SessionValidationForm, VoteCommissionForm  # Ajoutés car utilisés dans les vues
)
from .services import (
    AuthentificationService, RapportService, ConformiteService, CommissionService,
    ScolariteService, AdminService, NotificationService, UniqueIdGeneratorService, ReportingService
)
from .models import (
    Etudiant, Enseignant, PersonnelAdministratif, RapportEtudiant, SectionRapport,
    CritereConformite, SessionValidation, ProcesVerbal, Penalite, Notification,
    Reclamation, Delegation, DocumentOfficiel, Stage, Inscription, Note, Ecue,
    AnneeAcademique, Specialite
)
from .enums import (
    StatutRapport, StatutPenalite, StatutPV, DecisionValidationPV, StatutReclamation, StatutSession  # Imports nettoyés
)

import logging

audit_logger = logging.getLogger('audit_logger')
error_logger = logging.getLogger('error_logger')


# --- Fonctions d'aide pour les tests de groupe ---
def is_admin_sys(user):
    return user.is_authenticated and user.groups.filter(name='Administrateur Système').exists()


def is_etudiant(user):
    return user.is_authenticated and user.groups.filter(name='Étudiant').exists()


def is_responsable_scolarite(user):
    return user.is_authenticated and user.groups.filter(name='Responsable Scolarité').exists()


def is_agent_conformite(user):
    return user.is_authenticated and user.groups.filter(name='Agent de Conformité').exists()


def is_membre_commission(user):
    return user.is_authenticated and user.groups.filter(name='Membre de Commission').exists()


def is_enseignant(user):
    return user.is_authenticated and user.groups.filter(name='Enseignant').exists()


# --- Vues d'Authentification ---

def user_login(request):
    if request.user.is_authenticated:
        return redirect('dashboard_redirect')

    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                if AuthentificationService.is_account_locked(user):
                    messages.error(request, "Votre compte est temporairement bloqué. Veuillez réessayer plus tard.")
                    audit_logger.warning(f"Tentative de connexion échouée pour {username}: compte bloqué.")
                    return render(request, 'core/auth/login.html', {'form': form})

                AuthentificationService.reset_login_attempts(user)
                login(request, user)
                messages.success(request, f"Bienvenue, {user.first_name} {user.last_name} !")
                audit_logger.info(f"Connexion réussie pour {username}.")
                return redirect('dashboard_redirect')
            else:
                user_obj = User.objects.filter(username=username).first()
                if user_obj:
                    AuthentificationService.increment_login_attempts(user_obj)
                    if AuthentificationService.is_account_locked(user_obj):
                        messages.error(request, "Votre compte est temporairement bloqué. Veuillez réessayer plus tard.")
                        audit_logger.warning(
                            f"Connexion échouée pour {username}: compte bloqué après tentatives excessives.")
                        return render(request, 'core/auth/login.html', {'form': form})
                messages.error(request, "Nom d'utilisateur ou mot de passe incorrect.")
                audit_logger.warning(f"Connexion échouée pour {username}: identifiants incorrects.")
        else:
            messages.error(request, "Veuillez corriger les erreurs ci-dessous.")
    else:
        form = LoginForm()
    return render(request, 'core/auth/login.html', {'form': form})


@login_required
def user_logout(request):
    audit_logger.info(f"Déconnexion de {request.user.username}.")
    logout(request)
    messages.info(request, "Vous avez été déconnecté.")
    return redirect('login')


def password_reset_request(request):
    if request.method == 'POST':
        form = PasswordResetEmailForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            user = User.objects.filter(email=email).first()
            if user:
                messages.info(request,
                              "Si un compte avec cet email existe, des instructions de réinitialisation ont été envoyées.")
                audit_logger.info(f"Demande de réinitialisation de mot de passe pour {email}.")
            else:
                messages.info(request,
                              "Si un compte avec cet email existe, des instructions de réinitialisation ont été envoyées.")
            return redirect('login')
    else:
        form = PasswordResetEmailForm()
    return render(request, 'core/auth/password_reset_request.html', {'form': form})


def password_reset_confirm(request, uidb64, token):
    messages.info(request, "Cette page est un placeholder pour la réinitialisation de mot de passe.")
    return redirect('login')


@login_required
def email_validation_confirm(request):
    token = request.GET.get('token')
    if not token:
        messages.error(request, "Jeton de validation manquant.")
        return redirect('dashboard_redirect')

    try:
        if AuthentificationService.validate_email(request.user, token):
            messages.success(request, "Votre adresse email a été validée avec succès !")
        else:
            messages.error(request, "Le jeton de validation est invalide ou a expiré.")
    except Exception as e:
        error_logger.error(f"Erreur lors de la validation d'email pour {request.user.username}: {e}")
        messages.error(request, "Une erreur est survenue lors de la validation de votre email.")
    return redirect('dashboard_redirect')


@login_required
def two_factor_setup(request):
    if request.user.is_2fa_active:
        messages.info(request, "L'authentification à deux facteurs est déjà active.")
        return redirect('dashboard_redirect')

    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['code']
            try:
                if AuthentificationService.verify_2fa_code(request.user, code):
                    messages.success(request, "L'authentification à deux facteurs a été activée avec succès !")
                    return redirect('dashboard_redirect')
                else:
                    messages.error(request, "Code de vérification invalide.")
            except ValueError as e:
                messages.error(request, str(e))
                error_logger.error(f"Erreur 2FA pour {request.user.username}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(f"Erreur inattendue 2FA pour {request.user.username}: {e}", exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = TwoFactorSetupForm()

    secret = AuthentificationService.generate_2fa_secret(request.user)

    return render(request, 'core/auth/2fa_setup.html', {'secret': secret, 'form': form})


@login_required
def two_factor_verify(request):
    if not request.user.is_2fa_active:
        return redirect('dashboard_redirect')

    if request.method == 'POST':
        form = TwoFactorSetupForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['code']
            try:
                if AuthentificationService.verify_2fa_code(request.user, code):
                    messages.success(request, "Code 2FA vérifié. Connexion réussie.")
                    return redirect('dashboard_redirect')
                else:
                    messages.error(request, "Code 2FA invalide.")
            except ValueError as e:
                messages.error(request, str(e))
                error_logger.error(f"Erreur 2FA pour {request.user.username}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(f"Erreur inattendue 2FA pour {request.user.username}: {e}", exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = TwoFactorSetupForm()
    return render(request, 'core/auth/2fa_verify.html', {'form': form})


@login_required
def disable_2fa(request):
    if request.method == 'POST':
        try:
            if AuthentificationService.disable_2fa(request.user):
                messages.success(request, "L'authentification à deux facteurs a été désactivée.")
            else:
                messages.warning(request, "La 2FA n'était pas active ou une erreur est survenue.")
        except Exception as e:
            messages.error(request, f"Erreur lors de la désactivation de la 2FA: {e}")
            error_logger.error(f"Erreur désactivation 2FA pour {request.user.username}: {e}")
    return redirect('user_profile')


# --- Vues Communes ---

@login_required
def dashboard_redirect(request):
    if is_admin_sys(request.user):
        return redirect('admin_dashboard')
    elif is_etudiant(request.user):
        return redirect('etudiant_dashboard')
    elif is_responsable_scolarite(request.user) or is_agent_conformite(request.user):
        return redirect('personnel_dashboard')
    elif is_membre_commission(request.user) or is_enseignant(request.user):
        return redirect('enseignant_dashboard')
    else:
        messages.warning(request, "Votre rôle ne vous donne pas accès à un tableau de bord spécifique.")
        return render(request, 'core/dashboard_base.html')


@login_required
def user_profile(request):
    user_profile_form = UserProfileForm(instance=request.user)
    etudiant_profile_form = None
    if is_etudiant(request.user):
        etudiant_profile_form = EtudiantProfileForm(instance=request.user.profil_etudiant)

    if request.method == 'POST':
        if 'update_user_profile' in request.POST:
            user_profile_form = UserProfileForm(request.POST, instance=request.user)
            if user_profile_form.is_valid():
                user_profile_form.save()
                messages.success(request, "Votre profil utilisateur a été mis à jour.")
                audit_logger.info(f"Profil utilisateur de {request.user.username} mis à jour.")
                return redirect('user_profile')
            else:
                messages.error(request, "Erreur lors de la mise à jour du profil utilisateur.")
        elif 'update_etudiant_profile' in request.POST and is_etudiant(request.user):
            etudiant_profile_form = EtudiantProfileForm(request.POST, instance=request.user.profil_etudiant)
            if etudiant_profile_form.is_valid():
                etudiant_profile_form.save()
                messages.success(request, "Votre profil étudiant a été mis à jour.")
                audit_logger.info(f"Profil étudiant de {request.user.username} mis à jour.")
                return redirect('user_profile')
            else:
                messages.error(request, "Erreur lors de la mise à jour du profil étudiant.")
        elif 'change_password' in request.POST:
            password_form = PasswordChangeForm(request.user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, "Votre mot de passe a été changé avec succès !")
                audit_logger.info(f"Mot de passe de {request.user.username} changé.")
                return redirect('user_profile')
            else:
                messages.error(request, "Erreur lors du changement de mot de passe.")
        elif 'send_email_validation' in request.POST:
            try:
                if AuthentificationService.send_email_validation_token(request.user):
                    messages.info(request, "Un email de validation a été envoyé à votre adresse principale.")
                else:
                    messages.warning(request, "Votre email est déjà validé ou une erreur est survenue.")
            except Exception as e:
                messages.error(request, f"Erreur lors de l'envoi de l'email de validation: {e}")
                error_logger.error(f"Erreur envoi email validation pour {request.user.username}: {e}")
            return redirect('user_profile')
        elif 'disable_2fa_action' in request.POST:
            try:
                if AuthentificationService.disable_2fa(request.user):
                    messages.success(request, "L'authentification à deux facteurs a été désactivée.")
                else:
                    messages.warning(request, "La 2FA n'était pas active ou une erreur est survenue.")
            except Exception as e:
                messages.error(request, f"Erreur lors de la désactivation de la 2FA: {e}")
                error_logger.error(f"Erreur désactivation 2FA pour {request.user.username}: {e}")
            return redirect('user_profile')

    context = {
        'user_profile_form': user_profile_form,
        'etudiant_profile_form': etudiant_profile_form,
        'password_form': PasswordChangeForm(request.user),
        'is_etudiant': is_etudiant(request.user),
        'email_not_validated': not request.user.email_valide,
        'is_2fa_active': request.user.is_2fa_active,
    }
    return render(request, 'core/user_profile.html', context)


# --- Vues Étudiant ---

@login_required
@user_passes_test(is_etudiant, login_url='dashboard_redirect')
def etudiant_dashboard(request):
    etudiant_profile = request.user.profil_etudiant
    rapports = RapportEtudiant.objects.filter(etudiant=etudiant_profile).order_by('-date_soumission')
    notifications = Notification.objects.filter(destinataire=request.user, est_lue=False).order_by('-date_creation')[:5]
    reclamations = Reclamation.objects.filter(etudiant=etudiant_profile).order_by('-date_soumission')[:5]

    can_submit_report = etudiant_profile.est_eligible_soumission

    context = {
        'etudiant': etudiant_profile,
        'rapports': rapports,
        'notifications': notifications,
        'reclamations': reclamations,
        'can_submit_report': can_submit_report,
    }
    return render(request, 'core/etudiant/dashboard.html', context)


@login_required
@user_passes_test(is_etudiant, login_url='dashboard_redirect')
def rapport_create_or_edit(request, rapport_id=None):
    etudiant_profile = request.user.profil_etudiant
    rapport = None
    sections_data_for_template = []

    if rapport_id:
        rapport = get_object_or_404(RapportEtudiant, id_rapport_etudiant=rapport_id, etudiant=etudiant_profile)
        if rapport.statut_rapport not in [StatutRapport.BROUILLON, StatutRapport.NON_CONFORME]:
            messages.error(request, "Ce rapport ne peut plus être modifié dans son statut actuel.")
            return redirect('rapport_suivi', rapport_id=rapport.id_rapport_etudiant)
        sections_data_for_template = list(
            SectionRapport.objects.filter(rapport_etudiant=rapport).order_by('ordre').values('titre_section',
                                                                                             'contenu_section',
                                                                                             'ordre'))
        rapport_form = RapportEtudiantForm(instance=rapport, etudiant=etudiant_profile)
    else:
        rapport_form = RapportEtudiantForm(etudiant=etudiant_profile)
        sections_data_for_template = [
            {'titre_section': 'Introduction', 'contenu_section': '', 'ordre': 1},
            {'titre_section': 'Développement', 'contenu_section': '', 'ordre': 2},
            {'titre_section': 'Conclusion', 'contenu_section': '', 'ordre': 3},
            {'titre_section': 'Bibliographie', 'contenu_section': '', 'ordre': 4}
        ]

    if request.method == 'POST':
        rapport_form = RapportEtudiantForm(request.POST, instance=rapport, etudiant=etudiant_profile)

        section_data_from_post = {}
        for key, value in request.POST.items():
            if key.startswith('section_titre_'):
                index = key.replace('section_titre_', '')
                titre = value
                contenu = request.POST.get(f'section_contenu_{index}')
                ordre = request.POST.get(f'section_ordre_{index}', 0)
                if titre:
                    section_data_from_post[titre] = {'contenu': contenu, 'ordre': int(ordre)}

        if rapport_form.is_valid():
            try:
                with transaction.atomic():
                    if not rapport:
                        rapport = RapportService.create_draft_report(
                            etudiant=etudiant_profile,
                            stage=rapport_form.cleaned_data['stage'],
                            title=rapport_form.cleaned_data['libelle_rapport_etudiant'],
                            theme=rapport_form.cleaned_data['theme'],
                            num_pages=rapport_form.cleaned_data['nombre_pages']
                        )
                    else:
                        rapport.libelle_rapport_etudiant = rapport_form.cleaned_data['libelle_rapport_etudiant']
                        rapport.theme = rapport_form.cleaned_data['theme']
                        rapport.nombre_pages = rapport_form.cleaned_data['nombre_pages']
                        rapport.stage = rapport_form.cleaned_data['stage']
                        rapport.save()

                    current_section_titles = set(
                        SectionRapport.objects.filter(rapport_etudiant=rapport).values_list('titre_section', flat=True))

                    for titre, data in section_data_from_post.items():
                        SectionRapport.objects.update_or_create(
                            rapport_etudiant=rapport,
                            titre_section=titre,
                            defaults={'contenu_section': data['contenu'], 'ordre': data['ordre']}
                        )

                    for old_title in current_section_titles:
                        if old_title not in section_data_from_post:
                            SectionRapport.objects.filter(rapport_etudiant=rapport, titre_section=old_title).delete()

                    if 'submit_report' in request.POST:
                        if rapport.statut_rapport == StatutRapport.NON_CONFORME:
                            correction_note = request.POST.get('correction_note_field')
                            RapportService.resubmit_corrected_report(rapport, correction_note)
                            messages.success(request, "Votre rapport corrigé a été re-soumis avec succès !")
                        else:
                            RapportService.submit_report(rapport)
                            messages.success(request, "Votre rapport a été soumis avec succès !")
                        return redirect('rapport_suivi', rapport_id=rapport.id_rapport_etudiant)
                    else:
                        messages.success(request, "Rapport sauvegardé en brouillon.")
                        return redirect('rapport_create_or_edit', rapport_id=rapport.id_rapport_etudiant)

            except ValueError as e:
                messages.error(request, f"Erreur de soumission: {e}")
                error_logger.error(f"Erreur soumission rapport pour {request.user.username}: {e}")
            except PermissionError as e:
                messages.error(request, f"Permission refusée: {e}")
                error_logger.error(f"Permission refusée soumission rapport pour {request.user.username}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue: {e}")
                error_logger.critical(f"Erreur inattendue soumission rapport pour {request.user.username}: {e}",
                                      exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs dans le formulaire principal.")

        sections_data_for_template = []
        for titre, data in section_data_from_post.items():
            sections_data_for_template.append(
                {'titre_section': titre, 'contenu_section': data['contenu'], 'ordre': data['ordre']})
        sections_data_for_template.sort(key=lambda x: x['ordre'])

    context = {
        'rapport_form': rapport_form,
        'rapport': rapport,
        'sections': sections_data_for_template,
        'is_editing': rapport_id is not None,
        'is_non_conforme': rapport and rapport.statut_rapport == StatutRapport.NON_CONFORME,
    }
    return render(request, 'core/etudiant/rapport_edit.html', context)


@login_required
@user_passes_test(is_etudiant, login_url='dashboard_redirect')
def rapport_suivi(request, rapport_id):
    etudiant_profile = request.user.profil_etudiant
    rapport = get_object_or_404(RapportEtudiant, id_rapport_etudiant=rapport_id, etudiant=etudiant_profile)

    conformite_details = rapport.conformiterapportdetail_set.all().order_by('critere__libelle_critere')

    context = {
        'rapport': rapport,
        'conformite_details': conformite_details,
    }
    return render(request, 'core/etudiant/rapport_suivi.html', context)


@login_required
@user_passes_test(is_etudiant, login_url='dashboard_redirect')
def etudiant_documents(request):
    etudiant_profile = request.user.profil_etudiant
    official_documents = DocumentOfficiel.objects.filter(etudiant=etudiant_profile, est_officiel=True).order_by(
        '-date_generation')

    if request.method == 'POST' and 'generate_provisional' in request.POST:
        try:
            pdf_content = ScolariteService.generate_provisional_transcript(etudiant_profile)
            response = HttpResponse(pdf_content, content_type='application/pdf')
            response[
                'Content-Disposition'] = f'attachment; filename="releve_provisoire_{etudiant_profile.nom_complet.replace(" ", "_")}_{timezone.now().strftime("%Y%m%d")}.pdf"'
            audit_logger.info(f"Relevé provisoire généré et téléchargé par {request.user.username}.")
            return response
        except Exception as e:
            messages.error(request, f"Erreur lors de la génération du relevé provisoire : {e}")
            error_logger.error(f"Erreur génération relevé provisoire pour {request.user.username}: {e}", exc_info=True)
            return redirect('etudiant_documents')

    context = {
        'official_documents': official_documents,
    }
    return render(request, 'core/etudiant/documents.html', context)


@login_required
@user_passes_test(is_etudiant, login_url='dashboard_redirect')
def etudiant_reclamations(request):
    etudiant_profile = request.user.profil_etudiant
    reclamations = Reclamation.objects.filter(etudiant=etudiant_profile).order_by('-date_soumission')

    if request.method == 'POST':
        form = ReclamationForm(request.POST)
        if form.is_valid():
            try:
                reclamation = form.save(commit=False)
                reclamation.etudiant = etudiant_profile
                reclamation.save()
                messages.success(request, "Votre réclamation a été soumise avec succès.")
                audit_logger.info(f"Réclamation soumise par {request.user.username}: {reclamation.sujet}.")
                return redirect('etudiant_reclamations')
            except Exception as e:
                messages.error(request, f"Erreur lors de la soumission de la réclamation : {e}")
                error_logger.error(f"Erreur soumission réclamation pour {request.user.username}: {e}", exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = ReclamationForm()

    context = {
        'reclamations': reclamations,
        'form': form,
    }
    return render(request, 'core/etudiant/reclamations.html', context)


# --- Vues Personnel Administratif ---

@login_required
@user_passes_test(lambda u: is_responsable_scolarite(u) or is_agent_conformite(u), login_url='dashboard_redirect')
def personnel_dashboard(request):
    if is_responsable_scolarite(request.user):
        return redirect('scolarite_dashboard')
    elif is_agent_conformite(request.user):
        return redirect('conformite_dashboard')
    messages.info(request, "Bienvenue sur le tableau de bord du personnel administratif.")
    return render(request, 'core/personnel/dashboard.html')


@login_required
@user_passes_test(is_agent_conformite, login_url='dashboard_redirect')
def conformite_dashboard(request):
    reports_to_check = ConformiteService.get_reports_for_conformity_check(request.user)
    context = {
        'reports_to_check': reports_to_check,
    }
    return render(request, 'core/personnel/conformite_dashboard.html', context)


@login_required
@user_passes_test(is_agent_conformite, login_url='dashboard_redirect')
def conformite_check_report(request, rapport_id):
    rapport = get_object_or_404(RapportEtudiant, id_rapport_etudiant=rapport_id)
    if rapport.statut_rapport != StatutRapport.SOUMIS:
        messages.warning(request,
                         f"Ce rapport n'est pas en statut 'Soumis' et ne peut pas être vérifié. Statut actuel: {rapport.get_statut_rapport_display()}")
        return redirect('conformite_dashboard')

    criteres = CritereConformite.objects.filter(est_actif=True).order_by('libelle_critere')
    initial_data = {}
    for detail in rapport.conformiterapportdetail_set.all():
        initial_data[f'critere_{detail.critere.id_critere}_statut'] = detail.statut_validation
        initial_data[f'critere_{detail.critere.id_critere}_commentaire'] = detail.commentaire

    if request.method == 'POST':
        form = ConformityChecklistForm(request.POST, criteres=criteres)
        if form.is_valid():
            checklist_results = form.cleaned_data['checklist_results']
            try:
                ConformiteService.apply_conformity_checklist(rapport, request.user.profil_personnel, checklist_results)
                messages.success(request, "Vérification de conformité enregistrée et rapport mis à jour.")
                return redirect('conformite_dashboard')
            except ValueError as e:
                messages.error(request, f"Erreur lors de l'application de la checklist: {e}")
                error_logger.error(
                    f"Erreur application checklist pour {request.user.username} sur rapport {rapport_id}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue: {e}")
                error_logger.critical(
                    f"Erreur inattendue application checklist pour {request.user.username} sur rapport {rapport_id}: {e}",
                    exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = ConformityChecklistForm(initial=initial_data, criteres=criteres)

    context = {
        'rapport': rapport,
        'sections': rapport.sectionrapport_set.all(),
        'form': form,
        'criteres': criteres,
    }
    return render(request, 'core/personnel/conformite_check_report.html', context)


@login_required
@user_passes_test(is_responsable_scolarite, login_url='dashboard_redirect')
def scolarite_dashboard(request):
    students_to_activate = Etudiant.objects.filter(est_eligible_soumission=False, utilisateur__is_active=True)
    pending_stages = Stage.objects.filter(est_valide=False)
    pending_penalties = Penalite.objects.filter(statut_penalite=StatutPenalite.DUE)
    recent_reclamations = Reclamation.objects.filter(
        statut__in=[StatutReclamation.OUVERTE, StatutReclamation.EN_COURS]).order_by('-date_soumission')[:10]

    context = {
        'students_to_activate': students_to_activate,
        'pending_stages': pending_stages,
        'pending_penalties': pending_penalties,
        'recent_reclamations': recent_reclamations,
    }
    return render(request, 'core/personnel/scolarite_dashboard.html', context)


@login_required
@user_passes_test(is_responsable_scolarite, login_url='dashboard_redirect')
def scolarite_activate_student_account(request, etudiant_id):
    etudiant = get_object_or_404(Etudiant, utilisateur__id=etudiant_id)
    if request.method == 'POST':
        try:
            ScolariteService.activate_student_account(etudiant, request.user.profil_personnel)
            messages.success(request, f"Le compte de l'étudiant {etudiant.nom_complet} a été activé.")
        except ValueError as e:
            messages.error(request, f"Impossible d'activer le compte : {e}")
            error_logger.error(
                f"Erreur activation compte étudiant {etudiant.nom_complet} par {request.user.username}: {e}")
        except Exception as e:
            messages.error(request, f"Une erreur inattendue est survenue : {e}")
            error_logger.critical(
                f"Erreur inattendue activation compte étudiant {etudiant.nom_complet} par {request.user.username}: {e}",
                exc_info=True)
    return redirect('scolarite_dashboard')


@login_required
@user_passes_test(is_responsable_scolarite, login_url='dashboard_redirect')
def scolarite_validate_stage(request, stage_id):
    stage = get_object_or_404(Stage, id=stage_id)
    if request.method == 'POST':
        try:
            ScolariteService.validate_stage(stage, request.user.profil_personnel)
            messages.success(request, f"Le stage de {stage.etudiant.nom_complet} a été validé.")
        except ValueError as e:
            messages.error(request, f"Impossible de valider le stage : {e}")
            error_logger.error(f"Erreur validation stage {stage.id} par {request.user.username}: {e}")
        except Exception as e:
            messages.error(request, f"Une erreur inattendue est survenue : {e}")
            error_logger.critical(f"Erreur inattendue validation stage {stage.id} par {request.user.username}: {e}",
                                  exc_info=True)
    return redirect('scolarite_dashboard')


@login_required
@user_passes_test(is_responsable_scolarite, login_url='dashboard_redirect')
def scolarite_manage_penalties(request):
    penalties = Penalite.objects.filter(statut_penalite=StatutPenalite.DUE).order_by('date_creation')
    context = {
        'penalties': penalties,
    }
    return render(request, 'core/personnel/scolarite_penalties.html', context)


@login_required
@user_passes_test(is_responsable_scolarite, login_url='dashboard_redirect')
def scolarite_record_penalty_payment(request, penalty_id):
    penalite = get_object_or_404(Penalite, id_penalite=penalty_id)
    if request.method == 'POST':
        try:
            ScolariteService.record_penalty_payment(penalite, request.user.profil_personnel)
            messages.success(request,
                             f"La pénalité {penalite.id_penalite} de {penalite.etudiant.nom_complet} a été marquée comme réglée.")
        except ValueError as e:
            messages.error(request, f"Impossible d'enregistrer le paiement : {e}")
            error_logger.error(f"Erreur enregistrement paiement pénalité {penalty_id} par {request.user.username}: {e}")
        except Exception as e:
            messages.error(request, f"Une erreur inattendue est survenue : {e}")
            error_logger.critical(
                f"Erreur inattendue enregistrement paiement pénalité {penalty_id} par {request.user.username}: {e}",
                exc_info=True)
    return redirect('scolarite_manage_penalties')


@login_required
@user_passes_test(is_responsable_scolarite, login_url='dashboard_redirect')
def scolarite_manage_notes(request):
    notes = Note.objects.all().order_by('etudiant__nom', 'annee_academique', 'ecue__libelle_ecue')
    if request.method == 'POST':
        form = NoteForm(request.POST)
        if form.is_valid():
            try:
                ScolariteService.enter_note(
                    etudiant=form.cleaned_data['etudiant'],
                    ecue=form.cleaned_data['ecue'],
                    annee_academique=form.cleaned_data['annee_academique'],
                    note_value=form.cleaned_data['note'],
                    date_evaluation=form.cleaned_data['date_evaluation']
                )
                messages.success(request, "Note enregistrée avec succès.")
                return redirect('scolarite_manage_notes')
            except ValueError as e:
                messages.error(request, f"Erreur lors de l'enregistrement de la note : {e}")
                error_logger.error(f"Erreur enregistrement note par {request.user.username}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(f"Erreur inattendue enregistrement note par {request.user.username}: {e}",
                                      exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = NoteForm()

    context = {
        'notes': notes,
        'form': form,
    }
    return render(request, 'core/personnel/scolarite_notes.html', context)


@login_required
@user_passes_test(is_responsable_scolarite, login_url='dashboard_redirect')
def scolarite_generate_document(request):
    etudiants = Etudiant.objects.all().order_by('nom')
    annees_academiques = AnneeAcademique.objects.all().order_by('-libelle_annee_academique')

    if request.method == 'POST':
        etudiant_id = request.POST.get('etudiant')
        annee_id = request.POST.get('annee_academique')
        doc_type = request.POST.get('document_type')

        etudiant = get_object_or_404(Etudiant, utilisateur__id=etudiant_id)
        annee_academique = get_object_or_404(AnneeAcademique, id_annee_academique=annee_id) if annee_id else None

        try:
            if doc_type == 'Bulletin':
                document = ScolariteService.generate_official_bulletin(etudiant, annee_academique,
                                                                       request.user.profil_personnel)
            elif doc_type == 'AttestationScolarite':
                document = ScolariteService.generate_administrative_document(etudiant, 'AttestationScolarite',
                                                                             request.user.profil_personnel,
                                                                             annee_academique=annee_academique)
            elif doc_type == 'RecuPaiement':
                document = ScolariteService.generate_administrative_document(etudiant, 'RecuPaiement',
                                                                             request.user.profil_personnel,
                                                                             annee_academique=annee_academique)
            else:
                raise ValueError("Type de document non valide.")

            messages.success(request, f"Document '{doc_type}' généré pour {etudiant.nom_complet}.")
            return redirect('scolarite_generate_document')
        except ValueError as e:
            messages.error(request, f"Erreur de génération de document : {e}")
            error_logger.error(f"Erreur génération document par {request.user.username}: {e}")
        except Exception as e:
            messages.error(request, f"Une erreur inattendue est survenue : {e}")
            error_logger.critical(f"Erreur inattendue génération document par {request.user.username}: {e}",
                                  exc_info=True)

    context = {
        'etudiants': etudiants,
        'annees_academiques': annees_academiques,
        'document_types': ['Bulletin', 'AttestationScolarite', 'RecuPaiement'],
    }
    return render(request, 'core/personnel/scolarite_generate_document.html', context)


@login_required
@user_passes_test(lambda u: is_responsable_scolarite(u) or is_admin_sys(u), login_url='dashboard_redirect')
def scolarite_reclamation_detail(request, reclamation_id):
    reclamation = get_object_or_404(Reclamation, id=reclamation_id)

    if request.method == 'POST':
        form = ReclamationResponseForm(request.POST, instance=reclamation)
        if form.is_valid():
            try:
                reclamation = form.save(commit=False)
                reclamation.date_resolution = timezone.now() if reclamation.statut == StatutReclamation.RESOLUE else None
                reclamation.save()
                messages.success(request, "Réclamation mise à jour avec succès.")
                audit_logger.info(f"Réclamation {reclamation_id} mise à jour par {request.user.username}.")
                return redirect('scolarite_dashboard')
            except Exception as e:
                messages.error(request, f"Erreur lors de la mise à jour de la réclamation : {e}")
                error_logger.error(f"Erreur mise à jour réclamation {reclamation_id} par {request.user.username}: {e}",
                                   exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = ReclamationResponseForm(instance=reclamation)

    context = {
        'reclamation': reclamation,
        'form': form,
    }
    return render(request, 'core/personnel/reclamation_detail.html', context)


# --- Vues Enseignant / Membre de Commission ---

@login_required
@user_passes_test(is_enseignant, login_url='dashboard_redirect')
def enseignant_dashboard(request):
    enseignant_profile = request.user.profil_enseignant

    rapports_directeur = RapportEtudiant.objects.filter(directeur_memoire=enseignant_profile).order_by(
        '-date_soumission')

    sessions_commission = SessionValidation.objects.filter(
        Q(president_session=enseignant_profile) | Q(membres=enseignant_profile)).distinct().order_by(
        '-date_debut_session')

    votes_en_attente = []
    if is_membre_commission(request.user):
        for session in sessions_commission.filter(statut_session=StatutSession.EN_COURS):
            for rapport in session.rapports.all():
                if not VoteCommission.objects.filter(session=session, rapport_etudiant=rapport,
                                                     enseignant=enseignant_profile).exists():
                    votes_en_attente.append({'session': session, 'rapport': rapport})

    context = {
        'enseignant': enseignant_profile,
        'rapports_directeur': rapports_directeur,
        'sessions_commission': sessions_commission,
        'votes_en_attente': votes_en_attente,
    }
    return render(request, 'core/enseignant/dashboard.html', context)


@login_required
@user_passes_test(is_membre_commission, login_url='dashboard_redirect')
def commission_session_list(request):
    sessions = SessionValidation.objects.all().order_by('-date_debut_session')
    context = {
        'sessions': sessions,
    }
    return render(request, 'core/commission/session_list.html', context)


@login_required
@user_passes_test(is_membre_commission, login_url='dashboard_redirect')
def commission_session_create(request):
    if request.method == 'POST':
        form = SessionValidationForm(request.POST)
        if form.is_valid():
            try:
                president_enseignant = form.cleaned_data['president_session']

                rapport_ids = [r.id_rapport_etudiant for r in form.cleaned_data['rapports']]
                member_user_ids = [m.utilisateur.id for m in form.cleaned_data['membres']]

                session = CommissionService.create_session(
                    president=president_enseignant,
                    name=form.cleaned_data['nom_session'],
                    mode=form.cleaned_data['mode_session'],
                    start_date=form.cleaned_data['date_debut_session'],
                    end_date=form.cleaned_data['date_fin_prevue'],
                    rapport_ids=rapport_ids,
                    member_user_ids=member_user_ids,
                    required_voters=form.cleaned_data['nombre_votants_requis']
                )
                messages.success(request, f"Session '{session.nom_session}' créée avec succès.")
                return redirect('commission_session_detail', session_id=session.id_session)
            except ValueError as e:
                messages.error(request, f"Erreur lors de la création de la session : {e}")
                error_logger.error(f"Erreur création session par {request.user.username}: {e}")
            except PermissionError as e:
                messages.error(request, f"Permission refusée : {e}")
                error_logger.error(f"Permission refusée création session par {request.user.username}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(f"Erreur inattendue création session par {request.user.username}: {e}",
                                      exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = SessionValidationForm()
    context = {
        'form': form,
    }
    return render(request, 'core/commission/session_create.html', context)


@login_required
@user_passes_test(is_membre_commission, login_url='dashboard_redirect')
def commission_session_detail(request, session_id):
    session = get_object_or_404(SessionValidation, id_session=session_id)
    if not is_admin_sys(request.user) and request.user.profil_enseignant not in session.membres.all():
        raise PermissionDenied("Vous n'êtes pas autorisé à voir les détails de cette session.")

    rapports_data = CommissionService.get_session_progress(session)

    context = {
        'session': session,
        'rapports_data': rapports_data,
        'is_president': session.president_session.utilisateur == request.user,
    }
    return render(request, 'core/commission/session_detail.html', context)


@login_required
@user_passes_test(is_membre_commission, login_url='dashboard_redirect')
def commission_session_action(request, session_id, action):
    session = get_object_or_404(SessionValidation, id_session=session_id)
    if session.president_session.utilisateur != request.user and not is_admin_sys(request.user):
        raise PermissionDenied("Seul le président de session ou un administrateur peut effectuer cette action.")

    try:
        if action == 'start':
            CommissionService.start_session(session)
            messages.success(request, f"La session '{session.nom_session}' a été démarrée.")
        elif action == 'close':
            CommissionService.close_session(session)
            messages.success(request, f"La session '{session.nom_session}' a été clôturée.")
        else:
            raise Http404("Action non valide.")
    except ValueError as e:
        messages.error(request, f"Erreur : {e}")
        error_logger.error(
            f"Erreur action session '{action}' par {request.user.username} sur session {session_id}: {e}")
    except Exception as e:
        messages.error(request, f"Une erreur inattendue est survenue : {e}")
        error_logger.critical(f"Erreur inattendue action session '{action}' par {request.user.username}: {e}",
                              exc_info=True)

    return redirect('commission_session_detail', session_id=session.id_session)


@login_required
@user_passes_test(is_membre_commission, login_url='dashboard_redirect')
def commission_rapport_vote(request, session_id, rapport_id):
    session = get_object_or_404(SessionValidation, id_session=session_id)
    rapport = get_object_or_404(RapportEtudiant, id_rapport_etudiant=rapport_id)
    enseignant_profile = request.user.profil_enseignant

    if session.statut_session != StatutSession.EN_COURS:
        messages.error(request, "Le vote n'est possible que pour une session en cours.")
        return redirect('commission_session_detail', session_id=session.id_session)
    if enseignant_profile not in session.membres.all():
        raise PermissionDenied("Vous n'êtes pas membre de cette session.")
    if rapport not in session.rapports.all():
        raise Http404("Le rapport n'appartient pas à cette session.")

    if request.method == 'POST':
        form = VoteCommissionForm(request.POST)
        if form.is_valid():
            decision = form.cleaned_data['decision']
            commentaire = form.cleaned_data['commentaire']
            try:
                CommissionService.submit_vote(session, rapport, enseignant_profile, decision, commentaire)
                messages.success(request, "Votre vote a été enregistré.")
                return redirect('commission_session_detail', session_id=session.id_session)
            except ValueError as e:
                messages.error(request, f"Erreur lors de l'enregistrement du vote : {e}")
                error_logger.error(
                    f"Erreur vote par {request.user.username} sur rapport {rapport_id} session {session_id}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(
                    f"Erreur inattendue vote par {request.user.username} sur rapport {rapport_id} session {session_id}: {e}",
                    exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = VoteCommissionForm()

    context = {
        'session': session,
        'rapport': rapport,
        'form': form,
    }
    return render(request, 'core/commission/rapport_vote.html', context)


@login_required
@user_passes_test(is_membre_commission, login_url='dashboard_redirect')
def commission_pv_manage(request, session_id):
    session = get_object_or_404(SessionValidation, id_session=session_id)
    if not is_admin_sys(request.user) and request.user.profil_enseignant not in session.membres.all():
        raise PermissionDenied("Vous n'êtes pas autorisé à gérer le PV de cette session.")

    pv = ProcesVerbal.objects.filter(session=session).first()
    is_redacteur = pv and pv.redacteur.utilisateur == request.user

    if request.method == 'POST':
        if 'initiate_pv' in request.POST:
            if pv:
                messages.warning(request, "Un PV existe déjà pour cette session.")
                return redirect('commission_pv_manage', session_id=session_id)
            try:
                CommissionService.initiate_pv_draft(session, request.user.profil_enseignant)
                messages.success(request, "Brouillon de Procès-Verbal initié.")
                return redirect('commission_pv_manage', session_id=session_id)
            except Exception as e:
                messages.error(request, f"Erreur lors de l'initialisation du PV : {e}")
                error_logger.error(f"Erreur init PV par {request.user.username} sur session {session_id}: {e}")

        if pv and is_redacteur and pv.statut_pv in [StatutPV.BROUILLON, StatutPV.REJETE]:
            form = ProcesVerbalForm(request.POST, instance=pv)
            if form.is_valid():
                try:
                    CommissionService.update_pv_content(pv, form.cleaned_data['libelle_compte_rendu'])
                    if 'submit_for_approval' in request.POST:
                        CommissionService.submit_pv_for_approval(pv)
                        messages.success(request, "PV soumis à approbation.")
                    else:
                        messages.success(request, "Contenu du PV sauvegardé.")
                    return redirect('commission_pv_manage', session_id=session_id)
                except ValueError as e:
                    messages.error(request, f"Erreur de sauvegarde/soumission du PV : {e}")
                    error_logger.error(
                        f"Erreur save/submit PV par {request.user.username} sur PV {pv.id_compte_rendu}: {e}")
                except Exception as e:
                    messages.error(request, f"Une erreur inattendue est survenue : {e}")
                    error_logger.critical(
                        f"Erreur inattendue save/submit PV par {request.user.username} sur PV {pv.id_compte_rendu}: {e}",
                        exc_info=True)
            else:
                messages.error(request, "Veuillez corriger les erreurs du formulaire.")
        else:
            messages.error(request, "Action non autorisée ou PV non modifiable.")

    if pv:
        form = ProcesVerbalForm(instance=pv)
        pv_approvals = pv.validationpv_set.all()
        approval_form = PVApprovalForm()
    else:
        form = None
        pv_approvals = []
        approval_form = None

    context = {
        'session': session,
        'pv': pv,
        'form': form,
        'is_redacteur': is_redacteur,
        'pv_approvals': pv_approvals,
        'approval_form': approval_form,
        'is_president': session.president_session.utilisateur == request.user,
    }
    return render(request, 'core/commission/pv_manage.html', context)


@login_required
@user_passes_test(is_membre_commission, login_url='dashboard_redirect')
def commission_pv_approve_request(request, pv_id):
    pv = get_object_or_404(ProcesVerbal, id_compte_rendu=pv_id)
    enseignant_profile = request.user.profil_enseignant

    if enseignant_profile not in pv.session.membres.all():
        raise PermissionDenied("Vous n'êtes pas membre de la session de ce PV.")
    if pv.redacteur == enseignant_profile:
        messages.warning(request, "Le rédacteur ne peut pas approuver ou demander de modification sur son propre PV.")
        return redirect('commission_pv_manage', session_id=pv.session.id_session)

    if request.method == 'POST':
        form = PVApprovalForm(request.POST)
        if form.is_valid():
            decision = form.cleaned_data['decision']
            commentaire = form.cleaned_data['commentaire']
            try:
                if decision == DecisionValidationPV.APPROUVE:
                    CommissionService.approve_pv(pv, enseignant_profile, commentaire)
                    messages.success(request, "Votre approbation a été enregistrée.")
                elif decision == DecisionValidationPV.MODIF_DEMANDEE:
                    CommissionService.request_pv_modification(pv, enseignant_profile, commentaire)
                    messages.success(request, "Votre demande de modification a été enregistrée.")
                return redirect('commission_pv_manage', session_id=pv.session.id_session)
            except ValueError as e:
                messages.error(request, f"Erreur : {e}")
                error_logger.error(
                    f"Erreur approbation/demande modif PV par {request.user.username} sur PV {pv_id}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(
                    f"Erreur inattendue approbation/demande modif PV par {request.user.username} sur PV {pv_id}: {e}",
                    exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        messages.error(request, "Méthode non autorisée.")
    return redirect('commission_pv_manage', session_id=pv.session.id_session)


@login_required
@user_passes_test(is_membre_commission, login_url='dashboard_redirect')
def commission_pv_finalize(request, pv_id):
    pv = get_object_or_404(ProcesVerbal, id_compte_rendu=pv_id)
    if pv.session.president_session.utilisateur != request.user and not is_admin_sys(request.user):
        raise PermissionDenied("Seul le président de session ou un administrateur peut finaliser le PV.")

    if pv.statut_pv != StatutPV.ATTENTE_APPROBATION:
        messages.error(request,
                       f"Le PV n'est pas en attente d'approbation et ne peut pas être finalisé (statut actuel: {pv.get_statut_pv_display()}).")
        return redirect('commission_pv_manage', session_id=pv.session.id_session)

    required_approvals = pv.session.membres.count() - (1 if pv.redacteur in pv.session.membres.all() else 0)
    current_approvals = pv.validationpv_set.filter(decision_validation_pv=DecisionValidationPV.APPROUVE).count()
    if current_approvals < required_approvals:
        messages.error(request,
                       f"Impossible de finaliser le PV. {required_approvals - current_approvals} approbation(s) manquante(s).")
        return redirect('commission_pv_manage', session_id=pv.session.id_session)

    if request.method == 'POST':
        try:
            CommissionService.finalize_pv(pv)
            messages.success(request, f"Le Procès-Verbal '{pv.id_compte_rendu}' a été finalisé et diffusé.")
        except ValueError as e:
            messages.error(request, f"Erreur lors de la finalisation du PV : {e}")
            error_logger.error(f"Erreur finalisation PV par {request.user.username}: {e}")
        except Exception as e:
            messages.error(request, f"Une erreur inattendue est survenue : {e}")
            error_logger.critical(f"Erreur inattendue finalisation PV par {request.user.username}: {e}", exc_info=True)
    return redirect('commission_pv_manage', session_id=pv.session.id_session)


# --- Vues Administrateur Système ---

@login_required
@user_passes_test(is_admin_sys, login_url='dashboard_redirect')
def admin_dashboard(request):
    total_users = User.objects.count()
    active_students = Etudiant.objects.filter(utilisateur__is_active=True).count()
    reports_submitted_this_year = RapportEtudiant.objects.filter(date_soumission__year=timezone.now().year).count()

    system_metrics = ReportingService.get_system_health_metrics()

    context = {
        'total_users': total_users,
        'active_students': active_students,
        'reports_submitted_this_year': reports_submitted_this_year,
        'system_metrics': system_metrics,
    }
    return render(request, 'core/admin/dashboard.html', context)


@login_required
@user_passes_test(is_admin_sys, login_url='dashboard_redirect')
def admin_user_management(request):
    users = User.objects.all().order_by('username')

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            try:
                AdminService.create_user_with_profile(
                    username=form.cleaned_data['username'],
                    password=form.cleaned_data['password'],
                    first_name=form.cleaned_data['first_name'],
                    last_name=form.cleaned_data['last_name'],
                    email=form.cleaned_data['email'],
                    profile_type=form.cleaned_data['profile_type'],
                    group_name=form.cleaned_data['group_name']
                )
                messages.success(request, f"Utilisateur {form.cleaned_data['username']} créé avec succès.")
                return redirect('admin_user_management')
            except ValueError as e:
                messages.error(request, f"Erreur de création d'utilisateur : {e}")
                error_logger.error(f"Erreur création utilisateur par {request.user.username}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(f"Erreur inattendue création utilisateur par {request.user.username}: {e}",
                                      exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = UserCreationForm()

    context = {
        'users': users,
        'form': form,
    }
    return render(request, 'core/admin/user_management.html', context)


@login_required
@user_passes_test(is_admin_sys, login_url='dashboard_redirect')
def admin_user_detail(request, user_id):
    user_obj = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        if 'assign_role' in request.POST:
            new_group_name = request.POST.get('new_group_name')
            try:
                AdminService.assign_role_to_user(user_obj, new_group_name)
                messages.success(request, f"Rôle de {user_obj.username} mis à jour vers {new_group_name}.")
            except ValueError as e:
                messages.error(request, f"Erreur d'assignation de rôle : {e}")
                error_logger.error(f"Erreur assignation rôle par {request.user.username} à {user_obj.username}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(
                    f"Erreur inattendue assignation rôle par {request.user.username} à {user_obj.username}: {e}",
                    exc_info=True)
        elif 'deactivate_account' in request.POST:
            try:
                AuthentificationService.deactivate_account(user_obj)
                messages.success(request, f"Compte de {user_obj.username} désactivé.")
            except Exception as e:
                messages.error(request, f"Erreur de désactivation : {e}")
                error_logger.error(f"Erreur désactivation compte {user_obj.username} par {request.user.username}: {e}")
        elif 'activate_account' in request.POST:
            try:
                AuthentificationService.activate_account(user_obj)
                messages.success(request, f"Compte de {user_obj.username} activé.")
            except Exception as e:
                messages.error(request, f"Erreur d'activation : {e}")
                error_logger.error(f"Erreur activation compte {user_obj.username} par {request.user.username}: {e}")
        elif 'reset_password_admin' in request.POST:
            new_password = User.objects.make_random_password()
            try:
                AuthentificationService.reset_password(user_obj, new_password)
                messages.success(request,
                                 f"Mot de passe de {user_obj.username} réinitialisé. Nouveau mot de passe: {new_password} (à communiquer en toute sécurité).")
            except Exception as e:
                messages.error(request, f"Erreur de réinitialisation de mot de passe : {e}")
                error_logger.error(f"Erreur reset password {user_obj.username} par {request.user.username}: {e}")

        return redirect('admin_user_detail', user_id=user_id)

    context = {
        'user_obj': user_obj,
        'current_role': user_obj.groups.first().name if user_obj.groups.exists() else 'Aucun',
        'all_groups': Group.objects.all(),
    }
    return render(request, 'core/admin/user_detail.html', context)


@login_required
@user_passes_test(is_admin_sys, login_url='dashboard_redirect')
def admin_delegation_management(request):
    delegations = Delegation.objects.all().order_by('-date_debut')

    if request.method == 'POST':
        form = DelegationForm(request.POST)
        if form.is_valid():
            try:
                AdminService.delegate_responsibilities(
                    delegant=form.cleaned_data['delegant'],
                    delegue=form.cleaned_data['delegue'],
                    permissions_list=form.cleaned_data['permissions_delegues'],
                    start_date=form.cleaned_data['date_debut'],
                    end_date=form.cleaned_data['date_fin']
                )
                messages.success(request, "Délégation créée avec succès.")
                return redirect('admin_delegation_management')
            except ValueError as e:
                messages.error(request, f"Erreur de création de délégation : {e}")
                error_logger.error(f"Erreur création délégation par {request.user.username}: {e}")
            except Exception as e:
                messages.error(request, f"Une erreur inattendue est survenue : {e}")
                error_logger.critical(f"Erreur inattendue création délégation par {request.user.username}: {e}",
                                      exc_info=True)
        else:
            messages.error(request, "Veuillez corriger les erreurs du formulaire.")
    else:
        form = DelegationForm()

    context = {
        'delegations': delegations,
        'form': form,
    }
    return render(request, 'core/admin/delegation_management.html', context)


@login_required
@user_passes_test(is_admin_sys, login_url='dashboard_redirect')
def admin_import_data(request):
    if request.method == 'POST':
        file = request.FILES.get('import_file')
        entity_type = request.POST.get('entity_type')

        if not file:
            messages.error(request, "Veuillez sélectionner un fichier à importer.")
            return redirect('admin_import_data')

        file_path = os.path.join(settings.MEDIA_ROOT, 'temp_imports', file.name)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'wb+') as destination:
            for chunk in file.chunks():
                destination.write(chunk)

        try:
            column_mapping = {}
            AdminService.import_data_from_file(file_path, entity_type, column_mapping, request.user)
            messages.success(request, "Importation lancée. Vous recevrez une notification une fois terminée.")
        except ValueError as e:
            messages.error(request, f"Erreur d'importation : {e}")
            error_logger.error(f"Erreur importation données par {request.user.username}: {e}")
        except Exception as e:
            messages.error(request, f"Une erreur inattendue est survenue : {e}")
            error_logger.critical(f"Erreur inattendue importation données par {request.user.username}: {e}",
                                  exc_info=True)

        return redirect('admin_import_data')

    context = {
        'entity_types': ['Etudiant', 'Enseignant', 'PersonnelAdministratif'],
    }
    return render(request, 'core/admin/import_data.html', context)


@login_required
@user_passes_test(is_admin_sys, login_url='dashboard_redirect')
def admin_audit_logs(request):
    filters = {}
    user_id = request.GET.get('user_id')
    event_type = request.GET.get('event_type')
    start_date_str = request.GET.get('start_date')
    end_date_str = request.GET.get('end_date')

    if user_id:
        filters['user_id'] = user_id
    if event_type:
        filters['event_type'] = event_type
    if start_date_str:
        try:
            filters['start_date'] = datetime.datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            messages.error(request, "Format de date de début invalide (YYYY-MM-DD).")
    if end_date_str:
        try:
            filters['end_date'] = datetime.datetime.strptime(end_date_str, '%Y-%m-%d').date()
        except ValueError:
            messages.error(request, "Format de date de fin invalide (YYYY-MM-DD).")

    logs = AdminService.get_audit_logs(filters)
    users = User.objects.all().order_by('username')
    event_types = Notification.objects.values_list('type_notification', flat=True).distinct()

    context = {
        'logs': logs,
        'users': users,
        'event_types': event_types,
        'current_filters': request.GET,
    }
    return render(request, 'core/admin/audit_logs.html', context)


@login_required
@user_passes_test(is_admin_sys, login_url='dashboard_redirect')
def admin_system_health(request):
    metrics = ReportingService.get_system_health_metrics()
    context = {
        'metrics': metrics,
    }
    return render(request, 'core/admin/system_health.html', context)


@login_required
@user_passes_test(is_admin_sys, login_url='dashboard_redirect')
def admin_reporting(request):
    annees_academiques = AnneeAcademique.objects.all().order_by('-libelle_annee_academique')
    specialites = Specialite.objects.all().order_by('libelle_specialite')

    validation_report = None
    if request.method == 'POST' and 'generate_validation_report' in request.POST:
        annee_id = request.POST.get('annee_academique')
        specialite_id = request.POST.get('specialite')

        selected_annee = get_object_or_404(AnneeAcademique, id_annee_academique=annee_id) if annee_id else None
        selected_specialite = get_object_or_404(Specialite, id_specialite=specialite_id) if specialite_id else None

        try:
            validation_report = ReportingService.generate_validation_rate_report(selected_annee, selected_specialite)
            messages.success(request, "Rapport de taux de validation généré.")
        except Exception as e:
            messages.error(request, f"Erreur lors de la génération du rapport : {e}")
            error_logger.error(f"Erreur génération rapport validation par {request.user.username}: {e}", exc_info=True)

    context = {
        'annees_academiques': annees_academiques,
        'specialites': specialites,
        'validation_report': validation_report,
    }
    return render(request, 'core/admin/reporting.html', context)


@login_required
def download_document(request, doc_id):
    document = get_object_or_404(DocumentOfficiel, id_document=doc_id)

    if is_etudiant(request.user) and document.etudiant != request.user.profil_etudiant:
        raise PermissionDenied("Vous n'êtes pas autorisé à télécharger ce document.")
    elif not is_admin_sys(request.user) and not is_responsable_scolarite(request.user) and not is_membre_commission(
            request.user) and not is_etudiant(request.user):
        raise PermissionDenied("Vous n'êtes pas autorisé à télécharger des documents.")

    file_path = os.path.join(settings.MEDIA_ROOT, document.chemin_fichier)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as fh:
            response = HttpResponse(fh.read(), content_type="application/pdf")
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            audit_logger.info(f"Document '{doc_id}' téléchargé par {request.user.username}.")
            return response
    else:
        messages.error(request, "Le fichier demandé n'existe pas sur le serveur.")
        error_logger.error(f"Fichier non trouvé pour le document {doc_id} à {file_path}.")
        raise Http404("Le document n'existe pas.")
