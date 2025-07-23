from django.urls import path, include
from . import views # <-- Cette ligne est cruciale et doit être présente
# from django.contrib.auth import views as auth_views # Commenté car non directement utilisé par nos vues personnalisées

urlpatterns = [
    # --- Vues d'Authentification ---
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('password_reset/', views.password_reset_request, name='password_reset_request'),
    # Django's built-in password reset confirm view (requires specific setup in settings and templates)
    # path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='core/auth/password_reset_confirm.html', form_class=SetNewPasswordForm), name='password_reset_confirm'),
    path('validate-email/', views.email_validation_confirm, name='email_validation_confirm'),
    path('2fa/setup/', views.two_factor_setup, name='two_factor_setup'),
    path('2fa/verify/', views.two_factor_verify, name='two_factor_verify'),
    path('2fa/disable/', views.disable_2fa, name='disable_2fa'),

    # --- Vues Communes ---
    path('dashboard/', views.dashboard_redirect, name='dashboard_redirect'),
    path('profile/', views.user_profile, name='user_profile'),
    path('documents/<str:doc_id>/download/', views.download_document, name='download_document'),

    # --- Vues Étudiant ---
    path('etudiant/dashboard/', views.etudiant_dashboard, name='etudiant_dashboard'),
    path('etudiant/rapports/creer/', views.rapport_create_or_edit, name='rapport_create'),
    path('etudiant/rapports/<str:rapport_id>/modifier/', views.rapport_create_or_edit, name='rapport_edit'),
    path('etudiant/rapports/<str:rapport_id>/suivi/', views.rapport_suivi, name='rapport_suivi'),
    path('etudiant/documents/', views.etudiant_documents, name='etudiant_documents'),
    path('etudiant/reclamations/', views.etudiant_reclamations, name='etudiant_reclamations'),

    # --- Vues Personnel Administratif ---
    path('personnel/dashboard/', views.personnel_dashboard, name='personnel_dashboard'),
    path('personnel/conformite/dashboard/', views.conformite_dashboard, name='conformite_dashboard'),
    path('personnel/conformite/rapport/<str:rapport_id>/verifier/', views.conformite_check_report, name='conformite_check_report'),
    path('personnel/scolarite/dashboard/', views.scolarite_dashboard, name='scolarite_dashboard'),
    path('personnel/scolarite/etudiant/<int:etudiant_id>/activer/', views.scolarite_activate_student_account, name='scolarite_activate_student_account'),
    path('personnel/scolarite/stage/<int:stage_id>/valider/', views.scolarite_validate_stage, name='scolarite_validate_stage'),
    path('personnel/scolarite/penalites/', views.scolarite_manage_penalties, name='scolarite_manage_penalties'),
    path('personnel/scolarite/penalites/<str:penalty_id>/regler/', views.scolarite_record_penalty_payment, name='scolarite_record_penalty_payment'),
    path('personnel/scolarite/notes/', views.scolarite_manage_notes, name='scolarite_manage_notes'),
    path('personnel/scolarite/documents/generer/', views.scolarite_generate_document, name='scolarite_generate_document'),
    path('personnel/reclamations/<int:reclamation_id>/', views.scolarite_reclamation_detail, name='scolarite_reclamation_detail'),

    # --- Vues Enseignant / Membre de Commission ---
    path('enseignant/dashboard/', views.enseignant_dashboard, name='enseignant_dashboard'),
    path('commission/sessions/', views.commission_session_list, name='commission_session_list'),
    path('commission/sessions/creer/', views.commission_session_create, name='commission_session_create'),
    path('commission/sessions/<str:session_id>/detail/', views.commission_session_detail, name='commission_session_detail'),
    path('commission/sessions/<str:session_id>/<str:action>/', views.commission_session_action, name='commission_session_action'),
    path('commission/sessions/<str:session_id>/rapports/<str:rapport_id>/voter/', views.commission_rapport_vote, name='commission_rapport_vote'),
    path('commission/sessions/<str:session_id>/pv/', views.commission_pv_manage, name='commission_pv_manage'),
    path('commission/pv/<str:pv_id>/approuver_demander/', views.commission_pv_approve_request, name='commission_pv_approve_request'),
    path('commission/pv/<str:pv_id>/finaliser/', views.commission_pv_finalize, name='commission_pv_finalize'),

    # --- Vues Administrateur Système ---
    path('admin_sys/dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('admin_sys/users/', views.admin_user_management, name='admin_user_management'),
    path('admin_sys/users/<int:user_id>/', views.admin_user_detail, name='admin_user_detail'),
    path('admin_sys/delegations/', views.admin_delegation_management, name='admin_delegation_management'),
    path('admin_sys/import/', views.admin_import_data, name='admin_import_data'),
    path('admin_sys/logs/', views.admin_audit_logs, name='admin_audit_logs'),
    path('admin_sys/health/', views.admin_system_health, name='admin_system_health'),
    path('admin_sys/reporting/', views.admin_reporting, name='admin_reporting'),
]