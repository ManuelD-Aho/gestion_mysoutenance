from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm, SetPasswordForm
from django.contrib.auth.models import User, Group, Permission
# Importation manquante : Enseignant
from .models import RapportEtudiant, SectionRapport, CritereConformite, Stage, Penalite, Inscription, Note, Ecue, AnneeAcademique, NiveauEtude, Specialite, Entreprise, SessionValidation, ProcesVerbal, Delegation, Reclamation, Etudiant, Enseignant # Ajout de Enseignant
from .enums import StatutRapport, StatutConformite, DecisionVote, StatutPV, DecisionValidationPV, StatutPaiement, TypePenalite, StatutPenalite, StatutReclamation, ModeSession, StatutSession

class LoginForm(AuthenticationForm):
    username = forms.CharField(label="Nom d'utilisateur", max_length=150, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(label="Mot de passe", widget=forms.PasswordInput(attrs={'class': 'form-control'}))

class PasswordResetEmailForm(PasswordResetForm):
    email = forms.EmailField(label="Adresse email", max_length=254, widget=forms.EmailInput(attrs={'class': 'form-control'}))

class SetNewPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(label="Nouveau mot de passe", widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    new_password2 = forms.CharField(label="Confirmer le nouveau mot de passe", widget=forms.PasswordInput(attrs={'class': 'form-control'}))

class TwoFactorSetupForm(forms.Form):
    code = forms.CharField(label="Code de vérification (TOTP)", max_length=6, widget=forms.TextInput(attrs={'class': 'form-control'}))

class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }

class EtudiantProfileForm(forms.ModelForm):
    class Meta:
        model = Etudiant
        fields = ['telephone', 'email_contact_secondaire', 'adresse_postale', 'contact_urgence_nom', 'contact_urgence_telephone']
        widgets = {
            'telephone': forms.TextInput(attrs={'class': 'form-control'}),
            'email_contact_secondaire': forms.EmailInput(attrs={'class': 'form-control'}),
            'adresse_postale': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'contact_urgence_nom': forms.TextInput(attrs={'class': 'form-control'}),
            'contact_urgence_telephone': forms.TextInput(attrs={'class': 'form-control'}),
        }

class RapportEtudiantForm(forms.ModelForm):
    class Meta:
        model = RapportEtudiant
        fields = ['libelle_rapport_etudiant', 'theme', 'nombre_pages', 'stage']
        widgets = {
            'libelle_rapport_etudiant': forms.TextInput(attrs={'class': 'form-control'}),
            'theme': forms.TextInput(attrs={'class': 'form-control'}),
            'nombre_pages': forms.NumberInput(attrs={'class': 'form-control'}),
            'stage': forms.Select(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        etudiant = kwargs.pop('etudiant', None)
        super().__init__(*args, **kwargs)
        if etudiant:
            self.fields['stage'].queryset = Stage.objects.filter(etudiant=etudiant)
            self.fields['stage'].empty_label = "Sélectionnez un stage"

class SectionRapportForm(forms.ModelForm):
    class Meta:
        model = SectionRapport
        fields = ['titre_section', 'contenu_section', 'ordre']
        widgets = {
            'titre_section': forms.TextInput(attrs={'class': 'form-control'}),
            'contenu_section': forms.Textarea(attrs={'class': 'form-control wysiwyg-editor', 'rows': 10}),
            'ordre': forms.NumberInput(attrs={'class': 'form-control'}),
        }

class ConformityChecklistForm(forms.Form):
    def __init__(self, *args, **kwargs):
        criteres = kwargs.pop('criteres', [])
        super().__init__(*args, **kwargs)
        for critere in criteres:
            self.fields[f'critere_{critere.id_critere}_statut'] = forms.ChoiceField(
                label=critere.libelle_critere,
                choices=StatutConformite.choices,
                widget=forms.Select(attrs={'class': 'form-control'}),
                required=True
            )
            self.fields[f'critere_{critere.id_critere}_commentaire'] = forms.CharField(
                label="Commentaire",
                widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
                required=False
            )

    def clean(self):
        cleaned_data = super().clean()
        results = {}
        for field_name, value in cleaned_data.items():
            if field_name.startswith('critere_') and field_name.endswith('_statut'):
                critere_id = field_name.replace('critere_', '').replace('_statut', '')
                status = value
                comment = cleaned_data.get(f'critere_{critere_id}_commentaire', '')
                results[critere_id] = {'statut_validation': status, 'commentaire': comment}
        self.cleaned_data['checklist_results'] = results
        return cleaned_data

class RapportCorrectionForm(forms.Form):
    correction_note = forms.CharField(
        label="Note explicative des corrections apportées",
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        required=True
    )

class SessionValidationForm(forms.ModelForm):
    rapports = forms.ModelMultipleChoiceField(
        queryset=RapportEtudiant.objects.filter(statut_rapport=StatutRapport.CONFORME),
        widget=forms.CheckboxSelectMultiple,
        label="Rapports à inclure",
        required=False
    )
    membres = forms.ModelMultipleChoiceField(
        queryset=Enseignant.objects.all(),
        widget=forms.CheckboxSelectMultiple,
        label="Membres de la commission",
        required=True
    )

    class Meta:
        model = SessionValidation
        fields = ['nom_session', 'date_debut_session', 'date_fin_prevue', 'president_session', 'mode_session', 'nombre_votants_requis', 'rapports', 'membres']
        widgets = {
            'nom_session': forms.TextInput(attrs={'class': 'form-control'}),
            'date_debut_session': forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}),
            'date_fin_prevue': forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}),
            'president_session': forms.Select(attrs={'class': 'form-control'}),
            'mode_session': forms.Select(attrs={'class': 'form-control'}),
            'nombre_votants_requis': forms.NumberInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['president_session'].queryset = Enseignant.objects.all()

class VoteCommissionForm(forms.Form):
    decision = forms.ChoiceField(
        label="Décision",
        choices=DecisionVote.choices,
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=True
    )
    commentaire = forms.CharField(
        label="Commentaire (obligatoire si non 'Approuvé')",
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        required=False
    )

    def clean(self):
        cleaned_data = super().clean()
        decision = cleaned_data.get('decision')
        commentaire = cleaned_data.get('commentaire')

        if decision != DecisionVote.APPROUVE and not commentaire:
            self.add_error('commentaire', "Un commentaire est obligatoire pour toute décision autre que 'Approuvé'.")
        return cleaned_data

class ProcesVerbalForm(forms.ModelForm):
    class Meta:
        model = ProcesVerbal
        fields = ['libelle_compte_rendu']
        widgets = {
            'libelle_compte_rendu': forms.Textarea(attrs={'class': 'form-control wysiwyg-editor', 'rows': 15}),
        }

class PVApprovalForm(forms.Form):
    decision = forms.ChoiceField(
        label="Décision",
        choices=[(DecisionValidationPV.APPROUVE, 'Approuver'), (DecisionValidationPV.MODIF_DEMANDEE, 'Demander une modification')],
        widget=forms.RadioSelect,
        required=True
    )
    commentaire = forms.CharField(
        label="Commentaire (obligatoire si 'Demander une modification')",
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        required=False
    )

    def clean(self):
        cleaned_data = super().clean()
        decision = cleaned_data.get('decision')
        commentaire = cleaned_data.get('commentaire')

        if decision == DecisionValidationPV.MODIF_DEMANDEE and not commentaire:
            self.add_error('commentaire', "Un commentaire est obligatoire si vous demandez une modification.")
        return cleaned_data

class InscriptionForm(forms.ModelForm):
    class Meta:
        model = Inscription
        fields = ['etudiant', 'niveau_etude', 'annee_academique', 'montant_inscription', 'date_inscription', 'statut_paiement', 'date_paiement', 'decision_passage']
        widgets = {
            'etudiant': forms.Select(attrs={'class': 'form-control'}),
            'niveau_etude': forms.Select(attrs={'class': 'form-control'}),
            'annee_academique': forms.Select(attrs={'class': 'form-control'}),
            'montant_inscription': forms.NumberInput(attrs={'class': 'form-control'}),
            'date_inscription': forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}),
            'statut_paiement': forms.Select(attrs={'class': 'form-control'}),
            'date_paiement': forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}),
            'decision_passage': forms.Select(attrs={'class': 'form-control'}),
        }

class StageForm(forms.ModelForm):
    class Meta:
        model = Stage
        fields = ['etudiant', 'entreprise', 'date_debut_stage', 'date_fin_stage', 'sujet_stage', 'nom_tuteur_entreprise', 'est_valide']
        widgets = {
            'etudiant': forms.Select(attrs={'class': 'form-control'}),
            'entreprise': forms.Select(attrs={'class': 'form-control'}),
            'date_debut_stage': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'date_fin_stage': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'sujet_stage': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'nom_tuteur_entreprise': forms.TextInput(attrs={'class': 'form-control'}),
            'est_valide': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

class PenaliteForm(forms.ModelForm):
    class Meta:
        model = Penalite
        fields = ['etudiant', 'annee_academique', 'type_penalite', 'montant_du', 'motif', 'statut_penalite']
        widgets = {
            'etudiant': forms.Select(attrs={'class': 'form-control'}),
            'annee_academique': forms.Select(attrs={'class': 'form-control'}),
            'type_penalite': forms.Select(attrs={'class': 'form-control'}),
            'montant_du': forms.NumberInput(attrs={'class': 'form-control'}),
            'motif': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'statut_penalite': forms.Select(attrs={'class': 'form-control'}),
        }

class NoteForm(forms.ModelForm):
    class Meta:
        model = Note
        fields = ['etudiant', 'ecue', 'annee_academique', 'note', 'date_evaluation']
        widgets = {
            'etudiant': forms.Select(attrs={'class': 'form-control'}),
            'ecue': forms.Select(attrs={'class': 'form-control'}),
            'annee_academique': forms.Select(attrs={'class': 'form-control'}),
            'note': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'min': '0', 'max': '20'}),
            'date_evaluation': forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}),
        }

class ReclamationForm(forms.ModelForm):
    class Meta:
        model = Reclamation
        fields = ['sujet', 'description']
        widgets = {
            'sujet': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        }

class ReclamationResponseForm(forms.ModelForm):
    class Meta:
        model = Reclamation
        fields = ['statut', 'assigne_a', 'commentaire_resolution']
        widgets = {
            'statut': forms.Select(attrs={'class': 'form-control'}),
            'assigne_a': forms.Select(attrs={'class': 'form-control'}),
            'commentaire_resolution': forms.Textarea(attrs={'class': 'form-control', 'rows': 5}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['assigne_a'].queryset = User.objects.filter(
            Q(groups__name='Responsable Scolarité') |
            Q(groups__name='Agent de Conformité') |
            Q(groups__name='Administrateur Système')
        ).distinct()

class DelegationForm(forms.ModelForm):
    class Meta:
        model = Delegation
        fields = ['delegant', 'delegue', 'permissions_delegues', 'date_debut', 'date_fin', 'est_active']
        widgets = {
            'delegant': forms.Select(attrs={'class': 'form-control'}),
            'delegue': forms.Select(attrs={'class': 'form-control'}),
            'permissions_delegues': forms.SelectMultiple(attrs={'class': 'form-control'}),
            'date_debut': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'date_fin': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'est_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['delegant'].queryset = User.objects.all()
        self.fields['delegue'].queryset = User.objects.all()
        self.fields['permissions_delegues'].choices = [(p.codename, f"{p.content_type.app_label}.{p.codename}") for p in Permission.objects.all()]

class UserCreationForm(forms.Form):
    username = forms.CharField(label="Nom d'utilisateur", max_length=150, widget=forms.TextInput(attrs={'class': 'form-control'}))
    password = forms.CharField(label="Mot de passe", widget=forms.PasswordInput(attrs={'class': 'form-control'}))
    first_name = forms.CharField(label="Prénom", max_length=150, required=False, widget=forms.TextInput(attrs={'class': 'form-control'}))
    last_name = forms.CharField(label="Nom", max_length=150, required=False, widget=forms.TextInput(attrs={'class': 'form-control'}))
    email = forms.EmailField(label="Email", max_length=254, widget=forms.EmailInput(attrs={'class': 'form-control'}))
    profile_type = forms.ChoiceField(
        label="Type de profil",
        choices=[('Etudiant', 'Étudiant'), ('Enseignant', 'Enseignant'), ('PersonnelAdministratif', 'Personnel Administratif')],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    group_name = forms.ChoiceField(
        label="Groupe (Rôle)",
        choices=[(g.name, g.name) for g in Group.objects.all()],
        widget=forms.Select(attrs={'class': 'form-control'})
    )