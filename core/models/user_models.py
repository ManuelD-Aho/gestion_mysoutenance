from django.db import models
from django.contrib.auth.models import User
from core.enums import StatutReclamation # Assurez-vous que cette importation est présente

class Etudiant(models.Model):
    utilisateur = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='profil_etudiant')
    nom = models.CharField(max_length=100)
    prenom = models.CharField(max_length=100)
    date_naissance = models.DateField(null=True, blank=True)
    lieu_naissance = models.CharField(max_length=100, null=True, blank=True)
    nationalite = models.CharField(max_length=50, null=True, blank=True)
    sexe = models.CharField(max_length=10, null=True, blank=True)
    adresse_postale = models.TextField(null=True, blank=True)
    telephone = models.CharField(max_length=20, null=True, blank=True)
    email_contact_secondaire = models.EmailField(max_length=255, null=True, blank=True)
    contact_urgence_nom = models.CharField(max_length=100, null=True, blank=True)
    contact_urgence_telephone = models.CharField(max_length=20, null=True, blank=True)
    est_eligible_soumission = models.BooleanField(default=False)

    @property
    def nom_complet(self):
        return f"{self.prenom} {self.nom}"

    def __str__(self):
        return f"{self.prenom} {self.nom}"

class Enseignant(models.Model):
    utilisateur = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='profil_enseignant')
    nom = models.CharField(max_length=100)
    prenom = models.CharField(max_length=100)
    telephone_professionnel = models.CharField(max_length=20, null=True, blank=True)
    email_professionnel = models.EmailField(max_length=255, unique=True, null=True, blank=True)

    @property
    def nom_complet(self):
        return f"{self.prenom} {self.nom}"

    def __str__(self):
        return f"{self.prenom} {self.nom}"

class PersonnelAdministratif(models.Model):
    utilisateur = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='profil_personnel')
    nom = models.CharField(max_length=100)
    prenom = models.CharField(max_length=100)
    telephone_professionnel = models.CharField(max_length=20, null=True, blank=True)
    email_professionnel = models.EmailField(max_length=255, unique=True, null=True, blank=True)

    @property
    def nom_complet(self):
        return f"{self.prenom} {self.nom}"

    def __str__(self):
        return f"{self.prenom} {self.nom}"

class Grade(models.Model):
    id_grade = models.CharField(max_length=50, primary_key=True)
    libelle_grade = models.CharField(max_length=50)

    def __str__(self):
        return self.libelle_grade

class Fonction(models.Model):
    id_fonction = models.CharField(max_length=50, primary_key=True)
    libelle_fonction = models.CharField(max_length=100)

    def __str__(self):
        return self.libelle_fonction

class GradeEnseignant(models.Model):
    enseignant = models.ForeignKey('core.Enseignant', on_delete=models.CASCADE)
    grade = models.ForeignKey('core.Grade', on_delete=models.CASCADE)
    date_acquisition = models.DateField()

    class Meta:
        unique_together = ('enseignant', 'grade', 'date_acquisition')

class FonctionEnseignant(models.Model):
    enseignant = models.ForeignKey('core.Enseignant', on_delete=models.CASCADE)
    fonction = models.ForeignKey('core.Fonction', on_delete=models.CASCADE)
    date_debut_occupation = models.DateField()
    date_fin_occupation = models.DateField(null=True, blank=True)

    class Meta:
        unique_together = ('enseignant', 'fonction', 'date_debut_occupation')

# Extension du modèle User de Django pour les champs de sécurité et de notification
# Ces champs sont ajoutés dynamiquement. Les linters peuvent avoir du mal à les reconnaître.
# Pour une solution plus robuste pour les linters, un Custom User Model serait préférable.
User.add_to_class('email_valide', models.BooleanField(default=False))
User.add_to_class('token_validation_email', models.CharField(max_length=255, null=True, blank=True))
User.add_to_class('date_expiration_token', models.DateTimeField(null=True, blank=True))
User.add_to_class('tentatives_connexion_echouees', models.PositiveSmallIntegerField(default=0))
User.add_to_class('compte_bloque_jusqua', models.DateTimeField(null=True, blank=True))
User.add_to_class('two_fa_secret', models.CharField(max_length=100, null=True, blank=True))
User.add_to_class('is_2fa_active', models.BooleanField(default=False))
User.add_to_class('preferences_notifications', models.JSONField(default=dict, null=True, blank=True))

class Delegation(models.Model):
    delegant = models.ForeignKey(User, on_delete=models.CASCADE, related_name='delegations_faites')
    delegue = models.ForeignKey(User, on_delete=models.CASCADE, related_name='delegations_recues')
    permissions_delegues = models.JSONField()
    date_debut = models.DateField()
    date_fin = models.DateField()
    est_active = models.BooleanField(default=True)

    def __str__(self):
        return f"Délégation de {self.delegant.username} à {self.delegue.username}"

class Notification(models.Model):
    destinataire = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    message = models.TextField()
    date_creation = models.DateTimeField(auto_now_add=True)
    est_lue = models.BooleanField(default=False)
    type_notification = models.CharField(max_length=100, null=True, blank=True)
    lien_action = models.CharField(max_length=255, null=True, blank=True)
    est_archivee = models.BooleanField(default=False)

    class Meta:
        ordering = ['-date_creation']

    def __str__(self):
        return f"Notification pour {self.destinataire.username}: {self.message[:50]}..."

class Reclamation(models.Model):
    etudiant = models.ForeignKey(Etudiant, on_delete=models.CASCADE, related_name='reclamations')
    sujet = models.CharField(max_length=255)
    description = models.TextField()
    date_soumission = models.DateTimeField(auto_now_add=True)
    statut = models.CharField(max_length=50, choices=StatutReclamation.choices, default=StatutReclamation.OUVERTE)
    assigne_a = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reclamations_assignees')
    date_resolution = models.DateTimeField(null=True, blank=True)
    commentaire_resolution = models.TextField(null=True, blank=True)

    class Meta:
        ordering = ['-date_soumission']

    def __str__(self):
        return f"Réclamation de {self.etudiant.nom} - {self.sujet}"