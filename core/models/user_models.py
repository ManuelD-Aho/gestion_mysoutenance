from django.db import models
from django.contrib.auth.models import User

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

    def __str__(self):
        return f"{self.prenom} {self.nom}"

class Enseignant(models.Model):
    utilisateur = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='profil_enseignant')
    nom = models.CharField(max_length=100)
    prenom = models.CharField(max_length=100)
    telephone_professionnel = models.CharField(max_length=20, null=True, blank=True)
    email_professionnel = models.EmailField(max_length=255, unique=True, null=True, blank=True)

    def __str__(self):
        return f"{self.prenom} {self.nom}"

class PersonnelAdministratif(models.Model):
    utilisateur = models.OneToOneField(User, on_delete=models.CASCADE, primary_key=True, related_name='profil_personnel')
    nom = models.CharField(max_length=100)
    prenom = models.CharField(max_length=100)
    telephone_professionnel = models.CharField(max_length=20, null=True, blank=True)
    email_professionnel = models.EmailField(max_length=255, unique=True, null=True, blank=True)

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