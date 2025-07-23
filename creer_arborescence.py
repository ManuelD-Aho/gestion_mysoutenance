import os

# Le chemin de base où l'arborescence sera créée
base_path = r"C:\wamp64\www\gestion_mysoutenance"

# Liste de tous les répertoires à créer
directories = [
    "core",
    "core/management/commands",
    "core/migrations",
    "core/models",
    "config",
    "static/css",
    "static/js",
    "static/images",
    "templates/core/commission",
    "templates/core/etudiant",
    "templates/core/personnel",
    "templates/core/partials",
    "templates/pdf",
    "venv"
]

# Liste de tous les fichiers à créer
files = [
    ".env",
    "manage.py",
    "requirements.txt",
    "README.md",
    "core/__init__.py",
    "core/admin.py",
    "core/apps.py",
    "core/enums.py",
    "core/forms.py",
    "core/management/__init__.py",
    "core/management/commands/__init__.py",
    "core/management/commands/seed_referentials.py",
    "core/management/commands/check_penalties.py",
    "core/migrations/__init__.py",
    "core/migrations/0001_initial.py",
    "core/models/__init__.py",
    "core/models/user_models.py",
    "core/models/academic_models.py",
    "core/models/report_models.py",
    "core/models/commission_models.py",
    "core/services.py",
    "core/signals.py",
    "core/tasks.py",
    "core/tests.py",
    "core/urls.py",
    "core/views.py",
    "config/__init__.py",
    "config/asgi.py",
    "config/settings.py",
    "config/urls.py",
    "config/wsgi.py",
    "static/css/styles.css",
    "static/js/htmx.min.js",
    "templates/base.html",
    "templates/core/commission/session_detail.html",
    "templates/core/etudiant/dashboard.html",
    "templates/core/etudiant/soumettre_rapport.html",
    "templates/core/personnel/conformite_dashboard.html",
    "templates/core/partials/statut_rapport_partial.html",
    "templates/pdf/bulletin.html",
    "templates/pdf/pv.html"
]

def create_project_structure():
    """
    Crée l'arborescence de dossiers et de fichiers pour le projet.
    """
    # Créer le dossier racine s'il n'existe pas
    if not os.path.exists(base_path):
        os.makedirs(base_path)
        print(f"Dossier racine créé : {base_path}")

    # Créer les sous-dossiers
    for directory in directories:
        dir_path = os.path.join(base_path, directory.replace('/', os.sep))
        os.makedirs(dir_path, exist_ok=True)
        # Ajout d'un fichier __init__.py dans les packages nécessaires qui n'en ont pas
        if "__init__.py" not in os.listdir(os.path.dirname(dir_path)) and os.path.dirname(dir_path).endswith('management'):
             open(os.path.join(os.path.dirname(dir_path), "__init__.py"), 'a').close()

    # Créer les fichiers vides
    for file in files:
        file_path = os.path.join(base_path, file.replace('/', os.sep))
        # S'assurer que le dossier parent existe avant de créer le fichier
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            pass # Crée simplement le fichier vide

    print("\n✅ Arborescence du projet créée avec succès !")

if __name__ == "__main__":
    create_project_structure()