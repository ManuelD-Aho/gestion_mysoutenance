from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import RedirectView
from django.contrib.auth import views as auth_views

urlpatterns = [
path('admin/', admin.site.urls),
    # Redirige l'URL racine vers la page de connexion
    path('', RedirectView.as_view(url='/login/', permanent=False)),

    # --- Vues d'Authentification (Utiliser celles de Django) ---
    path('login/', auth_views.LoginView.as_view(template_name='registration/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),
]