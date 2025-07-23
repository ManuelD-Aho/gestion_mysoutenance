"""
URL configuration for config2 project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.views.generic.base import RedirectView # <-- Importez RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    # Redirige l'URL racine vers la page de connexion
    path('', RedirectView.as_view(url='/login/', permanent=False)), # <-- Ajout de cette ligne
    path('', include('core.urls')), # Inclut les URLs de l'application 'core'
]