from django import template
from django.contrib.auth.models import Group

register = template.Library()

@register.filter(name='has_group')
def has_group(user, group_name):
    """
    Vérifie si l'utilisateur appartient au groupe spécifié.
    Utilisation dans les templates : {% if request.user|has_group:'NomDuGroupe' %}
    """
    if user.is_authenticated:
        try:
            group = Group.objects.get(name=group_name)
            return group in user.groups.all()
        except Group.DoesNotExist:
            return False
    return False