from django import template

register = template.Library()

@register.filter(name='get_item')
def get_item(dictionary, key):
    """
    Permet d'accéder à un élément d'un dictionnaire par sa clé dans les templates Django.
    Utilisation : {{ my_dict|get_item:key }}
    """
    if isinstance(dictionary, dict):
        return dictionary.get(key)
    # Si l'objet n'est pas un dictionnaire, on peut essayer d'accéder à l'attribut
    # C'est utile si form.fields est un objet qui se comporte comme un dictionnaire
    # mais n'en est pas techniquement un (comme un BoundField dict-like)
    try:
        return getattr(dictionary, key)
    except AttributeError:
        return None

@register.filter(name='replace')
def replace_filter(value, arg):
    """
    Remplace une sous-chaîne par une autre.
    Utilisation : {{ value|replace:"old,new" }}
    """
    if isinstance(value, str) and isinstance(arg, str):
        try:
            old, new = arg.split(',', 1)
            return value.replace(old, new)
        except ValueError:
            # Si l'argument n'est pas au format "old,new", on ne fait rien
            return value
    return value