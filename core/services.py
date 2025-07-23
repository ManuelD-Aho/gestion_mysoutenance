from django.db import transaction
from .models import Sequence
import datetime

class UniqueIdGeneratorService:
    @staticmethod
    @transaction.atomic
    def generate(prefix, year=None):
        if year is None:
            year = datetime.date.today().year

        sequence, created = Sequence.objects.select_for_update().get_or_create(
            nom_sequence=prefix,
            annee=year,
            defaults={'valeur_actuelle': 0}
        )

        sequence.valeur_actuelle += 1
        sequence.save()

        return f"{prefix.upper()}-{year}-{str(sequence.valeur_actuelle).zfill(4)}"