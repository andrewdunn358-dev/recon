"""
Mint (or show) a REST API token for a user — used by SynthOps and any other
machine caller.

    docker compose exec web python manage.py api_token synthops

Create a dedicated service user first if you like:
    docker compose exec web python manage.py createsuperuser  (or a normal user)
Then call the API with header:  Authorization: Token <token>
"""
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token


class Command(BaseCommand):
    help = "Show or create a REST API token for a user."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("--rotate", action="store_true",
                            help="Replace any existing token with a new one.")

    def handle(self, *args, **opts):
        U = get_user_model()
        try:
            user = U.objects.get(username=opts["username"])
        except U.DoesNotExist:
            raise CommandError(
                f"No user '{opts['username']}'. Create one with createsuperuser "
                f"or the admin first.")
        if opts["rotate"]:
            Token.objects.filter(user=user).delete()
        token, created = Token.objects.get_or_create(user=user)
        self.stdout.write(self.style.SUCCESS(
            f"{'created' if created else 'existing'} token for {user.username}:"))
        self.stdout.write(token.key)
        self.stdout.write(self.style.HTTP_INFO(
            "Use header:  Authorization: Token " + token.key))
