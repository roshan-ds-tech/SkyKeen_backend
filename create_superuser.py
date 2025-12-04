import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'skykeen_backend.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

if not User.objects.filter(email="admin@skykeen.com").exists():
    User.objects.create_superuser(
        email="admin@skykeen.com",
        username="admin",
        password="YourStrongPasswordHere"
    )

