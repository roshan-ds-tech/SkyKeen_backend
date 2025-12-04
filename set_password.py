import os
import django


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "skykeen_backend.settings")
django.setup()

from django.contrib.auth import get_user_model


User = get_user_model()

user = User.objects.get(email="admin@skykeen.com")
user.set_password("admin123")
user.save()

print("Password updated successfully!")


