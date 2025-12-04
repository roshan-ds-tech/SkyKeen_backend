import os
import django


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "skykeen_backend.settings")
django.setup()

from django.contrib.auth import get_user_model


User = get_user_model()

email = "admin@skykeen.com"
password = "admin123"  # choose your password

try:
    user = User.objects.get(email=email)
    user.set_password(password)
    user.save()
    print("Password updated successfully!")
except User.DoesNotExist:
    print("User does not exist!")


