import os
import django


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "skykeen_backend.settings")
django.setup()

from django.contrib.auth import get_user_model


User = get_user_model()

email = "admin@skykeen.com"
password = "admin123"

try:
    user = User.objects.get(email=email)
    user.set_password(password)
    user.is_staff = True
    user.is_superuser = True
    user.save()
    print(f"Password updated successfully for user: {email}")
except User.DoesNotExist:
    # Create the user if it doesn't exist
    User.objects.create_superuser(
        email=email,
        username="admin",
        password=password
    )
    print(f"User created successfully: {email}")
except Exception as e:
    print(f"Error: {str(e)}")


