import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'skykeen_backend.settings')
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

# Default admin credentials (change these after first login!)
username = 'admin'
email = 'admin@skykeen.com'
password = 'admin123'

if not User.objects.filter(username=username).exists():
    User.objects.create_superuser(username=username, email=email, password=password)
    print(f'Superuser created successfully!')
    print(f'Username: {username}')
    print(f'Email: {email}')
    print(f'Password: {password}')
    print('\n⚠️  IMPORTANT: Change this password after first login!')
else:
    print(f'Superuser "{username}" already exists.')

