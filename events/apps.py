from django.apps import AppConfig
import sys


class EventsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'events'

    def ready(self):
        """
        Automatically create/update admin user on app startup.
        This runs automatically on every deployment, perfect for Render free tier.
        """
        # Skip during migrations and other management commands
        if 'migrate' in sys.argv or 'makemigrations' in sys.argv or 'collectstatic' in sys.argv:
            return
        
        # Use a delayed execution to avoid database access during initialization
        # This will run after Django is fully initialized
        import threading
        
        def create_admin_user_delayed():
            # Wait a bit for Django to be fully ready
            import time
            time.sleep(2)
            
            try:
                from django.contrib.auth import get_user_model
                from django.db import connection
                
                # Check if database is ready
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT 1")
                except:
                    return  # Database not ready yet
                
                User = get_user_model()
                email = "admin@skykeen.com"
                password = "admin123"
                
                # Check if user exists
                if User.objects.filter(email=email).exists():
                    # Update existing user
                    user = User.objects.get(email=email)
                    user.set_password(password)
                    user.is_staff = True
                    user.is_superuser = True
                    user.save()
                    print(f"✓ Admin user password updated: {email}")
                else:
                    # Create new superuser
                    User.objects.create_superuser(
                        email=email,
                        username="admin",
                        password=password
                    )
                    print(f"✓ Admin user created: {email}")
            except Exception as e:
                # Don't crash the app if user creation fails
                print(f"⚠ Could not create/update admin user: {str(e)}")
        
        # Run in a separate thread to avoid blocking startup
        thread = threading.Thread(target=create_admin_user_delayed, daemon=True)
        thread.start()