from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RegistrationViewSet, admin_login, admin_logout, admin_check, get_csrf_token, test_logging

router = DefaultRouter()
router.register(r'registrations', RegistrationViewSet, basename='registration')

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/admin/login/', admin_login, name='admin-login'),
    path('api/admin/logout/', admin_logout, name='admin-logout'),
    path('api/admin/check/', admin_check, name='admin-check'),
    path('api/csrf-token/', get_csrf_token, name='csrf-token'),
    path('api/test-logging/', test_logging, name='test-logging'),
]

