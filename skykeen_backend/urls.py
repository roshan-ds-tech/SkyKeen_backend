"""
URL configuration for skykeen_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.http import HttpResponse, Http404
from django.views.static import serve
import os

def home(request):
    return HttpResponse("SkyKeen API is running successfully!")

def serve_media(request, path):
    """
    Serve media files in production.
    This view handles media file serving for Render deployment.
    """
    media_root = settings.MEDIA_ROOT
    file_path = os.path.join(media_root, path)
    
    if os.path.exists(file_path) and os.path.isfile(file_path):
        return serve(request, path, document_root=media_root)
    else:
        raise Http404("File not found")

urlpatterns = [
    path('', home),
    path('', include('events.urls')),
    path('admin/', admin.site.urls),
]

# Serve media files
# Use custom view for production, static() for development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
else:
    # Production: use custom view to serve media files
    urlpatterns += [
        re_path(r'^media/(?P<path>.*)$', serve_media, name='media'),
    ]
