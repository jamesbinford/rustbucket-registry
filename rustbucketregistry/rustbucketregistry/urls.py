"""
URL configuration for rustbucketregistry project.

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
from django.urls import path, include
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required

# Import views
from rustbucketregistry.views.home import index, about, detail
from rustbucketregistry.views.logsinks import logsinks_view, logsink_api, honeypot_api

# Main URL patterns
urlpatterns = [
    path('admin/', admin.site.urls),
    path('', login_required(index), name='home'),
    path('bucket/<str:bucket_id>/', login_required(detail), name='bucket_detail'),
    path('logsinks/', login_required(logsinks_view), name='logsinks'),
    path('logsinks/<str:bucket_id>/', login_required(logsinks_view), name='logsinks_detail'),

    # Authentication views
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),

    # Internal API endpoints (for UI)
    path('api/logsinks/', login_required(logsink_api), name='logsinks_api'),
    path('api/logsinks/<str:bucket_id>/', login_required(logsink_api), name='logsinks_api_detail'),
    path('api/honeypot/', login_required(honeypot_api), name='honeypot_api'),
    path('api/honeypot/<str:bucket_id>/', login_required(honeypot_api), name='honeypot_api_detail'),

    # External API endpoints (for Rustbuckets)
    path('api/v1/', include('rustbucketregistry.api.urls')),
]
