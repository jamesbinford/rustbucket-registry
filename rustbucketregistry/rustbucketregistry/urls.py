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
from rustbucketregistry.views.register import (
    register_rustbucket,
    get_rustbucket,
    submit_logs,
    report_honeypot_activity,
    extract_logs,
    update_buckets,
)
from rustbucketregistry.views.dashboard import (
    dashboard_view,
    dashboard_overview_api,
    dashboard_attacks_api,
    dashboard_top_ips_api,
    dashboard_countries_api,
    dashboard_alerts_api,
    dashboard_resources_api,
    dashboard_targets_api,
)

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

    # Public API endpoints (for rustbucket clients)
    path('api/register/', register_rustbucket, name='register_rustbucket'),
    path('api/rustbucket/<str:rustbucket_id>/', get_rustbucket, name='get_rustbucket'),
    path('api/logs/submit/', submit_logs, name='submit_logs'),
    path('api/honeypot/report/', report_honeypot_activity, name='report_honeypot_activity'),
    path('api/logs/extract/', extract_logs, name='extract_logs'),
    path('api/buckets/update/', update_buckets, name='update_buckets'),

    # Internal API endpoints (for UI)
    path('api/logsinks/', login_required(logsink_api), name='logsinks_api'),
    path('api/logsinks/<str:bucket_id>/', login_required(logsink_api), name='logsinks_api_detail'),
    path('api/honeypot/', login_required(honeypot_api), name='honeypot_api'),
    path('api/honeypot/<str:bucket_id>/', login_required(honeypot_api), name='honeypot_api_detail'),

    # Dashboard
    path('dashboard/', login_required(dashboard_view), name='dashboard'),

    # Dashboard API endpoints
    path('api/dashboard/overview/', login_required(dashboard_overview_api), name='dashboard_overview_api'),
    path('api/dashboard/attacks/', login_required(dashboard_attacks_api), name='dashboard_attacks_api'),
    path('api/dashboard/top-ips/', login_required(dashboard_top_ips_api), name='dashboard_top_ips_api'),
    path('api/dashboard/countries/', login_required(dashboard_countries_api), name='dashboard_countries_api'),
    path('api/dashboard/alerts/', login_required(dashboard_alerts_api), name='dashboard_alerts_api'),
    path('api/dashboard/resources/', login_required(dashboard_resources_api), name='dashboard_resources_api'),
    path('api/dashboard/resources/<str:bucket_id>/', login_required(dashboard_resources_api), name='dashboard_resources_api_detail'),
    path('api/dashboard/targets/', login_required(dashboard_targets_api), name='dashboard_targets_api'),
]
