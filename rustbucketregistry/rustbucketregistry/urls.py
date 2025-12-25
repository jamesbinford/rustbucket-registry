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

# Import views
from rustbucketregistry.views.home import index, detail
from rustbucketregistry.views.logsinks import logsinks_view, logsink_api
from rustbucketregistry.views.register import (
    register_rustbucket,
    get_rustbucket,
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
from rustbucketregistry.views.api_keys import (
    list_api_keys,
    create_api_key,
    revoke_api_key,
    rotate_api_key,
)
from rustbucketregistry.views.registration_keys import (
    create_registration_key,
    list_registration_keys,
    revoke_registration_key,
    registration_keys_view,
)

# Main URL patterns
urlpatterns = [
    path('admin/', admin.site.urls),
    # Views with RBAC decorators (login_required is applied in the view)
    path('', index, name='home'),
    path('bucket/<str:bucket_id>/', detail, name='bucket_detail'),
    path('logsinks/', logsinks_view, name='logsinks'),
    path('logsinks/<str:bucket_id>/', logsinks_view, name='logsinks_detail'),
    path('registration-keys/', registration_keys_view, name='registration_keys'),

    # Authentication views
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),

    # Public API endpoints (for rustbucket clients - token auth)
    path('api/register/', register_rustbucket, name='register_rustbucket'),
    path('api/rustbucket/<str:rustbucket_id>/', get_rustbucket, name='get_rustbucket'),
    path('api/logs/extract/', extract_logs, name='extract_logs'),
    path('api/buckets/update/', update_buckets, name='update_buckets'),

    # Internal API endpoints (for UI - RBAC applied in views)
    path('api/logsinks/', logsink_api, name='logsinks_api'),
    path('api/logsinks/<str:bucket_id>/', logsink_api, name='logsinks_api_detail'),

    # Dashboard (RBAC applied in views)
    path('dashboard/', dashboard_view, name='dashboard'),

    # Dashboard API endpoints (RBAC applied in views)
    path('api/dashboard/overview/', dashboard_overview_api, name='dashboard_overview_api'),
    path('api/dashboard/attacks/', dashboard_attacks_api, name='dashboard_attacks_api'),
    path('api/dashboard/top-ips/', dashboard_top_ips_api, name='dashboard_top_ips_api'),
    path('api/dashboard/countries/', dashboard_countries_api, name='dashboard_countries_api'),
    path('api/dashboard/alerts/', dashboard_alerts_api, name='dashboard_alerts_api'),
    path('api/dashboard/resources/', dashboard_resources_api, name='dashboard_resources_api'),
    path('api/dashboard/resources/<str:bucket_id>/', dashboard_resources_api, name='dashboard_resources_api_detail'),
    path('api/dashboard/targets/', dashboard_targets_api, name='dashboard_targets_api'),

    # API Key Management (RBAC applied in views)
    path('api/keys/', list_api_keys, name='list_api_keys'),
    path('api/keys/<str:rustbucket_id>/', list_api_keys, name='list_api_keys_by_rustbucket'),
    path('api/keys/<str:rustbucket_id>/create/', create_api_key, name='create_api_key'),
    path('api/keys/<int:api_key_id>/revoke/', revoke_api_key, name='revoke_api_key'),
    path('api/keys/<int:api_key_id>/rotate/', rotate_api_key, name='rotate_api_key'),

    # Registration Key Management (Admin only - RBAC applied in views)
    path('api/registration-keys/', list_registration_keys, name='list_registration_keys'),
    path('api/registration-keys/create/', create_registration_key, name='create_registration_key'),
    path('api/registration-keys/<int:key_id>/revoke/', revoke_registration_key, name='revoke_registration_key'),
]
