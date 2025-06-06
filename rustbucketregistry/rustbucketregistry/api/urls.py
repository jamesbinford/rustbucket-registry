"""
URL configuration for the RustBucket Registry API.
"""
from django.urls import path
from rustbucketregistry.api import views

app_name = 'api'

urlpatterns = [
    # Rustbucket registration endpoint as per documentation
    path('register_bucket/', views.register_rustbucket, name='api_register_rustbucket'),
    
    # Pull-based update endpoint
    path('update_buckets/', views.update_buckets, name='api_update_buckets'),
    
    # Pull-based log extraction endpoint
    path('extract_logs/', views.extract_logs, name='api_extract_logs'),
    
    # Other existing endpoints
    path('rustbucket/', views.get_rustbucket, name='api_get_rustbuckets'),
    path('rustbucket/<str:rustbucket_id>/', views.get_rustbucket, name='api_get_rustbucket_by_id'),
    path('rustbucket/key/<uuid:api_key>/', views.get_rustbucket, name='api_get_rustbucket_by_key'),
    
    # Log submission
    path('logs/submit/', views.submit_logs, name='api_submit_logs'),
    
    # Honeypot activity reporting
    path('honeypot/report/', views.report_honeypot_activity, name='api_report_honeypot_activity'),
]