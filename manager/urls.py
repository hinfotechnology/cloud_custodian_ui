from django.urls import path
from . import views

app_name = 'manager'

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    path('policies/', views.policy_list, name='policy_list'),
    path('upload/', views.upload_policy, name='upload_policy'),
    path('edit/<int:pk>/', views.edit_policy, name='edit_policy'),
    path('run/<int:pk>/', views.run_policy, name='run_policy'),
    path('aws-services/', views.aws_services, name='aws_services'),
    path('cost/', views.cost_view, name='cost'),
    path('resource/<str:service_name>/<str:resource_id>/', views.resource_details, name='resource_details'),
    path('resource/<str:service_name>/<str:resource_id>/delete/', views.delete_resource, name='delete_resource'),
    path('resource/<str:service_name>/<str:resource_id>/deactivate/', views.deactivate_resource, name='deactivate_resource'),
]
