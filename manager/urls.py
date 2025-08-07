from django.urls import path
from . import views

app_name = 'manager'

urlpatterns = [
    path('', views.policy_list, name='policy_list'),
    path('upload/', views.upload_policy, name='upload_policy'),
    path('edit/<int:pk>/', views.edit_policy, name='edit_policy'),
    path('run/<int:pk>/', views.run_policy, name='run_policy'),
    path('aws-services/', views.aws_services, name='aws_services'),
]
