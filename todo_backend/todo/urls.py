from django.urls import path
import todo.views as views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='user_login'),
    path('createList/', views.create_task_list, name='create_list'),
    path('logout/', views.user_logout, name='logout'),
]
