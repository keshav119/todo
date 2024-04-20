from django.urls import path
import todo.views as views

urlpatterns = [
    path('', views.index),

    #AUTH Routes
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='user_login'),
    path('logout/', views.user_logout, name='logout'),

    #TASKLIST CRUD Routes
    path('createTasksList/', views.create_task_list, name='create_task_list'),
    path('getTasksList/', views.get_tasklist_by_user_and_category, name='get_task_list'),
    path('editTasksList/<int:task_list_id>/', views.update_task_list, name='edit_task_list'),
    path('deleteTasksList/<int:task_list_id>/', views.delete_task_list, name='delete_task_list'),
    
    #TASK CRUD Routes
    path('createTask/', views.create_task, name='create_task'),
    path('updateTask/<int:task_id>/', views.update_task, name='update_task'),
    path('getTask/<int:task_list_id>/', views.get_tasks_by_task_list, name='get_task'),
    path('deleteTask/<int:task_id>/', views.delete_task, name='delete_task'),

    path('dashboardData/<int:user_id>/', views.fetch_dashboard_data, name='dashboard_data'),
]
