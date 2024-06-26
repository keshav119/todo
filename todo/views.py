import json
import jwt
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse, JsonResponse
from .models import TaskList, Task, Category  
from datetime import datetime, timedelta
from todo_backend import settings
from django.contrib.auth.models import User  # Import Django's default User model

def index(request):
    now = datetime.now()
    html = f'''
    <html>
        <body>
            <h1>Hello from Vercel!</h1>
            <p>The current time is { now }.</p>
        </body>
    </html>
    '''
    return HttpResponse(html)

def verify_token(request):
    authorization_header = request.headers.get('Authorization')
    
    if not authorization_header or not authorization_header.startswith('Bearer '):
        return None
    
    token = authorization_header.split(' ')[1]
    
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        
        user_id = decoded_token.get('user_id')
        
        user = User.objects.get(id=user_id)
        return user
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except User.DoesNotExist:
        return None

@csrf_exempt
def register(request):
    if request.method == 'POST':
        # Parse the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))
        
        # Extract email, username, and password from the data
        email = data.get('email')
        username = data.get('username')
        password = data.get('password')
        
        # Check if the email or username already exists in the default auth_user table
        if User.objects.filter(email=email).exists() or User.objects.filter(username=username).exists():
            return JsonResponse({
                'message': 'User already exists',
                'success': False,
            }, status=400)

        # Encrypt the password before saving
        

        # Create the user in the default auth_user table
        user = User.objects.create_user(email=email, username=username, password=password)
        
        return JsonResponse({
            'message': 'User created successfully',
            'success': True,
        }, status=201)
    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)

@csrf_exempt
def user_login(request):
    if request.method == 'POST':
        # Parse the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))

        # Extract username and password from the data
        username = data.get('username')
        password = data.get('password')
        
        # Authenticate the user using email and password
        user = authenticate(request=None, username=username, password=password)
        
        if user is not None:
            # If authentication is successful, log the user in
            login(request, user)

            payload = {
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(minutes=60),  # Expiration time set to 60 minutes from now
                'iat': datetime.utcnow(),  # Issued at time
            }
            
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            
            # Exclude the 'password' attribute from the user details
            user_details = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }

            response = JsonResponse({
                'message': 'Login successful',
                'token': token,
                'user': user_details,
                'success': True,
            }, status=200)
            
            return response
        else:
            # If authentication fails, return an error response
            return JsonResponse({
                'message': 'Invalid email or password',
                'success': False,
            }, status=401)
    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)

@csrf_exempt
def create_task_list(request):
    
    if request.method == 'POST':
        # Verify user authentication using token
        user = verify_token(request)
        if user is None:
            return JsonResponse({
                'message': 'Invalid token',
                'success': False,
            }, status=401)

        # Parse the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))

        # Extract task list details from data
        title = data.get('title')
        description = data.get('description')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        priority = data.get('priority')
        user_id = data.get('user_id')
        category_id = data.get('category_id')

        
        # Create the task list
        task_list = TaskList.objects.create(
            title=title,
            description=description,
            start_date=start_date,
            end_date=end_date,
            priority=priority,
            user_id=user_id,
            category_id=category_id,
            total_tasks=0,
            completed_tasks=0,
            pending_tasks=0
        )

        return JsonResponse({
            'message': 'Task list created successfully',
            'success': True,
            'task_list_id': task_list.id,
        }, status=201)

    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)
    

@csrf_exempt
def user_logout(request):
    if request.method == 'POST':
        response = JsonResponse({
            'message': 'User logged out successfully',
            'success': True,
        })
        return response
    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)
    
@csrf_exempt
def get_tasklist_by_user_and_category(request):
    if request.method == 'POST':
        # Verify user authentication using token
        user = verify_token(request)
        if user is None:
            return JsonResponse({
                'message': 'Invalid token',
                'success': False,
            }, status=401)

        # Parse the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))

        # Extract user_id and category_id from data
        user_id = data.get('user_id')
        category_id = data.get('category_id')

        # Query tasks based on user_id and category_id
        tasks = TaskList.objects.filter(user_id=user_id, category_id=category_id)

        # Serialize tasks data
        tasks_data = []
        for task in tasks:
            task_data = {
                'id': task.id,
                'title': task.title,
                'description': task.description,
                'start_date': task.start_date,
                'end_date': task.end_date,
                'priority': task.priority,
                'total_tasks': task.total_tasks,  # Assuming total tasks count is stored in the TaskList model
                'completed_tasks': task.completed_tasks,  # Assuming completed tasks count is stored in the TaskList model
                'pending_tasks': task.pending_tasks,  # Assuming pending tasks count is stored in the TaskList model
            }
            tasks_data.append(task_data)

        return JsonResponse({
            'message': 'Tasks fetched successfully',
            'success': True,
            'tasks': tasks_data,
        }, status=200)

    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)


@csrf_exempt
def update_task_list(request, task_list_id):
    if request.method == 'PUT':
        # Verify user authentication using token
        user = verify_token(request)
        if user is None:
            return JsonResponse({
                'message': 'Invalid token',
                'success': False,
            }, status=401)

        # Parse the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))

        try:
            # Retrieve the task list object
            task_list = TaskList.objects.get(id=task_list_id)
        except TaskList.DoesNotExist:
            return JsonResponse({
                'message': 'Task list does not exist',
                'success': False,
            }, status=404)

        # Check if the user is the owner of the task list
        if task_list.user_id != user.id:
            return JsonResponse({
                'message': 'You are not authorized to update this task list',
                'success': False,
            }, status=403)

        # Update task list fields
        if 'title' in data:
            task_list.title = data['title']
        if 'description' in data:
            task_list.description = data['description']
        if 'start_date' in data:
            task_list.start_date = data['start_date']
        if 'end_date' in data:
            task_list.end_date = data['end_date']
        if 'priority' in data:
            task_list.priority = data['priority']

        # Save the updated task list
        task_list.save()

        return JsonResponse({
            'message': 'Task list updated successfully',
            'success': True,
            'task_list_id': task_list.id,
        }, status=200)

    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)

@csrf_exempt
def delete_task_list(request, task_list_id):
    if request.method == 'DELETE':
        # Verify user authentication using token
        user = verify_token(request)
        if user is None:
            return JsonResponse({
                'message': 'Invalid token',
                'success': False,
            }, status=401)

        try:
            # Retrieve the task list object
            task_list = TaskList.objects.get(id=task_list_id)
        except TaskList.DoesNotExist:
            return JsonResponse({
                'message': 'Task list does not exist',
                'success': False,
            }, status=404)

        # Check if the user is the owner of the task list
        if task_list.user_id != user.id:
            return JsonResponse({
                'message': 'You are not authorized to delete this task list',
                'success': False,
            }, status=403)

        # Delete all tasks associated with the task list
        Task.objects.filter(task_list_id=task_list_id).delete()

        # Delete the task list
        task_list.delete()

        return JsonResponse({
            'message': 'Task list and associated tasks deleted successfully',
            'success': True,
        }, status=200)

    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)

@csrf_exempt
def create_task(request):
    if request.method == 'POST':
        # Verify user authentication using token
        user = verify_token(request)
        if user is None:
            return JsonResponse({
                'message': 'Invalid token',
                'success': False,
            }, status=401)

        # Parse the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))

        # Extract task details from data
        title = data.get('title')
        description = data.get('description')
        task_list_id = data.get('task_list_id')
        difficulty = data.get('difficulty')
        status = data.get('status', False)  # Default status is False (pending)

        try:
            # Check if the task list exists
            task_list = TaskList.objects.get(id=task_list_id)
        except TaskList.DoesNotExist:
            return JsonResponse({
                'message': 'Task list does not exist',
                'success': False,
            }, status=404)

        # Create the task
        task = Task.objects.create(
            title=title,
            description=description,
            task_list=task_list,
            difficulty=difficulty,
            status=status
        )

        return JsonResponse({
            'message': 'Task created successfully',
            'success': True,
            'task_id': task.id,
        }, status=201)

    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)

@csrf_exempt
def update_task(request, task_id):
    if request.method == 'PUT':
        # Verify user authentication using token
        user = verify_token(request)
        if user is None:
            return JsonResponse({
                'message': 'Invalid token',
                'success': False,
            }, status=401)

        # Parse the JSON data from the request body
        data = json.loads(request.body.decode('utf-8'))

        try:
            # Retrieve the task object
            task = Task.objects.get(id=task_id)
        except Task.DoesNotExist:
            return JsonResponse({
                'message': 'Task does not exist',
                'success': False,
            }, status=404)

        # Update task fields
        if 'title' in data:
            task.title = data['title']
        if 'description' in data:
            task.description = data['description']
        if 'difficulty' in data:
            task.difficulty = data['difficulty']
        if 'status' in data:
            task.status = data['status']

        # Save the updated task
        task.save()

        # Update total_tasks, pending_tasks, completed_tasks in task_list_table
        task_list_id = task.task_list_id
        total_tasks = Task.objects.filter(task_list_id=task_list_id).count()
        pending_tasks = Task.objects.filter(task_list_id=task_list_id, status=False).count()
        completed_tasks = Task.objects.filter(task_list_id=task_list_id, status=True).count()

        # Update the task_list_table
        task_list = TaskList.objects.get(id=task_list_id)
        task_list.total_tasks = total_tasks
        task_list.pending_tasks = pending_tasks
        task_list.completed_tasks = completed_tasks
        task_list.save()

        return JsonResponse({
            'message': 'Task updated successfully',
            'success': True,
            'task_id': task.id,
        }, status=200)

    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)
    
@csrf_exempt
def get_tasks_by_task_list(request, task_list_id):
    if request.method == 'GET':
        try:
            # Retrieve all tasks associated with the task list ID
            tasks = Task.objects.filter(task_list_id=task_list_id)
        except Task.DoesNotExist:
            return JsonResponse({
                'message': 'No tasks found for the specified task list ID',
                'success': False,
            }, status=404)

        # Serialize tasks data
        tasks_data = [{'id': task.id, 'title': task.title, 'description': task.description, 
                       'difficulty': task.difficulty, 'status': task.status} for task in tasks]

        return JsonResponse({
            'message': 'Tasks fetched successfully',
            'success': True,
            'tasks': tasks_data,
        }, status=200)

    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)
    
@csrf_exempt
def delete_task(request, task_id):
    if request.method == 'DELETE':
        try:
            # Retrieve the task object
            task = Task.objects.get(id=task_id)
        except Task.DoesNotExist:
            return JsonResponse({
                'message': 'Task does not exist',
                'success': False,
            }, status=404)

        # Delete the task
        task.delete()

        return JsonResponse({
            'message': 'Task deleted successfully',
            'success': True,
        }, status=200)

    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)

@csrf_exempt
def fetch_dashboard_data(request, user_id):
    if request.method == 'POST':
        # Fetch all task lists associated with the user
        user_task_lists = TaskList.objects.filter(user_id=user_id)

        # Initialize counters for total and completed tasks over all categories
        total_tasks_all = 0
        completed_tasks_all = 0

        # Initialize dictionaries to store task counts for each category
        category_task_counts = {}

        # Iterate over each task list to aggregate task data over all categories
        for task_list in user_task_lists:
            total_tasks_all += task_list.total_tasks
            completed_tasks_all += task_list.completed_tasks

            # Check if the category exists in the dictionary, if not, initialize it
            category_name = task_list.category.name
            if category_name not in category_task_counts:
                category_task_counts[category_name] = {
                    'total_tasks': 0,
                    'completed_tasks': 0,
                }

            # Update task counts for the category
            category_task_counts[category_name]['total_tasks'] += task_list.total_tasks
            category_task_counts[category_name]['completed_tasks'] += task_list.completed_tasks

        # Return the aggregated task data for all categories and specific categories
        return JsonResponse({
            'message': 'Dashboard data fetched successfully',
            'success': True,
            'total_tasks_all': total_tasks_all,
            'completed_tasks_all': completed_tasks_all,
            'category_task_counts': category_task_counts,
        }, status=200)
    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)
