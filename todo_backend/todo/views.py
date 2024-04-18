import json
import jwt 
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_exempt
from .models import TaskList
from datetime import datetime, timedelta
from todo_backend import settings
from django.http import JsonResponse, response
from django.contrib.auth.models import User  # Import Django's default User model

def verify_token(token):
    
    try:
        decoded_token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        
        print('hello')
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
            print(datetime.utcnow())
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
            response = JsonResponse({
                'message': 'Login successful',
                'token': token,
                'success': True,
            }, status=200)
            response.set_cookie(key='jwt', value=token)
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
        # Extract token from headers
        token = request.COOKIES.get('jwt')
        
        if not token:
            return JsonResponse({
                'message': 'Token is missing',
                'success': False,
            }, status=401)

        # Verify user authentication using token
        user = verify_token(token)
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

        # Check if the category exists
        # try:
        #     category = Category.objects.get(id=category_id)
        # except Category.DoesNotExist:
        #     return JsonResponse({
        #         'message': 'Category does not exist',
        #         'success': False,
        #     }, status=404)

        # Create the task list
        task_list = TaskList.objects.create(
            title=title,
            description=description,
            start_date=start_date,
            end_date=end_date,
            priority=priority,
            user_id=user_id,
            category_id=category_id
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
        response.delete_cookie('jwt')  # Delete the JWT cookie
        return response
    else:
        return JsonResponse({
            'message': 'Invalid',
            'success': False,
        }, status=405)