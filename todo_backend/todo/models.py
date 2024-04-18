import uuid
from django.db import models
from django.contrib.auth.models import User  # Import the User model from Django's auth system

class Category(models.Model):
    name = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.name
    
class TaskList(models.Model):
    title = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # Use the User model
    description = models.TextField(blank=True)
    start_date = models.DateField()
    end_date = models.DateField()
    priority = models.IntegerField()
    total_tasks = models.IntegerField(default=0)
    completed_tasks = models.IntegerField(default=0)
    pending_tasks = models.IntegerField(default=0)

    def __str__(self):
        return self.title

class Task(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    task_list = models.ForeignKey(TaskList, on_delete=models.CASCADE)
    difficulty = models.IntegerField()
    status = models.BooleanField(default=False)  # True for completed, False for pending

    def __str__(self):
        return self.title
