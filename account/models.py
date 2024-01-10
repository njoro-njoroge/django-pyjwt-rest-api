from django.db import models

from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    first_name = models.CharField(max_length=100, blank=False)
    last_name = models.CharField(max_length=100, blank=False)
    email = models.CharField(max_length=100, blank=False, unique=True)
    phone_number = models.CharField(max_length=100, blank=False)
    location = models.CharField(max_length=100, blank=False)
    password = models.CharField(max_length=100, blank=False)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return f'{self.first_name} {self.last_name}, {self.email} {self.phone_number} {self.location}'


class Store(models.Model):
    store_name = models.CharField(max_length=100, blank=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    def __str__(self):
        return f'{self.store_name}, {self.created_at}'
