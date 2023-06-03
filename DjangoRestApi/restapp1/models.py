from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    address = models.TextField()

    def __str__(self):
        return self.username


class Product(models.Model):
    product_name = models.CharField(max_length=100)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.product_name
