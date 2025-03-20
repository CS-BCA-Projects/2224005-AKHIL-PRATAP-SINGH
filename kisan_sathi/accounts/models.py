from django.db import models


class Crop(models.Model):
    name = models.CharField(max_length=255)
    variety = models.CharField(max_length=255)
    weight = models.FloatField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    
    def __str__(self):
        return self.name
