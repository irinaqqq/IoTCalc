# models.py
from django.db import models

class Device(models.Model):
    ip_address = models.CharField(max_length=15)
    mac_address = models.CharField(max_length=17, unique=True)
    device_type = models.CharField(max_length=100)
    trusted = models.BooleanField(default=False)
    scan_key = models.CharField(max_length=255, default='')

    def __str__(self):
        return self.mac_address

class DeviceActivity(models.Model):
    ip_address = models.CharField(max_length=100)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    is_active = models.BooleanField()  # Добавленное поле для хранения информации об активности устройства

    def __str__(self):
        return f"{self.ip_address} - {self.start_time}"
    
class DevicePort(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    port = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']