# views.py
from django.shortcuts import render
from django.http import HttpResponse
from scapy.all import *
import requests
from .models import *
from django.shortcuts import redirect, get_object_or_404
import socket
import concurrent.futures
from pythonping import ping
from django.utils import timezone
from django.db.models import Max
import ssl
from django.shortcuts import redirect, reverse
import uuid

def home(request):
    return render(request, 'home.html')

def index(request):
    target_ip = "192.168.0.0/24"
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=False)[0]

    scan_key = str(uuid.uuid4())  # Генерируем уникальный ключ для сканирования
    for sent, received in result:
        ip_address = received.psrc
        mac_address = received.hwsrc
        device_type = get_device_type(mac_address)
        existing_device = Device.objects.filter(mac_address=mac_address).first()
        if existing_device:
            # Если устройство уже существует, обновляем ключ сканирования
            existing_device.scan_key = scan_key
            existing_device.save()
        else:
            new_device = Device(ip_address=ip_address, mac_address=mac_address, device_type=device_type, scan_key=scan_key)
            new_device.save()

    # Получаем только устройства с текущим ключом сканирования для отображения на странице
    devices = Device.objects.filter(scan_key=scan_key)
    # Device.objects.filter(device_type='Неизвестно').update(device_type='Белгісіз құрылғы')
    return render(request, 'index.html', {'devices': devices})

def get_device_type(mac_address):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}")
        if response.status_code == 200:
            return response.text
        else:
            return "Белгісіз құрылғы"
    except requests.RequestException:
        return "Белгісіз құрылғы"
    
def trust_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    device.trusted = True
    device.save()
    device_info_url = reverse('device_info', kwargs={'device_id': device_id})
    return redirect(device_info_url)

def untrust_device(request, device_id):
    device = get_object_or_404(Device, id=device_id)
    device.trusted = False
    device.save()
    device_info_url = reverse('device_info', kwargs={'device_id': device_id})
    return redirect(device_info_url)

def device_info(request, device_id):
    device = get_object_or_404(Device, pk=device_id)
    if request.method == 'POST':
        if 'scan_ports' in request.POST:
            # Получаем IP-адрес устройства
            ip_address = device.ip_address

            # Сканируем открытые порты
            open_ports = scan_ports(ip_address)

            # Сохраняем результаты сканирования в базе данных
            save_scan_results(device, open_ports)

        elif 'check_activity' in request.POST:
            # Проверка активности устройства
            ip_address = device.ip_address
            monitor_device_activity(ip_address)  # Всегда запускаем мониторинг при нажатии кнопки

    # Получаем последний скан портов из базы данных
    ports = DevicePort.objects.filter(device=device)
    last_scan = DevicePort.objects.filter(device=device).order_by('-created_at').first()
    # Отображаем все записи о мониторинге активности этого устройства
    device_activities = DeviceActivity.objects.filter(ip_address=device.ip_address).order_by('-start_time')
    device_type = device.device_type
    # Проверяем SSL-сертификат устройства
    trust_level = calculate_trust_level(ports, device_activities, last_scan, device_type)
    return render(request, 'device_info.html', {'device': device, 'device_activities': device_activities, 'ports': ports, 'last_scan': last_scan, 'trust_level': trust_level})


def save_scan_results(device, open_ports):
    # Удаляем предыдущие результаты сканирования, если они есть
    DevicePort.objects.filter(device=device).delete()

    # Сохраняем новые результаты сканирования
    for port in open_ports:
        DevicePort.objects.create(device=device, port=port)

def scan_ports(ip_address):
    open_ports = []
    # Определяем порты, которые хотим сканировать
    ports_to_scan = range(1, 1001)

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)  # Уменьшаем таймаут до 0.5 секунды
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    return port
        except Exception as e:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_port, port) for port in ports_to_scan]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    if not open_ports:
        open_ports.append("0000")

    return open_ports

# Пример использования и кэширования результатов
cached_results = {}

def get_open_ports(ip_address):
    if ip_address not in cached_results:
        cached_results[ip_address] = scan_ports(ip_address)
    return cached_results[ip_address]

def calculate_trust_level(ports, device_activities, last_scan, device_type):
    trust_level = 100  # Initially set the maximum trust level

    # Criteria for calculating trust level
    if len(ports) > 3:
        trust_level -= 20  # Reduce trust if more than 10 ports are open

    if device_activities.filter(is_active=False).count() > 0:
        trust_level -= 30  # Reduce trust if there are inactive activity records

    if last_scan and last_scan.created_at.date() < timezone.now().date():
        trust_level -= 10  # Reduce trust if the last scan is more than one day old
    
    if not last_scan:
        trust_level -= 20

    if not device_activities:
        trust_level -= 30

    if device_type == "Белгісіз құрылғы":
        trust_level -= 10

    if device_activities.count() < 5:
        trust_level -= 10  # Reduce trust if there are fewer than 5 activity records

    return max(trust_level, 0)  # Trust level cannot be negative, so return the maximum of calculated level and 0



def check_device_activity(ip_address):
    try:
        # Проверяем доступность устройства по сети
        result = ping(ip_address, count=3)  # Посылаем 3 пакета ping
        # Если устройство отвечает на ping, считаем его активным
        if result.success():
            return True
        else:
            return False
    except Exception as e:
        print(f"Error checking device activity: {e}")
        return False

def monitor_device_activity(ip_address, duration=15, interval=5):
    start_time = timezone.now()
    end_time = start_time + timedelta(seconds=duration)

    # Создаем новую запись о мониторинге
    activity = DeviceActivity.objects.create(
        ip_address=ip_address,
        start_time=start_time,
        end_time=end_time,
        is_active=True  # По умолчанию считаем, что устройство активно
    )

    while timezone.now() < end_time:
        # Проверяем активность устройства
        is_active = check_device_activity(ip_address)

        # Если хотя бы одна проверка вернула False, обновляем флаг активности в базе данных на False
        if not is_active:
            activity.is_active = False
            activity.save()
            break  # Прерываем цикл, т.к. проверка уже не прошла

        time.sleep(interval)

    # Если цикл завершился и флаг активности остался True, сохраняем изменения в базе данных
    if activity.is_active:
        activity.save()


def home_page_view(request):
    return render(request, 'home_page.html')
