<!-- index.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Devices in Network</title>
</head>
<body>
    <h1>Devices in Network</h1>
    <ul>
        {% for device in devices %}
            <li>
                <a href="{% url 'device_info' device.id %}">
                    {{ device.ip_address }} - {{ device.mac_address }} - {{ device.device_type }} - Trusted: {{ device.trusted }}
                </a>
                <form method="post" action="{% url 'trust_device' device.id %}">
                    {% csrf_token %}
                    <button type="submit">Trust</button>
                </form>
            </li>
        {% endfor %}
    </ul>
</body>
</html>
