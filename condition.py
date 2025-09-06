import base64
from datetime import datetime, timedelta

def update_time(t=3):
    if not isinstance(t, int):
        t = 3
    with open('data.bin', 'wb') as f:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # now = datetime.strptime("2025-09-01 15:00:00", "%Y-%m-%d %H:%M:%S")
        f.write(base64.b64encode(f"{now}|{t}".encode()))

def check():
    try:
        with open('data.bin', 'rb') as f:
            data = base64.b64decode(f.read())
        data = data.decode().split('|')
        # print(data[0])
        last_online = datetime.strptime(data[0],"%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        d = now - last_online
        if d.total_seconds() > 86400 * int(data[1]):
            # print("Time Expired.")
            return True
        else:
            # print("Checking Complete.")
            return False
    except FileNotFoundError:
        # print("File Not Found.")
        update_time()
        return False