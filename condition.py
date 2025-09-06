import base64
from datetime import datetime, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

class Condition:
    def __init__(self, filename='data.bin', key=b'defaultkey1234567890123456'):
        self.filename = filename
        self.key = pad(key, 32)

    def update_time(self, days=3):
        if not isinstance(days, int):
            days = 3
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = f"{now}|{days}".encode()
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        with open(self.filename, 'wb') as f:
            f.write(iv + encrypted_data)

    def check_expired(self):
        if not os.path.exists(self.filename):
            self.update_time()
            return False
        try:
            with open(self.filename, 'rb') as f:
                content = f.read()
            iv = content[:16]
            encrypted_data = content[16:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            last_time_str, days_str = decrypted_data.decode().split('|')
            last_time = datetime.strptime(last_time_str, "%Y-%m-%d %H:%M:%S")
            delta = datetime.now() - last_time
            return delta.total_seconds() > int(days_str) * 86400
        except Exception:
            self.update_time()
            return False
