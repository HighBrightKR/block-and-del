import shutil
import tkinter as tk
from tkinter import font as tkFont, messagebox
import bcrypt
import keyboard
import threading
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.icons import Icon
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time
import sys
from condition import Condition
ttk.localization.initialize_localities = bool

PASSWORD_FILE = "password.bin"

class SecurityApp:
    def __init__(self, root):
        if not Condition().check_expired():
            sys.exit()

        self.root = root
        self.try_count = 0
        self.stop_blocking_event = threading.Event()
        self.start_purge_event = threading.Event()

        self.setup_ui()
        self.start_threads()

    def setup_ui(self):
        self.root.title("보안 경고")
        self.root.attributes('-fullscreen', True)
        self.root.attributes('-topmost', True)
        self.root.configure(bg='#F8F9FA')

        self.style = ttk.Style()
        self.style.configure('danger.TFrame', background='white', bordercolor='#DC3545', borderwidth=2, relief='solid')
        self.style.configure('white.TFrame', background='white')
        self.style.configure('white.TLabel', background='white')
        self.style.configure('danger.white.TLabel', background='white', foreground='#DC3545')

        self.outer_frame = ttk.Frame(self.root, style='TFrame', width=480, height=520)
        self.outer_frame.place(relx=0.5, rely=0.5, anchor="center")
        self.outer_frame.pack_propagate(False)

        self.card_frame = ttk.Frame(self.outer_frame, style='danger.TFrame', padding=(40, 40))
        self.card_frame.pack(expand=True, fill=BOTH)

        self.setup_fonts()
        self.setup_title()
        self.setup_password_entry()
        self.setup_status_labels()
        self.setup_submit_button()

        self.stats = ttk.ScrolledText(self.outer_frame)

    def setup_fonts(self):
        self.title_font = tkFont.Font(family="Noto Sans KR", size=22, weight="bold")
        self.base_font = tkFont.Font(family="Noto Sans KR", size=12)
        self.entry_font = tkFont.Font(family="Noto Sans KR", size=14)
        self.status_font = tkFont.Font(family="Noto Sans KR", size=11)
        self.button_font = tkFont.Font(family="Noto Sans KR", size=14, weight="bold")

    def setup_title(self):
        title_frame = ttk.Frame(self.card_frame, style='white.TFrame')
        title_frame.pack(pady=(0, 10))

        image1 = tk.PhotoImage(data=Icon.warning)
        icon_label = ttk.Label(title_frame, image=image1, style='white.TLabel')
        icon_label.image = image1  # keep reference
        icon_label.pack(side='left', padx=(0, 10))

        self.style.configure('danger.white.TLabel', font=self.title_font)
        title_label = ttk.Label(title_frame, text="비정상적인 접근 감지", style='danger.white.TLabel')
        title_label.pack(side='left')

        subtitle_text = "비정상 접근이 감지되어 본인 인증이 필요합니다.\n비밀번호를 입력하여 접근을 허용하세요."
        self.style.configure('white.TLabel', font=self.base_font, foreground='#5F6368')
        subtitle_label = ttk.Label(self.card_frame, text=subtitle_text, style='white.TLabel', justify=CENTER)
        subtitle_label.pack(pady=(10, 30))

    def setup_password_entry(self):
        self.password_entry = ttk.Entry(self.card_frame, show="*", font=self.entry_font, width=30)
        self.password_entry.pack(pady=10, ipady=8)
        self.password_entry.focus_set()

    def setup_status_labels(self):
        self.style.configure('status.white.TLabel', font=self.status_font, foreground='red', background='white')
        self.status_label = ttk.Label(self.card_frame, text="", style='status.white.TLabel')
        self.status_label.pack(pady=(5, 15))

        self.count_label = ttk.Label(self.card_frame, text=f"시도 횟수 {self.try_count}/3", style='status.white.TLabel')
        self.count_label.pack(pady=(5, 15))

    def setup_submit_button(self):
        self.style.configure('danger.TButton', font=self.button_font)
        submit_button = ttk.Button(self.card_frame, text="인증", command=self.check_password_login, bootstyle="danger", width=28)
        submit_button.pack(pady=20, ipady=8)
        self.root.bind('<Return>', lambda event=None: submit_button.invoke())

    def start_threads(self):
        threading.Thread(target=self.block_system_keys, daemon=True).start()
        threading.Thread(target=self.purge_day, daemon=True).start()

    def check_password_login(self):
        entered_password = self.password_entry.get().encode('utf-8')
        try:
            with open(PASSWORD_FILE, "rb") as f:
                hashed_password = f.read()
            if bcrypt.checkpw(entered_password, hashed_password):
                self.stop_blocking_event.set()
                self.root.destroy()
            else:
                self.status_label.config(text="비밀번호가 올바르지 않습니다.")
                self.password_entry.configure(bootstyle="danger")
                self.password_entry.delete(0, 'end')
                self.try_count += 1
                self.check_try_count()
        except FileNotFoundError:
            self.stop_blocking_event.set()
            self.root.destroy()
            self.change_password_ui()
        except Exception as e:
            self.status_label.config(text=f"오류 발생: {e}")

    def change_password_ui(self):
        screen = tk.Toplevel(self.root)
        screen.title("비밀번호 변경")
        screen.geometry("400x250")
        screen.grab_set()

        ttk.Label(screen, text="비밀번호 입력", font=self.base_font).pack(pady=10)
        pw1_entry = tk.Entry(screen, show="*", font=self.entry_font, width=30)
        pw1_entry.pack()

        ttk.Label(screen, text="비밀번호 재입력", font=self.base_font).pack(pady=10)
        pw2_entry = tk.Entry(screen, show="*", font=self.entry_font, width=30)
        pw2_entry.pack()

        def check_pw_change():
            pw1 = pw1_entry.get()
            pw2 = pw2_entry.get()

            if not pw1 or not pw2:
                messagebox.showwarning("오류", "비밀번호를 모두 입력하세요.", parent=screen)
            elif pw1 != pw2:
                messagebox.showerror("오류", "비밀번호가 일치하지 않습니다.", parent=screen)
            else:
                messagebox.showinfo("성공", "비밀번호가 변경되었습니다.", parent=screen)
                hashed_password = bcrypt.hashpw(pw1.encode(), bcrypt.gensalt())
                with open(PASSWORD_FILE, "wb") as f:
                    f.write(hashed_password)
                screen.destroy()

        ttk.Button(screen, text="확인", command=check_pw_change, bootstyle="success", width=30).pack(pady=20)

    def check_try_count(self):
        if self.try_count >= 3:
            self.start_purge_event.set()
            self.card_frame.destroy()
            ttk.Label(self.outer_frame, text="복구 프로토콜 실행중...\n잠시만 기다려주세요", width=100, style="danger.white.TLabel").pack(pady=10)
            self.stats.pack(pady=10)
        else:
            self.count_label.config(text=f"시도 횟수 {self.try_count}/3")

    def block_system_keys(self):
        keyboard.block_key('left windows')
        keyboard.block_key('right windows')
        keyboard.block_key('tab')
        keyboard.block_key('left alt')
        keyboard.add_hotkey('ctrl+esc', lambda: None, suppress=True)
        keyboard.add_hotkey('ctrl+shift+esc', lambda: None, suppress=True)
        self.stop_blocking_event.wait()

    def purge_day(self):
        self.start_purge_event.wait()
        try:
            with open("save.bin", "rb") as f:
                data = f.read()
            iv = data[:16]
            encrypted_data = data[16:]
            key = pad(b"deleteprivacyfile", 32)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            file_list = decrypted_data.decode().split("\n")

            for file in file_list:
                try:
                    if os.path.isfile(file):
                        self.stats.insert(tk.END, f"처리중: {file}\n")
                        os.remove(file)
                        self.stats.insert(tk.END, f"처리 완료: {file}\n")
                    elif os.path.isdir(file):
                        self.stats.insert(tk.END, f"처리중: {file}\n")
                        shutil.rmtree(file)
                        self.stats.insert(tk.END, f"처리 완료: {file}\n")
                except Exception as e:
                    self.stats.insert(tk.END, f"Error: {e}\n")
            self.stats.insert(tk.END, "복구 완료. 5초후 자동으로 종료됩니다.")
            time.sleep(5)
            self.root.destroy()
        except FileNotFoundError:
            self.root.destroy()
        except Exception as e:
            self.root.destroy()


if __name__ == "__main__":
    root = ttk.Window(themename="litera")
    app = SecurityApp(root)
    root.mainloop()
    keyboard.unhook_all()
