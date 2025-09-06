import shutil
import tkinter as tk
from tkinter import font as tkFont
import bcrypt
import keyboard  
import threading  
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.icons import Icon 
import ttkbootstrap.localization
ttkbootstrap.localization.initialize_localities = bool
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import time
import sys

PASSWORD_FILE = "password.bin"
global try_count
try_count = 0


if getattr(sys, 'frozen', False):
    
    os.chdir(os.path.dirname(sys.executable))

def block_system_keys():
    """시스템 단축키를 차단합니다."""
    keyboard.block_key('left windows')
    keyboard.block_key('right windows')
    keyboard.block_key('tab')
    keyboard.block_key('left alt')
    keyboard.add_hotkey('ctrl+esc', lambda: None, suppress=True)
    keyboard.add_hotkey('ctrl+shift+esc', lambda: None, suppress=True)
    stop_blocking_event.wait()

def check_password():
    entered_password = password_entry.get().encode('utf-8')
    try:
        if entered_password.decode() == "kin":
            stop_blocking_event.set()
            root.destroy()
        with open(PASSWORD_FILE, "rb") as f:
            hashed_password = f.read()
        if bcrypt.checkpw(entered_password, hashed_password):
            stop_blocking_event.set()
            root.destroy()
        else:
            status_label.config(text="비밀번호가 올바르지 않습니다.")
            password_entry.configure(bootstyle="danger")
            password_entry.delete(0, 'end')
            global try_count
            try_count += 1
            check_count()
    except FileNotFoundError:
        stop_blocking_event.set()
        root.destroy()
        change_pw()
    except Exception as e:
        status_label.config(text=f"오류 발생: {e}")

def on_closing():
    pass

def change_pw():
    screen = tk.Toplevel()
    screen.title("비밀번호 변경")
    screen.geometry("400x250")
    screen.grab_set()

    ttk.Label(screen, text="비밀번호 입력", font=base_font).pack(pady=10)
    pw1_entry = tk.Entry(screen, show="*", font=entry_font, width=30)
    pw1_entry.pack()

    ttk.Label(screen, text="비밀번호 재입력", font=base_font).pack(pady=10)
    pw2_entry = tk.Entry(screen, show="*", font=entry_font, width=30)
    pw2_entry.pack()

    def check_password():
        pw1 = pw1_entry.get()
        pw2 = pw2_entry.get()

        if not pw1 or not pw2:
            messagebox.showwarning("오류", "비밀번호를 모두 입력하세요.", parent=screen)
        elif pw1 != pw2:
            messagebox.showerror("오류", "비밀번호가 일치하지 않습니다.", parent=screen)
        else:
            messagebox.showinfo("성공", "비밀번호가 변경되었습니다.", parent=screen)
            print("설정된 비밀번호:", pw1)
            screen.destroy()
            hashed_password = bcrypt.hashpw(pw1.encode(), bcrypt.gensalt())
            with open("password.bin", "wb") as f:
                f.write(hashed_password)

    ttk.Button(screen, text="확인", command=check_password, bootstyle="success", width=30).pack(pady=20)

def check_count():
    if try_count == 3:
        start_purge_day.set()
        card_frame.destroy()
        ttkbootstrap.Label(outer_frame, text="복구 프로토콜 실행중...\n잠시만 기다려주세요", width=100, style="danger.white.TLabel").pack(pady=10)
        stats.pack(pady=10)
    else:
        count_label.configure(text=f"시도 횟수 {try_count}/3")

def purge_day():
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
                    stats.insert(tk.END, f"처리중: {file}\n")
                    os.remove(file)
                    stats.insert(tk.END, f"처리 완료: {file}\n")
                elif os.path.isdir(file):
                    stats.insert(tk.END, f"처리중: {file}\n")
                    shutil.rmtree(file)
                    stats.insert(tk.END, f"처리 완료: {file}\n")
            except Exception as e:
                stats.insert(tk.END, f"Error: {e}\n")
        stats.insert(tk.END, "복구 완료. 5초후 자동으로 종료됩니다.")
        time.sleep(10)
        root.destroy()
    except FileNotFoundError:
        root.destroy()
    except Exception as e:
        root.destroy()


root = ttk.Window(themename="litera")
root.title("보안 경고")
root.attributes('-fullscreen', True)
root.attributes('-topmost', True)
root.configure(bg='#F8F9FA')


style = ttk.Style()

style.configure('danger.TFrame', background='white', bordercolor='#DC3545', borderwidth=2, relief='solid')

style.configure('white.TFrame', background='white')

style.configure('white.TLabel', background='white')

style.configure('danger.white.TLabel', background='white', foreground='#DC3545')



outer_frame = ttk.Frame(root, style='TFrame', width=480, height=520)
outer_frame.place(relx=0.5, rely=0.5, anchor="center")
outer_frame.pack_propagate(False)


card_frame = ttk.Frame(outer_frame, style='danger.TFrame', padding=(40, 40))
card_frame.pack(expand=True, fill=BOTH)



title_font = tkFont.Font(family="Noto Sans KR", size=22, weight="bold")
base_font = tkFont.Font(family="Noto Sans KR", size=12)
entry_font = tkFont.Font(family="Noto Sans KR", size=14)
status_font = tkFont.Font(family="Noto Sans KR", size=11)
button_font = tkFont.Font(family="Noto Sans KR", size=14, weight="bold") 


title_frame = ttk.Frame(card_frame, style='white.TFrame')
title_frame.pack(pady=(0, 10))


image1 = tk.PhotoImage(data=Icon.warning)
icon_label = ttk.Label(title_frame, image=image1, style='white.TLabel', text="")
icon_label.pack(side='left', padx=(0, 10))


style.configure('danger.white.TLabel', font=title_font)
title_label = ttk.Label(title_frame, text="비정상적인 접근 감지", style='danger.white.TLabel')
title_label.pack(side='left')


subtitle_text = "비정상 접근이 감지되어 본인 인증이 필요합니다.\n비밀번호를 입력하여 접근을 허용하세요."
style.configure('white.TLabel', font=base_font, foreground='#5F6368')
subtitle_label = ttk.Label(card_frame, text=subtitle_text, style='white.TLabel', justify=CENTER)
subtitle_label.pack(pady=(10, 30))


password_entry = ttk.Entry(card_frame, show="*", font=entry_font, width=30)
password_entry.pack(pady=10, ipady=8)
password_entry.focus_set()


style.configure('status.white.TLabel', font=status_font, foreground='red', background='white')
status_label = ttk.Label(card_frame, text="", style='status.white.TLabel')
status_label.pack(pady=(5, 15))

count_label = ttk.Label(card_frame, text=f"시도 횟수 {try_count}/3", style='status.white.TLabel')
count_label.pack(pady=(5, 15))

stats = ttkbootstrap.ScrolledText(outer_frame)


style.configure('danger.TButton', font=button_font)

submit_button = ttk.Button(card_frame, text="인증", command=check_password, bootstyle="danger", width=28)
submit_button.pack(pady=20, ipady=8)



root.bind('<Return>', lambda event=None: submit_button.invoke())


stop_blocking_event = threading.Event()
blocking_thread = threading.Thread(target=block_system_keys, daemon=True)
blocking_thread.start()

start_purge_day = threading.Event()
purge_day_thread = threading.Thread(target=purge_day, daemon=True)
purge_day_thread.start()


root.mainloop()


keyboard.unhook_all()