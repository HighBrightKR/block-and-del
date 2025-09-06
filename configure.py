import tkinter as tk
from tkinter import font as tkFont
import bcrypt
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import ttkbootstrap.localization
ttkbootstrap.localization.initialize_localities = bool
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from tkinter import messagebox, filedialog

global PW
PW = b"deleteprivacyfile"

def check_password():
    entered_password = password_entry.get().encode('utf-8')
    try:
        with open("password.bin", "rb") as f:
            hashed_password = f.read()
        if bcrypt.checkpw(entered_password, hashed_password):
            call_setting()
        else:
            status_label.config(text="비밀번호가 올바르지 않습니다.")
            password_entry.configure(bootstyle="danger")
            password_entry.delete(0, 'end')
    except FileNotFoundError:
        status_label.config(text="비밀번호가 설정되지 않았습니다.")

    except Exception as e:
        status_label.config(text=f"오류 발생: {e}")

def load_filelist():
    try:
        path = filedialog.askopenfilename(
            title="파일 로드",
            filetypes=[("세이브 파일", "*.bin")]
        )
        if not path:
            return
        with open(path, "rb") as f:
            data = f.read()
        iv = data[:16]
        encrypted_data = data[16:]
        key = pad(PW, 32)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        file_list.delete("1.0", tk.END)
        file_list.insert("1.0", decrypted_data.decode())
        status_label_2.config(text="파일이 성공적으로 로드되었습니다.")
    except FileNotFoundError:
        status_label_2.config(text="저장된 파일 목록이 없습니다.")
    except Exception as e:
        status_label_2.config(text=f"오류 발생: {e}")


def on_closing():
    pass

def call_setting():
    login_frame.destroy()
    setting_pack()


def save_filelist():
    try:
        content = file_list.get("1.0", tk.END)
        data = content.strip().encode()
        key = pad(PW, 32)  # AES 256
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        with open("save.bin", "wb") as f:
            f.write(iv + encrypted_data)

        messagebox.showinfo("성공", "목록이 성공적으로 저장되었습니다.", parent=root)
    except Exception as e:
        status_label_2.config(text=f"오류 발생: {e}")

def add_folder():
    try:
        path = filedialog.askdirectory(title="폴더 추가")
        file_list.insert(tk.END, path+"\n")
    except Exception as e:
        status_label_2.config(text=f"오류 발생: {e}")

def add_files():
    try:
        files = filedialog.askopenfilenames(title="파일 추가", filetypes=[("모든 파일", "*.*")])
        for file in files:
            file_list.insert(tk.END, file+"\n")
    except Exception as e:
        status_label_2.config(text=f"오류 발생: {e}")

def change_pw():
    screen = tk.Toplevel(root)
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
            hashed_password = bcrypt.hashpw(PW.encode(), bcrypt.gensalt())
            with open("password.bin", "wb") as f:
                f.write(hashed_password)

    ttk.Button(screen, text="확인", command=check_password, bootstyle="success", width=30).pack(pady=20)




# GUI
root = ttk.Window(themename="litera")
root.title("환경 설정")
root.configure(width=600, height=800)
root.configure(bg='#F8F9FA')

# 외부 프레임
outer_frame = ttk.Frame(root, style='TFrame', width=540, height=720)
outer_frame.place(relx=0.5, rely=0.5, anchor="center")
outer_frame.pack_propagate(False)

# 폰트 및 스타일
title_font = tkFont.Font(family="Noto Sans KR", size=22, weight="bold")
base_font = tkFont.Font(family="Noto Sans KR", size=12)
entry_font = tkFont.Font(family="Noto Sans KR", size=14)
status_font = tkFont.Font(family="Noto Sans KR", size=11)
button_font = tkFont.Font(family="Noto Sans KR", size=12, weight="bold")

style = ttk.Style()
style.configure('outer.TFrame', background='white', bordercolor='#2745d9', borderwidth=2, relief='solid')
style.configure('white.TFrame', background='white')
style.configure('white.TLabel', font=base_font, foreground='#5F6368', background="white")
style.configure('danger.white.TLabel', background='white', foreground='#2745d9', font=title_font)
style.configure('success.TButton', font=button_font)
style.configure('info.TButton', font=button_font)
style.configure('danger.TButton', font=button_font)
style.configure('status.white.TLabel', font=status_font, foreground='red', background='white')


#region 인증

# 내부 카드 프레임
login_frame = ttk.Frame(outer_frame, style='outer.TFrame', padding=(40, 40))
login_frame.pack(expand=True, fill=BOTH)

# 제목
title_label = ttk.Label(login_frame, text="환경설정", style='danger.white.TLabel')
title_label.pack(pady=(80, 10))

# 부제목
subtitle_text = "환경 설정을 위해 인증이 필요합니다.\n비밀번호를 입력하여 접근을 허용하세요."
subtitle_label = ttk.Label(login_frame, text=subtitle_text, style='white.TLabel', justify=CENTER)
subtitle_label.pack(pady=(10, 30))

# 비밀번호 엔트리
password_entry = ttk.Entry(login_frame, show="*", font=entry_font, width=30)
password_entry.pack(pady=(10, 10), ipady=8)
password_entry.focus_set()

# 상태 메시지
status_label = ttk.Label(login_frame, text="", style='status.white.TLabel')
status_label.pack(pady=(5, 15))

# 확인 버튼
submit_button = ttk.Button(login_frame, text="인증", command=check_password, bootstyle="success", width=28)
submit_button.pack(pady=10, ipady=8)
submit_button.bind('<Return>', lambda event=None: submit_button.invoke())

#endregion


#region 설정 카드 프레임

setting_frame = ttk.Frame(outer_frame, style='outer.TFrame', padding=(40, 40))
load_list_btn = ttk.Button(setting_frame, text="파일 목록 로드", command=load_filelist, bootstyle="info", width=30)
file_list = ttk.ScrolledText(setting_frame, height=20)
status_label_2 = ttk.Label(setting_frame, text="", style='status.white.TLabel')
btn_frame = ttk.Frame(setting_frame)
add_files_btn = ttk.Button(btn_frame, text="파일 추가", command=add_files, bootstyle="info", width=13)
add_folder_btn = ttk.Button(btn_frame, text="폴더 추가", command=add_folder, bootstyle="info", width=13)
save_list_btn = ttk.Button(setting_frame, text="파일 목록 저장", command=save_filelist, bootstyle="success", width=30)
change_pw_btn = ttk.Button(setting_frame, text="비밀번호 변경", command=change_pw, bootstyle="danger", width=30)
alert_label = ttk.Label(setting_frame, text="비밀번호 변경 혹은 파일 분실시 파일 목록 로드는 불가능합니다.", style='white.TLabel', font=base_font)


def setting_pack():
    setting_frame.pack(expand=True, fill=BOTH)
    alert_label.pack(pady=5)
    load_list_btn.pack(pady=5)
    file_list.pack()
    status_label_2.pack(pady=(5, 15))
    btn_frame.pack(pady=5)
    add_files_btn.pack(side=LEFT, padx=5)
    add_folder_btn.pack(side=LEFT, padx=5)
    save_list_btn.pack(pady=5)
    change_pw_btn.pack(pady=5)

root.mainloop()