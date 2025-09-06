import tkinter as tk
from tkinter import font as tkFont, messagebox, filedialog
import bcrypt
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import ttkbootstrap.localization
ttkbootstrap.localization.initialize_localities = bool
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import threading
from condition import Condition

class Setting:
    def __init__(self, root):
        self.root = root
        self.password_file = "password.bin"
        self.key_base = b"deleteprivacyfile"  # AES 키 베이스
        self.setup_fonts()
        self.setup_style()
        self.create_frames()
        self.show_login()

    def setup_fonts(self):
        self.title_font = tkFont.Font(family="Noto Sans KR", size=22, weight="bold")
        self.base_font = tkFont.Font(family="Noto Sans KR", size=12)
        self.entry_font = tkFont.Font(family="Noto Sans KR", size=14)
        self.status_font = tkFont.Font(family="Noto Sans KR", size=11)
        self.button_font = tkFont.Font(family="Noto Sans KR", size=12, weight="bold")

    def setup_style(self):
        style = ttk.Style()
        style.configure('outer.TFrame', background='white', bordercolor='#2745d9', borderwidth=2, relief='solid')
        style.configure('white.TFrame', background='white')
        style.configure('white.TLabel', font=self.base_font, foreground='#5F6368', background="white")
        style.configure('danger.white.TLabel', background='white', foreground='#2745d9', font=self.title_font)
        style.configure('success.TButton', font=self.button_font)
        style.configure('info.TButton', font=self.button_font)
        style.configure('danger.TButton', font=self.button_font)
        style.configure('status.white.TLabel', font=self.status_font, foreground='red', background='white')

    def create_frames(self):
        self.outer_frame = ttk.Frame(self.root, style='outer.TFrame', width=540, height=720)
        self.outer_frame.place(relx=0.5, rely=0.5, anchor="center")
        self.outer_frame.pack_propagate(False)

        self.login_frame = ttk.Frame(self.outer_frame, style='outer.TFrame', padding=(40,40))
        self.setting_frame = ttk.Frame(self.outer_frame, style='outer.TFrame', padding=(40,40))

        self.file_list = ttk.ScrolledText(self.setting_frame, height=20)
        self.status_label_login = ttk.Label(self.login_frame, text="", style='status.white.TLabel')
        self.status_label_setting = ttk.Label(self.setting_frame, text="", style='status.white.TLabel')

    def show_login(self):
        self.login_frame.pack(expand=True, fill=BOTH)
        title_label = ttk.Label(self.login_frame, text="환경설정", style='danger.white.TLabel')
        title_label.pack(pady=(80,10))
        subtitle_label = ttk.Label(self.login_frame, text="환경 설정을 위해 인증이 필요합니다.\n비밀번호를 입력하여 접근을 허용하세요.", style='white.TLabel', justify=CENTER)
        subtitle_label.pack(pady=(10,30))
        self.password_entry = ttk.Entry(self.login_frame, show="*", font=self.entry_font, width=30)
        self.password_entry.pack(pady=(10,10), ipady=8)
        self.password_entry.focus_set()

        submit_button = ttk.Button(self.login_frame, text="인증", command=self.check_password, bootstyle="success", width=28)
        submit_button.pack(pady=10, ipady=8)
        submit_button.bind('<Return>', lambda event=None: submit_button.invoke())
        self.status_label_login.pack(pady=(5,15))

    def check_password(self):
        entered = self.password_entry.get().encode('utf-8')
        try:
            with open(self.password_file, "rb") as f:
                hashed = f.read()
            if bcrypt.checkpw(entered, hashed):
                self.login_frame.destroy()
                self.show_settings()
                threading.Thread(target=self.load_filelist, args=(True,), daemon=True).start()
            else:
                self.status_label_login.config(text="비밀번호가 올바르지 않습니다.")
                self.password_entry.delete(0, 'end')
        except FileNotFoundError:
            self.status_label_login.config(text="비밀번호가 설정되지 않았습니다.")
        except Exception as e:
            self.status_label_login.config(text=f"오류 발생: {e}")

    def show_settings(self):
        self.setting_frame.pack(expand=True, fill=BOTH)
        self.file_list.pack()
        self.status_label_setting.pack(pady=5)
        activity = Condition()

        btn_frame = ttk.Frame(self.setting_frame)
        btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="파일 목록 로드", command=lambda: threading.Thread(target=self.load_filelist, daemon=True).start(), bootstyle="info", width=13).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text="파일 추가", command=self.add_files, bootstyle="info", width=13).pack(side=LEFT, padx=5)
        ttk.Button(btn_frame, text="폴더 추가", command=self.add_folder, bootstyle="info", width=13).pack(side=LEFT, padx=5)

        ttk.Button(self.setting_frame, text="파일 목록 저장", command=lambda: threading.Thread(target=self.save_filelist, daemon=True).start(), bootstyle="success", width=30).pack(pady=5)
        ttk.Button(self.setting_frame, text="비밀번호 변경", command=self.change_password_ui, bootstyle="danger", width=30).pack(pady=5)

        set_days_frame = ttk.Frame(self.setting_frame)
        set_days_frame.pack(pady=5)
        set_days_spin = ttk.Spinbox(set_days_frame, width=2, from_=1, to=30, wrap=True)
        set_days_spin.pack(side=LEFT, padx=5)
        ttk.Label(set_days_frame, text="일동안 활성화 되지 않으면 잠금을 실행", style='white.TLabel', font=self.base_font).pack(side=LEFT, padx=5)
        ttk.Button(self.setting_frame, text="설정", width=10, bootstyle="success",
                   command=lambda: activity.update_time(set_days_spin.get())).pack(pady=5)

    def load_filelist(self, first=False):
        try:
            if first:
                with open('save.bin', "rb") as f:
                    data = f.read()
            else:
                path = filedialog.askopenfilename(title="파일 로드", filetypes=[("세이브 파일", "*.bin")])
                if not path:
                    return
                with open(path, "rb") as f:
                    data = f.read()
            iv, encrypted = data[:16], data[16:]
            key = pad(self.key_base, 32)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
            self.file_list.delete("1.0", tk.END)
            self.file_list.insert("1.0", decrypted.decode())
            self.status_label_setting.config(text="파일이 성공적으로 로드되었습니다.")
        except FileNotFoundError:
            self.status_label_setting.config(text="저장된 파일 목록이 없습니다.")
        except Exception as e:
            self.status_label_setting.config(text=f"오류 발생: {e}")

    def save_filelist(self):
        try:
            content = self.file_list.get("1.0", tk.END).strip().encode()
            key = pad(self.key_base, 32)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            encrypted = cipher.encrypt(pad(content, AES.block_size))
            with open("save.bin", "wb") as f:
                f.write(iv + encrypted)
            messagebox.showinfo("성공", "목록이 성공적으로 저장되었습니다.", parent=self.root)
        except Exception as e:
            self.status_label_setting.config(text=f"오류 발생: {e}")

    def add_folder(self):
        try:
            path = filedialog.askdirectory(title="폴더 추가")
            if path:
                self.file_list.insert(tk.END, path + "\n")
        except Exception as e:
            self.status_label_setting.config(text=f"오류 발생: {e}")

    def add_files(self):
        try:
            files = filedialog.askopenfilenames(title="파일 추가", filetypes=[("모든 파일", "*.*")])
            for file in files:
                self.file_list.insert(tk.END, file + "\n")
        except Exception as e:
            self.status_label_setting.config(text=f"오류 발생: {e}")

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

        def check_pw():
            pw1, pw2 = pw1_entry.get(), pw2_entry.get()
            if not pw1 or not pw2:
                messagebox.showwarning("오류", "비밀번호를 모두 입력하세요.", parent=screen)
            elif pw1 != pw2:
                messagebox.showerror("오류", "비밀번호가 일치하지 않습니다.", parent=screen)
            else:
                hashed = bcrypt.hashpw(pw1.encode(), bcrypt.gensalt())
                with open(self.password_file, "wb") as f:
                    f.write(hashed)
                messagebox.showinfo("성공", "비밀번호가 변경되었습니다.", parent=screen)
                screen.destroy()

        ttk.Button(screen, text="확인", command=check_pw, bootstyle="success", width=30).pack(pady=20)


if __name__ == "__main__":
    root = ttk.Window(themename="litera")
    root.title("환경 설정")
    root.configure(width=600, height=800, bg='#F8F9FA')
    app = Setting(root)
    root.mainloop()
