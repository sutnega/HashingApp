import os
import json
import tkinter as tk
from tkinter import filedialog
from Crypto.Hash import MD2  #pip install pycryptodome
from cryptography.fernet import Fernet #pip install cryptography   (шифрование самого файла)
from tkinter import ttk
from tkinter import messagebox, simpledialog
import re
BROKEN_ENCRYPT =0  # шифрование работает - 0,  шифрование сломалось - 1
def on_frame_configure(canvas):
    canvas.configure(scrollregion=canvas.bbox("all"))

class App:
    def __init__(self) -> None:
        self.input_error_password = 0
        self.b_Admin = False
        self.current_user = None
        self.dictRestrict = dict()

        self.root = tk.Tk()
        self.root.title("Application Gulinkin")
        self.root.geometry("500x520")
        self.root.minsize(500, 520)

        menu_bar = tk.Menu(self.root)
        menu_bar.add_cascade(label="Выход", command=self.exit_app)
        menu_info = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Справка", menu=menu_info)
        
        menu_info.add_command(label="О программе", command=self.open_about)

        self.root.config(menu=menu_bar)

        self.signin_widgets = [
            tk.Label(self.root, text="Имя пользователя:"), #0
            tk.Entry(self.root),#1 login
            tk.Label(self.root, text="Пароль:"),#2
            tk.Entry(self.root, show="*"),#3 password
            tk.Button(self.root, command=self.SignIn, text="Вход")#4
        ]

        for item in self.signin_widgets:
            item.pack()

        self.admin_widgets = [
            tk.Button(self.root, text="Сменить пароль", command=self.change_password),
            tk.Button(self.root, text="Просмотр списка пользователей", command=self.view_user_list),
            tk.Button(self.root, text="Управление пользователями", command=self.add_new_user),
            tk.Button(self.root, text="Заблокировать пользователя", command=self.block_user),
            tk.Button(self.root, text="Завершить сессию", command=self.exit_account)
        ]
        self.user_widgets = [
            tk.Button(self.root, text="Сменить пароль", command=self.change_password),
            tk.Button(self.root, text="Завершить сессию", command=self.exit_account)
        ]

        self.root.mainloop()

    def SignIn(self):
        tLogin = self.signin_widgets[1].get()
        tPassword = self.signin_widgets[3].get()

        with open("data.json") as file:
            self.data = json.load(file)

        for item in self.data["users"]:
            if item["password"] == tPassword and item["login"] == tLogin:
                if item["blocked"]:
                    messagebox.showerror("Ошибка", "Вы заблокированы")
                    return

                self.b_Admin = item["admin"]
                self.current_user = item
                
                for item in self.signin_widgets:
                    item.pack_forget()

                if self.b_Admin:
                    for widget in self.admin_widgets:
                        widget.pack()
                else:
                    for widget in self.user_widgets:
                        widget.pack()

                self.input_error_password = 0

                for item in self.data["users"]:
                    self.dictRestrict[item["id"]] = item["restrictions"]

                return
        
        messagebox.showerror(
        "Приложение",
        "Неправильный логин или пароль",
        )

        self.input_error_password = self.input_error_password + 1

        if self.input_error_password == 3:
            self.root.destroy()
            exit(1)

        pass

    def exit_app(self):
        exit(0)

    def open_about(self):
        child = tk.Toplevel(self.root)
        child.title("О Приложении")

        with open("readme.txt", "r", encoding="utf-8") as file:
            about_txt = file.read().replace("#", "").replace("*", "")
        lbl_about = tk.Label(child, text=about_txt, justify="left")
        lbl_about.pack()

        child.transient(self.root)
        child.grab_set()
        child.focus_set()
        child.wait_window()

    def change_password(self):
        old_password = simpledialog.askstring("Смена пароля", "Введите старый пароль:")

        if old_password is None:
            return 
        
        if old_password == self.current_user["password"]:
            new_password = simpledialog.askstring("Смена пароля", "Введите новый пароль:")

            if new_password is None:
                return
            #ограничения для нового пароля
            if (self.current_user["restrictions"]):
                has_latin    = re.search(r'[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]', new_password)
                has_operators = re.search(r'[абвгдеёжзиклмнопрстуфхцчшщъыьэюяБВГДЕЁЖЗИКЛМНОПРСТУФХЦЧШЩЬЫЪЭЮЯ]', new_password)
                if has_latin and has_operators:
                    self.current_user["password"] = new_password
                else:
                     messagebox.showerror("Смена пароля", "Пароль должен содержать кириллицу и латиницу")
                     return
            else:
                self.current_user["password"] = new_password
                
            messagebox.showinfo("Смена пароля", "Пароль успешно изменен.")
            self.save_changes(self.data)
        else:
            messagebox.showerror("Ошибка", "Неверный старый пароль.")

    def view_user_list(self): #отображение списка пользователей
        user_list = tk.Toplevel(self.root)
        user_list.title("Список пользователей")
        canvas = tk.Canvas(user_list)
        canvas.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(canvas, orient='vertical', command=canvas.yview)
        scrollbar.pack(side='right', fill='y')
        
        canvas.configure(yscrollcommand=scrollbar.set)
        frm_info = tk.Frame(canvas)
        canvas.create_window((0, 0), window=frm_info, anchor='nw')

        frm_info.bind(
            "<Configure>", lambda event, canvas=canvas: on_frame_configure(canvas)
        )

        for item in self.data["users"]:
            frm_user = tk.Frame(frm_info)

            tAdmin = "Admin"
            tBlock = "Work"

            if item["admin"]:
                tAdmin="User"

            if item["blocked"]:
                tBlock = "Ban"

            check_var = tk.IntVar(value=item["restrictions"])

            # Используйте переменную check_var при создании Checkbutton
            check_button = tk.Checkbutton(frm_user, variable=check_var)

            widgets_array = [
                tk.Label(frm_user, text=item["id"]),
                tk.Label(frm_user, text=item["login"]),
                tk.Label(frm_user, text=item["password"]),
                tk.Label(frm_user, text= tAdmin),
                tk.Label(frm_user, text= tBlock),
                tk.Label(frm_user, text="Restriction"),
                check_button
            ]

            check_button.config(command=lambda label=item["id"], var=check_var: self.on_check_click(label, var))

            for i, widget in enumerate(widgets_array):
                widget.grid(row=0, column=i, padx=5, pady=5, sticky="w")
            
            frm_user.pack(side=tk.TOP)

        btn = tk.Button(user_list, command=lambda : self.save_changes(self.data), text="Изменить")
        btn.pack(side=tk.BOTTOM)    

    def on_check_click(self, label, var):
        user = next((user for user in self.data["users"] if user["id"] == label), None)
        if user:
            user["restrictions"] = var.get() == 1

    def add_new_user(self):
        count_users = len(self.data["users"])
        new_username = simpledialog.askstring("Добавление нового пользователя", "Введите имя нового пользователя:")

        if new_username is None:
            return

        self.data["users"].append({"id": count_users, "login": new_username, "password": "", "admin": False, "blocked": False, "restrictions":False})
        messagebox.showinfo("Добавление нового пользователя", f"Пользователь {new_username} успешно добавлен.")
        self.save_changes(self.data)

    def block_user(self):
        username_to_block = simpledialog.askstring("Блокировка пользователя", "Введите имя пользователя для блокировки:")

        if username_to_block is None:
            return

        for user in self.data["users"]:
            if user["login"] == username_to_block:
                user["blocked"] = True
                messagebox.showinfo("Блокировка пользователя", f"Пользователь {username_to_block} успешно заблокирован.")
                self.save_changes(self.data)
                return
        messagebox.showerror("Ошибка", f"Пользователь {username_to_block} не найден.")
    
    def exit_account(self):
        if self.b_Admin:
            for item in self.admin_widgets:
                item.pack_forget()
        else:
            for item in self.user_widgets:
                item.pack_forget()

        for item in self.signin_widgets:
            item.pack()

    def save_changes(self, data: json):
        with open("data.json", "w") as file:
            json.dump(data, file)

#создание шифрования _________________________________________
def write_key():
    # Создаем ключ и сохраняем его в файл
    key = Fernet.generate_key()
    with open('crypto.key', 'wb') as key_file:
        key_file.write(key)

def load_key():
    # Загружаем ключ 'crypto.key' из текущего каталога
    return open('crypto.key', 'rb').read()

def encrypt(filename, key):
    f = Fernet(key) # Зашифруем файл и записываем его
    with open(filename, 'rb') as file:
        file_data = file.read()   # прочитать все данные файла
        encrypted_data = f.encrypt(file_data) # Зашифровать данные
    # записать зашифрованный файл пересоздав его
    with open(filename, 'wb') as file:
        file.write(encrypted_data)

def decrypt(filename, key):
# Расшифруем файл и записываем его
    f = Fernet(key)
    with open(filename, 'rb') as file:
        # читать зашифрованные данные
        encrypted_data = file.read()
    # расшифровать данные
    decrypted_data = f.decrypt(encrypted_data)
    # записать оригинальный файл
    with open(filename, 'wb') as file:
        file.write(decrypted_data)
#_______________________________________________________________________

def generate_hashM2(text):
    hashObject = MD2.new()
    hashObject.update(text.encode('utf-8'))
    digest = hashObject.hexdigest()
    return(digest)

def main():


    key = load_key()
    file='data.json'
    if not BROKEN_ENCRYPT:
        decrypt(file, key)  #расшифровать файл

    app = App()

    encrypt(file, key)  #зашифровать файл обратно

if __name__ == "__main__":
    main()