import sqlite3
import string
import random
import re
import hashlib
import customtkinter as ctkt
from CTkMessagebox import CTkMessagebox
from customtkinter import CTkCanvas
from customtkinter import IntVar
from cryptography.fernet import Fernet
import bcrypt
import pyperclip

class LoginPage(ctkt.CTk):
    def __init__(self):
        super().__init__()
        ctkt.set_appearance_mode("dark")
        self.geometry("350x400")
        self.title("PassGenX")
        self.resizable(False, False)

        self.conn = sqlite3.connect("userdata.db")
        self.cursor = self.conn.cursor()

        self.label = ctkt.CTkLabel(self, text="Login", font=("Arial", 30))
        self.label.pack(padx=10, pady=30)

        self.username_entry = ctkt.CTkEntry(self, width=300, placeholder_text="Username")
        self.username_entry.pack(padx=10, pady=10)

        self.password_entry = ctkt.CTkEntry(self, placeholder_text="Password", show="*", width=300)
        self.password_entry.pack(padx=10, pady=10)

        self.max_attempts_label = ctkt.CTkLabel(self, text="", font=ctkt.CTkFont(size=12))
        self.max_attempts_label.pack(padx=5)

        self.button_frame = ctkt.CTkFrame(self, fg_color="transparent")
        self.button_frame.pack(padx=5, pady=5)

        self.login_button = ctkt.CTkButton(self.button_frame, text="Login", command=self.login)
        self.login_button.pack(padx=10, pady=10, side="left")

        self.signup_button = ctkt.CTkButton(self.button_frame, text="Sign Up",
                                            command=self.open_signup_page)
        self.signup_button.pack(padx=10, pady=10)

        self.failed_attempts = 0


        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def login(self):
        self.password = self.password_entry.get()
        self.username = self.username_entry.get()

        if self.username != "" and self.password != "":
            sql = "SELECT password FROM userdata WHERE username = ?"
            self.cursor.execute(sql, (self.username,))
            self.result = self.cursor.fetchone()
            if self.result:
                if bcrypt.checkpw(self.password.encode("utf-8"), self.result[0]):
                    self.messagebox = CTkMessagebox(title="Success", message="Login Successfully.",
                                                    icon="check")
                    self.withdraw()
                    self.root = App()
                    self.root.mainloop()
                else:
                    if self.failed_attempts == 5:
                        self.login_button.configure(state="disable")
                        self.username_entry.configure(state="disable")
                        self.password_entry.configure(state="disable")
                        self.max_attempts_label.configure(
                            text="Too many attempts. Please restart the app to login again!",
                            text_color="red")
                    else:
                        self.failed_attempts += 1
                        self.max_attempts_label.configure(text="Invalid Username or Password!",
                                                          text_color="red")
            else:
                if self.failed_attempts == 5:
                    self.login_button.configure(state="disable")
                    self.username_entry.configure(state="disable")
                    self.password_entry.configure(state="disable")
                    self.max_attempts_label.configure(text="Too many attempts. Please restart the app to login again!",
                                                      text_color="red")
                else:
                    self.failed_attempts += 1
                    self.max_attempts_label.configure(text="Invalid Username or Password!",
                                                      text_color="red")
        else:
            self.max_attempts_label.configure(text="Please enter all data!",
                                              text_color="red")
    def open_signup_page(self):
        self.withdraw()  # Hide the login page
        self.signup_page = SignupPage(self)  # Create the signup page object
        self.signup_page.mainloop()  # Start the event loop for the signup page

    def on_closing(self):
        self.messagebox = CTkMessagebox(title="Exit?", message="Do you want to close the program?",
                                        icon="question", option_1="No", option_2="Yes")
        response = self.messagebox.get()
        if response == "Yes":
            self.destroy()

class SignupPage(ctkt.CTk):
    def __init__(self, parent):
        super().__init__()

        self.parent = parent

        self.title("PassGenX")
        self.geometry("500x320")

        self.resizable(False, False)

        self.conn = sqlite3.connect("userdata.db")
        self.cursor = self.conn.cursor()

        self.cursor.execute("""
            CREATE TABLE IF NOT EXISTS userdata (
                username TEXT NOT NULL,
                password TEXT NOT NULL)""")

        self.entry_frame = ctkt.CTkFrame(self, height=60, fg_color="transparent")
        self.entry_frame.grid(row=0, column=0, sticky="news")
        self.label = ctkt.CTkLabel(self.entry_frame, text="Sign Up", font=("Arial", 30))
        self.label.grid(row=1, column=0, padx=60, pady=5, sticky="e")
        self.username_entry = ctkt.CTkEntry(self.entry_frame, width=300, placeholder_text="Username")
        self.username_entry.grid(row=2, column=0, padx=25, pady=5, sticky="w")
        self.password_entry1 = ctkt.CTkEntry(self.entry_frame, placeholder_text="Password", show="*", width=300)
        self.password_entry1.grid(row=3, column=0, padx=25, pady=5, sticky="w")
        self.password_entry1.bind("<KeyRelease>", lambda event: self.pass_entry_check(self.password_entry1.get()))
        self.password_entry2 = ctkt.CTkEntry(self.entry_frame, placeholder_text="Re-entered Password", show="*",
                                             width=300)
        self.password_entry2.grid(row=4, column=0, padx=25, pady=5, sticky="w")
        self.password_entry2.bind("<KeyRelease>", lambda event: self.update_pass_label())
        self.show_pass_button = ctkt.CTkButton(self.entry_frame, text="Show password", width=40,
                                               font=ctkt.CTkFont(size=12), command=self.show_pass)
        self.show_pass_button.grid(row=3, column=1, pady=5, sticky="w")
        self.pass_label = ctkt.CTkLabel(self.entry_frame, text="", font=ctkt.CTkFont(size=12, weight="bold"))
        self.pass_label.grid(row=4, column=1, pady=5, sticky="w")

        self.label_frame = ctkt.CTkFrame(self, fg_color="transparent")
        self.label_frame.grid(row=2, column=0, sticky="sew")
        self.password_requirements_label1 = ctkt.CTkLabel(
            self.label_frame, text="Minimum 8 characters", text_color="red", font=ctkt.CTkFont(size=12))
        self.password_requirements_label1.grid(row=0, column=0, padx=30, sticky="w")
        self.password_requirements_label2 = ctkt.CTkLabel(
            self.label_frame, text="At least 1 Uppercase character", text_color="red", font=ctkt.CTkFont(size=12))
        self.password_requirements_label2.grid(row=0, column=1, padx=10, sticky="w")
        self.password_requirements_label3 = ctkt.CTkLabel(
            self.label_frame, text="At least 1 Lowercase character", text_color="red", font=ctkt.CTkFont(size=12))
        self.password_requirements_label3.grid(row=1, column=0, padx=30, sticky="w")
        self.password_requirements_label4 = ctkt.CTkLabel(
            self.label_frame, text="At least 1 digit", text_color="red", font=ctkt.CTkFont(size=12))
        self.password_requirements_label4.grid(row=1, column=1, padx=10, sticky="w")
        self.password_requirements_label5 = ctkt.CTkLabel(
            self.label_frame, text="At least 1 Special character", text_color="red", font=ctkt.CTkFont(size=12))
        self.password_requirements_label5.grid(padx=30, pady=5, sticky="w")

        self.button_frame = ctkt.CTkFrame(self, fg_color="transparent")
        self.button_frame.grid(pady=5, sticky="new")
        self.signup_button = ctkt.CTkButton(self.button_frame, text="Sign Up", command=self.signup)
        self.signup_button.grid(row=0, column=0, padx=60, pady=5, sticky="w")
        self.back_button = ctkt.CTkButton(self.button_frame, text="Back to Login", command=self.go_back_to_login)
        self.back_button.grid(row=0, column=1, padx=5, pady=5, sticky="e")

        self.protocol("WM_DELETE_WINDOW", self.on_closing)



    def change_color_label(self, password):
        self.has_digits = any(char.isdigit() for char in password)
        self.has_lowercase = any(char.islower() for char in password)
        self.has_uppercase = any(char.isupper() for char in password)
        self.has_special_chars = any(char in string.punctuation for char in password)
        self.is_long_enough = len(password) > 8
        if self.is_long_enough:
            self.password_requirements_label1.configure(text_color="green")
        else:
            self.password_requirements_label1.configure(text_color="red")
        if self.has_uppercase:
            self.password_requirements_label2.configure(text_color="green")
        else:
            self.password_requirements_label2.configure(text_color="red")
        if self.has_lowercase:
            self.password_requirements_label3.configure(text_color="green")
        else:
            self.password_requirements_label3.configure(text_color="red")
        if self.has_digits:
            self.password_requirements_label4.configure(text_color="green")
        else:
            self.password_requirements_label4.configure(text_color="red")
        if self.has_special_chars:
            self.password_requirements_label5.configure(text_color="green")
        else:
            self.password_requirements_label5.configure(text_color="red")
    def pass_entry_check(self, password):
        self.change_color_label(password)

    def show_pass(self):
        if self.password_entry1.cget("show") == "*" or self.password_entry2.cget("show") == "*":
            self.password_entry1.configure(show="")
            self.password_entry2.configure(show="")
            self.show_pass_button.configure(text="Hide Password")
        else:
            self.password_entry1.configure(show="*")
            self.password_entry2.configure(show="*")
            self.show_pass_button.configure(text="Show Password")

    def go_back_to_login(self):
        self.parent.deiconify()
        self.destroy()
    def update_pass_label(self):
        password1 = self.password_entry1.get()
        password2 = self.password_entry2.get()
        if password1 == password2:
            self.pass_label.configure(text="Passwords Match!", text_color="green")
        else:
            self.pass_label.configure(text="Passwords Don't Match!", text_color="red")
        if not password2:
            self.pass_label.configure(text="")

    def signup(self):
        self.username = self.username_entry.get()
        self.password1 = self.password_entry1.get()
        self.password2 = self.password_entry2.get()
        if self.password1 != self.password2:
            self.messagebox = CTkMessagebox(title="Error", message="Passwords do not match!", icon="warning")
            return
        if self.username != "" and self.password1 != "" and self.password2 != "":
            self.cursor.execute("SELECT username FROM userdata WHERE username=?", [self.username])
            if self.cursor.fetchone() is not None:
                self.messagebox = CTkMessagebox(title="Error", message="Username already exists.", icon="warning")
            else:
                self.encode_password = self.password1.encode("utf-8")
                self.hashed_password = bcrypt.hashpw(self.encode_password, bcrypt.gensalt())
                self.sql = "INSERT INTO userdata VALUES (?, ?)"
                self.cursor.execute(self.sql, [self.username, self.hashed_password])
                self.conn.commit()
                self.messagebox = CTkMessagebox(title="Signup success", message="Account has been created.",
                                                    icon="check")
                self.parent.deiconify()
                self.destroy()
        else:
            self.messagebox = CTkMessagebox(title="Error", message="Enter all data.", icon="warning")

    def on_closing(self):
        self.messagebox = CTkMessagebox(title="Exit?", message="Do you want to close the program?",
                                        icon="question", option_1="No", option_2="Yes")
        response = self.messagebox.get()
        if response == "Yes":
            self.parent.destroy()
            self.destroy()
class App(ctkt.CTk):
    def __init__(self):
        super().__init__()
        ctkt.set_appearance_mode("dark")
        self.title("PassGenX")
        self.geometry("1100x450")
        self.resizable(False, False)

        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # create navigation frame
        self.navigation_frame = ctkt.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="new")
        self.navigation_frame.grid_columnconfigure(8, weight=1)
        # app label
        self.app_label = ctkt.CTkLabel(self.navigation_frame, text="PassGenX", compound="left",
                                       font=ctkt.CTkFont(size=20, weight="bold"))
        self.app_label.grid(row=0, column=0, padx=40, pady=5)
        # navigation button
        self.home_button = ctkt.CTkButton(self.navigation_frame, corner_radius=12, height=40, border_spacing=10,
                                          text="Home", fg_color="transparent", text_color=("gray10", "gray90"),
                                          hover_color=("gray70", "gray30"), command=self.home_button_event,
                                          font=ctkt.CTkFont(size=14, weight="bold"))
        self.home_button.grid(row=0, column=1, padx=5, pady=4, sticky="ns")
        self.password_generation_button = ctkt.CTkButton(self.navigation_frame, corner_radius=12, height=40,
                                                         border_spacing=10, text="Password \nGeneration",
                                                         fg_color="transparent", text_color=("gray10", "gray90"),
                                                         hover_color=("gray70", "gray30"),
                                                         command=self.password_generation_button_event,
                                                         font=ctkt.CTkFont(size=14, weight="bold"))
        self.password_generation_button.grid(row=0, column=2, padx=5, pady=4, sticky="ns")
        self.password_checker_button = ctkt.CTkButton(self.navigation_frame, corner_radius=12, height=40,
                                                      border_spacing=10, text="Password \nChecker",
                                                      fg_color="transparent", text_color=("gray10", "gray90"),
                                                      hover_color=("gray70", "gray30"),
                                                      command=self.password_checker_button_event,
                                                      font=ctkt.CTkFont(size=14, weight="bold"))
        self.password_checker_button.grid(row=0, column=3, padx=5, pady=4, sticky="ns")

        self.data_encryption_button = ctkt.CTkButton(self.navigation_frame, corner_radius=12, height=40,
                                                     border_spacing=10, text="Data \nEncryption",
                                                     fg_color="transparent", text_color=("gray10", "gray90"),
                                                     hover_color=("gray70", "gray30"),
                                                     command=self.data_encryption_button_event,
                                                     font=ctkt.CTkFont(size=14, weight="bold"))
        self.data_encryption_button.grid(row=0, column=4, padx=5, pady=4, sticky="ns")
        self.data_hasher_button = ctkt.CTkButton(self.navigation_frame, corner_radius=12, height=40, border_spacing=10,
                                                 text="Data \nHasher", fg_color="transparent", text_color=("gray10", "gray90"),
                                                 hover_color=("gray70", "gray30"), command=self.data_hasher_button_event,
                                                 font=ctkt.CTkFont(size=14, weight="bold"))
        self.data_hasher_button.grid(row=0, column=5, padx=5, pady=4, sticky="ns")
        self.setting_button = ctkt.CTkButton(self.navigation_frame, corner_radius=12, height=40, border_spacing=10,
                                             text="Setting", fg_color="transparent", text_color=("gray10", "gray90"),
                                             hover_color=("gray70", "gray30"), command=self.setting_button_event,
                                             font=ctkt.CTkFont(size=14, weight="bold"))
        self.setting_button.grid(row=0, column=6, padx=5, pady=4, sticky="ns")

        # Home frame
        self.home_frame = ctkt.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid(row=0, column=0, )
        self.home_frame.grid_columnconfigure(0, weight=1)
        self.home_frame.grid_rowconfigure(4, weight=1)

        self.space_label = ctkt.CTkLabel(self.home_frame, text="", )
        self.space_label.grid(row=0, column=0, padx=10, pady=10)
        self.application_description_label = ctkt.CTkLabel(self.home_frame, text="Welcome to PassGenX",
                                                           font=ctkt.CTkFont(size=40, weight="bold"))
        self.application_description_label.grid(row=1, column=0, padx=10, pady=10)
        self.application_description_label2 = ctkt.CTkLabel(self.home_frame, text="Secure your passwords. Simplify your life.",
                                                            font=ctkt.CTkFont(size=25, weight="bold"))
        self.application_description_label2.grid(row=2, column=0, padx=10, pady=10)
        self.application_description_label3 = ctkt.CTkLabel(self.home_frame,
                                                            text="(*This app is still in a beta version and "
                                                                 "still in develop process, \n so there might be some "
                                                                 "error occurs.)",
                                                            font=ctkt.CTkFont(size=15))
        self.application_description_label3.grid(row=3, column=0, padx=10, pady=10)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Password generation
        self.password_generation_frame = ctkt.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.password_generation_frame.grid(row=0, column=0, sticky="nsew")
        self.password_generation_frame.grid_columnconfigure(1, weight=1)
        self.password_generation_frame.grid_rowconfigure(2, weight=1)

        # label frame
        self.pass_gen_label_frame = ctkt.CTkFrame(self.password_generation_frame, fg_color="transparent")
        self.pass_gen_label_frame.grid(row=0, column=1, sticky="nsew")
        self.pass_gen_label_frame.grid_columnconfigure(1, weight=1)
        self.pass_gen_label_frame.grid_rowconfigure(2, weight=1)
        # label
        self.pass_gen_description_label = ctkt.CTkLabel(self.pass_gen_label_frame, text="Password Generation",
                                                        font=ctkt.CTkFont(size=25, weight="bold"))
        self.pass_gen_description_label.grid(row=0, column=1, padx=5, pady=5, sticky="n")
        self.pass_gen_description_label = ctkt.CTkLabel(self.pass_gen_label_frame,
                                                        text="Generate your password to meet your demand here!",
                                                        font=ctkt.CTkFont(size=18, ))
        self.pass_gen_description_label.grid(row=1, column=1, sticky="n")

        # lines divider
        self.divider_line_canvas1 = CTkCanvas(self.password_generation_frame, height=1, bg="black")
        self.divider_line_canvas1.grid(row=1, column=0, columnspan=2, sticky="ew", pady=2)

        # left frame
        self.passgen_left_frame = ctkt.CTkFrame(self.password_generation_frame, fg_color="transparent")
        self.passgen_left_frame.grid(row=2, column=1, sticky="nsw")
        self.passgen_left_frame.grid_columnconfigure(1, weight=1)
        self.passgen_left_frame.grid_rowconfigure(4, weight=1)

        self.option_label1 = ctkt.CTkLabel(self.passgen_left_frame, text="Password Options",
                                           font=ctkt.CTkFont(size=20, weight="bold"))
        self.option_label1.grid(row=0, column=0, padx=160, pady=20)
        self.option_label2 = ctkt.CTkLabel(self.passgen_left_frame,
                                           text="Choosing these options to generate your password(it is \n"
                                                "recommend to select all options to has a strong password):",
                                           font=ctkt.CTkFont(size=14))
        self.option_label2.grid(row=1, column=0, sticky="w", padx=30)

        # option frame
        self.option_frame = ctkt.CTkFrame(self.passgen_left_frame, fg_color="transparent")
        self.option_frame.grid(row=2, column=0, )
        self.option_frame.grid_columnconfigure(4, weight=1)
        self.option_frame.grid_rowconfigure(1, weight=1)

        self.check_box1 = IntVar(value=0)
        self.password_check_box1 = ctkt.CTkCheckBox(self.option_frame, text="Include Digits", onvalue=True,
                                                    offvalue=False,
                                                    variable=self.check_box1)
        self.password_check_box1.grid(row=0, column=0, pady=25, padx=30, sticky="w")
        self.check_box2 = IntVar(value=0)
        self.password_check_box2 = ctkt.CTkCheckBox(self.option_frame, text="Include Special Character", onvalue=True,
                                                    offvalue=False, variable=self.check_box2)
        self.password_check_box2.grid(row=0, column=1, pady=25, padx=40)
        self.check_box3 = IntVar(value=0)
        self.password_check_box3 = ctkt.CTkCheckBox(self.option_frame, text="Include Uppercase Character", onvalue=True,
                                                    offvalue=False, variable=self.check_box3)
        self.password_check_box3.grid(row=1, column=0, pady=10, padx=30, sticky="w")
        self.check_box4 = IntVar(value=0)

        self.password_check_box4 = ctkt.CTkCheckBox(self.option_frame, text="Include Lower Character", onvalue=True,
                                                    offvalue=False, variable=self.check_box4)
        self.password_check_box4.grid(row=1, column=1, pady=10, padx=40)
        self.password_length_entry = ctkt.CTkEntry(self.option_frame, width=40)
        self.password_length_entry.grid(row=2, column=0, padx=30, pady=20, sticky="w")
        self.password_length_label = ctkt.CTkLabel(self.option_frame, text="Enter Password length")
        self.password_length_label.grid(row=2, column=0, padx=80, pady=20)

        self.divider_line_canvas2 = CTkCanvas(self.password_generation_frame, width=1, bg="black")
        self.divider_line_canvas2.grid(row=2, column=1, rowspan=4, sticky="ns")

        # right frame
        self.passgen_right_frame = ctkt.CTkFrame(self.password_generation_frame, fg_color="transparent")
        self.passgen_right_frame.grid(row=2, column=1, sticky="nse")
        self.passgen_right_frame.grid_columnconfigure(1, weight=1)
        self.passgen_right_frame.grid_rowconfigure(4, weight=1)
        self.option_label = ctkt.CTkLabel(self.passgen_right_frame, text="Password Outputs",
                                          font=ctkt.CTkFont(size=20, weight="bold"))
        self.option_label.grid(row=0, column=0, padx=170, pady=20)
        self.output_entry = ctkt.CTkEntry(self.passgen_right_frame, height=150, width=400,
                                          font=("Arial", 16))
        self.output_entry.grid(row=1, column=0, padx=20)
        self.output_entry.configure(justify="center")
        self.generate_button = ctkt.CTkButton(self.passgen_right_frame, text="Generate Password",
                                              font=ctkt.CTkFont(weight="bold"), command=self.pass_generate)
        self.generate_button.grid(row=2, column=0, padx=110, pady=20, sticky="w")
        self.copy_button = ctkt.CTkButton(self.passgen_right_frame, text="Copy Password",
                                          font=ctkt.CTkFont(weight="bold"), command=self.copy_password)
        self.copy_button.grid(row=2, column=0, padx=110, pady=20, sticky="e")

        # Password Checker
        self.password_checker_frame = ctkt.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.password_checker_frame.grid(row=0, column=0, sticky="nsew")
        self.password_checker_frame.grid_columnconfigure(1, weight=1)
        self.password_checker_frame.grid_rowconfigure(2, weight=1)

        # label frame
        self.pass_check_label_frame = ctkt.CTkFrame(self.password_checker_frame, fg_color="transparent")
        self.pass_check_label_frame.grid(row=0, column=1, sticky="nsew")
        self.pass_check_label_frame.grid_columnconfigure(1, weight=1)
        self.pass_check_label_frame.grid_rowconfigure(2, weight=1)
        # label
        self.pass_check_description_label1 = ctkt.CTkLabel(self.pass_check_label_frame, text="Password Checker",
                                                           font=ctkt.CTkFont(size=25, weight="bold"))
        self.pass_check_description_label1.grid(row=0, column=1, padx=5, pady=5, sticky="n")
        self.pass_check_description_label2 = ctkt.CTkLabel(self.pass_check_label_frame,
                                                           text="Check your password here to ensure it met the "
                                                                "strength password policy!",
                                                           font=ctkt.CTkFont(size=18))
        self.pass_check_description_label2.grid(row=1, column=1, sticky="n")

        # lines divider
        self.divider_line_canvas1 = CTkCanvas(self.password_checker_frame, height=1, bg="black")
        self.divider_line_canvas1.grid(row=1, column=0, columnspan=2, sticky="ew", pady=2)

        # left frame
        self.pass_check_left_frame = ctkt.CTkFrame(self.password_checker_frame, fg_color="transparent")
        self.pass_check_left_frame.grid(row=2, column=1, sticky="nsw")
        self.pass_check_left_frame.grid_columnconfigure(1, weight=1)
        self.pass_check_left_frame.grid_rowconfigure(4, weight=1)
        self.pass_check_label1 = ctkt.CTkLabel(self.pass_check_left_frame, text="Enter your password here:",
                                               font=ctkt.CTkFont(size=20, weight="bold"))
        self.pass_check_label1.grid(row=0, column=0, padx=170, pady=15)

        self.password_var = ctkt.StringVar()  # Store password text
        self.pass_check_entry = ctkt.CTkEntry(self.pass_check_left_frame, height=120, width=400, font=("Arial", 18),
                                              textvariable=self.password_var)
        self.pass_check_entry.grid(row=1, column=0, )
        self.pass_check_entry.configure(justify="center")
        self.pass_check_entry.bind("<KeyRelease>", lambda event: self.pass_entry_check(self.pass_check_entry.get()))
        self.pass_check_entry.bind("<KeyRelease>", self.update_progress_bar)

        self.pass_check_label2 = ctkt.CTkLabel(self.pass_check_left_frame, text="Password Strength",
                                               font=ctkt.CTkFont(size=16, weight="bold"))
        self.pass_check_label2.grid(row=2, column=0, pady=15)
        self.progress_bar = ctkt.CTkProgressBar(self.pass_check_left_frame, height=20, width=450,
                                                progress_color="black")
        self.progress_bar.grid(row=3, column=0)
        self.progress_bar.set(0)

        self.pass_label = ctkt.CTkLabel(self.pass_check_left_frame, text="Please enter your password",
                                        font=ctkt.CTkFont(size=14, weight="bold"))
        self.pass_label.grid(row=4, column=0)

        self.pass_weak_label = ctkt.CTkLabel(self.pass_check_left_frame, text="Your password is weak",
                                             font=ctkt.CTkFont(size=14, weight="bold"))
        self.pass_weak_label.grid(row=4, column=0)
        self.pass_weak_label.grid_forget()

        self.pass_medium_label = ctkt.CTkLabel(self.pass_check_left_frame,
                                               text="Your password is average but still vulnerable",
                                               font=ctkt.CTkFont(size=14, weight="bold"))
        self.pass_medium_label.grid(row=4, column=0)
        self.pass_medium_label.grid_forget()

        self.pass_strong_label = ctkt.CTkLabel(self.pass_check_left_frame,
                                               text="Your password is strong and highly secure",
                                               font=ctkt.CTkFont(size=14, weight="bold"))
        self.pass_strong_label.grid(row=4, column=0)
        self.pass_strong_label.grid_forget()

        self.divider_line_canvas2 = CTkCanvas(self.pass_check_left_frame, width=1, bg="black")
        self.divider_line_canvas2.grid(row=0, column=1, rowspan=20, sticky="ns")

        # right frame
        self.pass_check_right_frame = ctkt.CTkFrame(self.password_checker_frame, fg_color="transparent")
        self.pass_check_right_frame.grid(row=2, column=1, sticky="nse")
        self.pass_check_right_frame.grid_columnconfigure(1, weight=1)
        self.pass_check_right_frame.grid_rowconfigure(4, weight=1)

        self.option_label1 = ctkt.CTkLabel(self.pass_check_right_frame, text="Password Options",
                                           font=ctkt.CTkFont(size=20, weight="bold"))
        self.option_label1.grid(row=0, column=0, padx=160, pady=15)

        self.option_label2 = ctkt.CTkLabel(self.pass_check_right_frame,
                                           text="(If your password meet these options, it will changed color!)",
                                           font=ctkt.CTkFont(size=14))
        self.option_label2.grid(row=1, column=0, padx=30, sticky="w")

        # option frame
        self.option_frame = ctkt.CTkFrame(self.pass_check_right_frame, fg_color="transparent")
        self.option_frame.grid(row=2, column=0, )
        self.option_frame.grid_columnconfigure(4, weight=1)
        self.option_frame.grid_rowconfigure(1, weight=1)

        self.strength = 0

        self.password_check_label1 = ctkt.CTkLabel(self.option_frame, text="1/Length(more than 8 character)",
                                                   text_color="red", font=ctkt.CTkFont(size=14, weight="bold"))
        self.password_check_label1.grid(row=0, column=0, pady=20, padx=20, sticky="w")
        self.password_check_label2 = ctkt.CTkLabel(self.option_frame, text="4/Digits", text_color="red",
                                                   font=ctkt.CTkFont(size=14, weight="bold"))
        self.password_check_label2.grid(row=0, column=1, pady=20, padx=30, sticky="w")
        self.password_check_label3 = ctkt.CTkLabel(self.option_frame, text="2/Uppercase Character", text_color="red",
                                                   font=ctkt.CTkFont(size=14, weight="bold"))
        self.password_check_label3.grid(row=1, column=0, pady=20, padx=20, sticky="w")
        self.password_check_label4 = ctkt.CTkLabel(self.option_frame, text="5/Lowercase Character", text_color="red",
                                                   font=ctkt.CTkFont(size=14, weight="bold"))
        self.password_check_label4.grid(row=1, column=1, pady=20, padx=30, sticky="w")
        self.password_check_label5 = ctkt.CTkLabel(self.option_frame, text="3/Special Character", text_color="red",
                                                   font=ctkt.CTkFont(size=14, weight="bold"))
        self.password_check_label5.grid(row=2, column=0, pady=20, padx=20, sticky="w")

        # Data encrypt/decrypt
        self.data_encryption_frame = ctkt.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.data_encryption_frame.grid(row=0, column=0, sticky="nsew")
        self.data_encryption_frame.grid_columnconfigure(1, weight=1)
        self.data_encryption_frame.grid_rowconfigure(2, weight=1)

        # label frame
        self.data_encrypt_label_frame = ctkt.CTkFrame(self.data_encryption_frame, fg_color="transparent")
        self.data_encrypt_label_frame.grid(row=0, column=1, sticky="nsew")
        self.data_encrypt_label_frame.grid_columnconfigure(1, weight=1)
        self.data_encrypt_label_frame.grid_rowconfigure(2, weight=1)
        # label
        self.data_encrypt_description_label1 = ctkt.CTkLabel(self.data_encrypt_label_frame,
                                                             text="Data Encryption/Decryption",
                                                             font=ctkt.CTkFont(size=25, weight="bold"))
        self.data_encrypt_description_label1.grid(row=0, column=1, padx=5, pady=5, sticky="n")
        self.data_encrypt_description_label2 = ctkt.CTkLabel(self.data_encrypt_label_frame,
                                                             text="Encrypt/Decrypt your password or data here!",
                                                             font=ctkt.CTkFont(size=20))
        self.data_encrypt_description_label2.grid(row=1, column=1, sticky="n")

        # lines divider
        self.divider_line_canvas1 = CTkCanvas(self.data_encryption_frame, height=1, bg="black")
        self.divider_line_canvas1.grid(row=1, column=0, columnspan=2, sticky="ew", pady=2)

        # left frame(encrypt)
        self.data_encrypt_left_frame = ctkt.CTkFrame(self.data_encryption_frame, fg_color="transparent")
        self.data_encrypt_left_frame.grid(row=2, column=1, sticky="nsw")
        self.data_encrypt_left_frame.grid_columnconfigure(1, weight=1)
        self.data_encrypt_left_frame.grid_rowconfigure(7, weight=1)
        self.data_encrypt_label1 = ctkt.CTkLabel(self.data_encrypt_left_frame, text="Data Encryption",
                                                 font=ctkt.CTkFont(size=20, weight="bold"))
        self.data_encrypt_label1.grid(row=0, column=0, padx=200, pady=10)
        self.data_encrypt_label2 = ctkt.CTkLabel(self.data_encrypt_left_frame, text="Insert your data here:",
                                                 font=ctkt.CTkFont(size=16))
        self.data_encrypt_label2.grid(row=1, column=0, padx=30, sticky="w")
        self.data_encrypt_label3 = ctkt.CTkLabel(self.data_encrypt_left_frame, text="Generate Key",
                                                 font=ctkt.CTkFont(size=16))
        self.data_encrypt_label3.grid(row=1, column=0, padx=150, sticky="e")
        self.data_encrypt_entry1 = ctkt.CTkEntry(self.data_encrypt_left_frame, height=40, width=220, font=("Arial", 16))
        self.data_encrypt_entry1.grid(row=2, column=0, padx=30, pady=5, sticky="w")
        self.data_encrypt_entry1.configure(justify="center")
        self.data_encrypt_entry2 = ctkt.CTkEntry(self.data_encrypt_left_frame, height=40, width=220,
                                                 font=("Arial", 16))
        self.data_encrypt_entry2.grid(row=2, column=0, padx=30, pady=5, sticky="e")
        self.data_encrypt_entry2.configure(justify="center")
        self.encrypt_button1 = ctkt.CTkButton(self.data_encrypt_left_frame, text="Generate", width=60,
                                              command=self.generate_key)
        self.encrypt_button1.grid(row=3, column=0, sticky="e", padx=140, pady=5)
        self.encrypt_button2 = ctkt.CTkButton(self.data_encrypt_left_frame, text="Copy", width=60,
                                              command=self.copy_key)
        self.encrypt_button2.grid(row=3, column=0, sticky="e", padx=70, pady=5)
        self.data_encrypt_label4 = ctkt.CTkLabel(self.data_encrypt_left_frame, text="Encrypt Data:",
                                                 font=ctkt.CTkFont(size=16))
        self.data_encrypt_label4.grid(row=4, column=0, padx=30, pady=5)
        self.data_encrypt_entry4 = ctkt.CTkEntry(self.data_encrypt_left_frame, height=40, width=350,
                                                 font=("Arial", 16))
        self.data_encrypt_entry4.grid(row=5, column=0, padx=30, pady=5)
        self.data_encrypt_entry4.configure(justify="center")
        self.encrypt_button3 = ctkt.CTkButton(self.data_encrypt_left_frame, text="Encrypt", width=60,
                                              command=self.encrypt_data)
        self.encrypt_button3.grid(row=6, column=0, padx=200, pady=5, sticky="w")
        self.encrypt_button4 = ctkt.CTkButton(self.data_encrypt_left_frame, text="View & Copy", width=60,
                                              command=self.view_encrypt_value)
        self.encrypt_button4.grid(row=6, column=0, padx=195, pady=5, sticky="e")

        self.divider_line_canvas2 = CTkCanvas(self.data_encrypt_left_frame, width=1, bg="black")
        self.divider_line_canvas2.grid(row=0, column=1, rowspan=20, sticky="ns")

        # right frame(decrypt)
        self.data_decrypt_right_frame = ctkt.CTkFrame(self.data_encryption_frame, fg_color="transparent")
        self.data_decrypt_right_frame.grid(row=2, column=1, sticky="nse")
        self.data_decrypt_right_frame.grid_columnconfigure(1, weight=1)
        self.data_decrypt_right_frame.grid_rowconfigure(7, weight=1)
        self.data_decrypt_label1 = ctkt.CTkLabel(self.data_decrypt_right_frame, text="Data Decryption",
                                                 font=ctkt.CTkFont(size=20, weight="bold"))
        self.data_decrypt_label1.grid(row=0, column=0, padx=190, pady=10)
        self.data_decrypt_label2 = ctkt.CTkLabel(self.data_decrypt_right_frame, text="Insert your data here:",
                                                 font=ctkt.CTkFont(size=16))
        self.data_decrypt_label2.grid(row=1, column=0, padx=30, sticky="w")
        self.data_decrypt_label3 = ctkt.CTkLabel(self.data_decrypt_right_frame, text="Insert the key:",
                                                 font=ctkt.CTkFont(size=16))
        self.data_decrypt_label3.grid(row=1, column=0, padx=150, sticky="e")
        self.data_decrypt_entry1 = ctkt.CTkEntry(self.data_decrypt_right_frame, height=40, width=220,
                                                 font=("Arial", 14))
        self.data_decrypt_entry1.grid(row=2, column=0, padx=30, pady=5, sticky="w")
        self.data_decrypt_entry1.configure(justify="center")
        self.data_decrypt_entry2 = ctkt.CTkEntry(self.data_decrypt_right_frame, height=40, width=220,
                                                 font=("Arial", 14))
        self.data_decrypt_entry2.grid(row=2, column=0, padx=30, pady=5, sticky="e")
        self.data_decrypt_entry2.configure(justify="center")
        self.data_decrypt_label4 = ctkt.CTkLabel(self.data_decrypt_right_frame, text="Data Decrypt",
                                                 font=ctkt.CTkFont(size=16))
        self.data_decrypt_label4.grid(row=4, column=0, padx=30, pady=10)
        self.data_decrypt_entry4 = ctkt.CTkEntry(self.data_decrypt_right_frame, height=40, width=350,
                                                 font=("Arial", 14))
        self.data_decrypt_entry4.grid(row=5, column=0, padx=30, pady=5)
        self.data_decrypt_entry4.configure(justify="center")
        self.decrypt_button3 = ctkt.CTkButton(self.data_decrypt_right_frame, text="Decrypt", width=60,
                                              command=self.decrypt_data)
        self.decrypt_button3.grid(row=6, column=0, padx=210, pady=5, sticky="w")
        self.decrypt_button4 = ctkt.CTkButton(self.data_decrypt_right_frame, text="Full view", width=60,
                                              command=self.view_decrypt_value)
        self.decrypt_button4.grid(row=6, column=0, padx=190, pady=5, sticky="e")

        # Data Hasher
        self.data_hasher_frame = ctkt.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.data_hasher_frame.grid(row=0, column=0, sticky="nsew")
        self.data_hasher_frame.grid_columnconfigure(1, weight=1)
        self.data_hasher_frame.grid_rowconfigure(2, weight=1)

        # label frame
        self.data_hasher_label_frame = ctkt.CTkFrame(self.data_hasher_frame, fg_color="transparent")
        self.data_hasher_label_frame.grid(row=0, column=1, sticky="nsew")
        self.data_hasher_label_frame.grid_columnconfigure(1, weight=1)
        self.data_hasher_label_frame.grid_rowconfigure(2, weight=1)
        # label
        self.data_hasher_description_label1 = ctkt.CTkLabel(self.data_hasher_label_frame,
                                                            text="Data Hasher",
                                                            font=ctkt.CTkFont(size=25, weight="bold"))
        self.data_hasher_description_label1.grid(row=0, column=1, padx=5, pady=5, sticky="n")
        self.data_hasher_description_label2 = ctkt.CTkLabel(self.data_hasher_label_frame,
                                                            text="Hash your password and data here!",
                                                            font=ctkt.CTkFont(size=18))
        self.data_hasher_description_label2.grid(row=1, column=1, sticky="n")

        # lines divider
        self.divider_line_canvas1 = CTkCanvas(self.data_hasher_frame, height=1, bg="black")
        self.divider_line_canvas1.grid(row=1, column=0, columnspan=2, sticky="ew", pady=2)

        # left frame
        self.data_hasher_left_frame = ctkt.CTkFrame(self.data_hasher_frame, fg_color="transparent")
        self.data_hasher_left_frame.grid(row=2, column=1, sticky="nsw")
        self.data_hasher_left_frame.grid_columnconfigure(1, weight=1)
        self.data_hasher_left_frame.grid_rowconfigure(7, weight=1)
        self.data_hasher_label1 = ctkt.CTkLabel(self.data_hasher_left_frame, text="Data Hashing",
                                                font=ctkt.CTkFont(size=20, weight="bold"))
        self.data_hasher_label1.grid(row=0, column=0, padx=190, pady=10)
        self.data_hasher_label2 = ctkt.CTkLabel(self.data_hasher_left_frame, text="Insert your data here:",
                                                font=ctkt.CTkFont(size=16))
        self.data_hasher_label2.grid(row=1, column=0, sticky="w", padx=50, pady=10)
        self.data_hasher_entry1 = ctkt.CTkEntry(self.data_hasher_left_frame, height=50, width=460, font=("Arial", 16))
        self.data_hasher_entry1.grid(row=2, column=0, sticky="w", padx=50)
        self.data_hasher_entry1.configure(justify="center")
        self.data_hasher_label3 = ctkt.CTkLabel(self.data_hasher_left_frame, text="Insert salt for the hash:",
                                                font=ctkt.CTkFont(size=16))
        self.data_hasher_label3.grid(row=3, column=0, sticky="w", padx=50, pady=45)
        self.data_hasher_entry2 = ctkt.CTkEntry(self.data_hasher_left_frame, height=50, width=290, font=("Arial", 16))
        self.data_hasher_entry2.grid(row=3, column=0, sticky="e", padx=50)
        self.data_hasher_entry2.configure(justify="center")
        self.data_hasher_button1 = ctkt.CTkButton(self.data_hasher_left_frame, text="Generate", command=self.get_hash)
        self.data_hasher_button1.grid(row=4, column=0)

        self.divider_line_canvas2 = CTkCanvas(self.data_hasher_left_frame, width=1, bg="black")
        self.divider_line_canvas2.grid(row=0, column=1, rowspan=20, sticky="ns")

        # right frame
        self.data_hasher_right_frame = ctkt.CTkFrame(self.data_hasher_frame, fg_color="transparent")
        self.data_hasher_right_frame.grid(row=2, column=1, sticky="nse")
        self.data_hasher_right_frame.grid_columnconfigure(1, weight=1)
        self.data_hasher_right_frame.grid_rowconfigure(7, weight=1)
        self.data_hasher_label4 = ctkt.CTkLabel(self.data_hasher_right_frame, text="Hashing Output",
                                                font=ctkt.CTkFont(size=20, weight="bold"))
        self.data_hasher_label4.grid(row=0, column=0, padx=190, pady=10)
        self.data_hasher_label5 = ctkt.CTkLabel(self.data_hasher_right_frame, text="Output in Encoded form:",
                                                font=ctkt.CTkFont(size=16))
        self.data_hasher_label5.grid(row=1, column=0, sticky="w", padx=40, pady=5)
        self.data_hasher_entry3 = ctkt.CTkEntry(self.data_hasher_right_frame, height=45, width=450, font=("Arial", 16))
        self.data_hasher_entry3.grid(row=2, column=0, sticky="w", padx=40)
        self.data_hasher_entry3.configure(justify="center")
        self.data_hasher_button2 = ctkt.CTkButton(self.data_hasher_right_frame, text="Full view",
                                                  command=self.view_hash_encode)
        self.data_hasher_button2.grid(row=3, column=0, pady=10)
        self.data_hasher_label6 = ctkt.CTkLabel(self.data_hasher_right_frame, text="Output in Hex form:",
                                                font=ctkt.CTkFont(size=16))
        self.data_hasher_label6.grid(row=4, column=0, sticky="w", padx=40, pady=5)
        self.data_hasher_entry4 = ctkt.CTkEntry(self.data_hasher_right_frame, height=45, width=450, font=("Arial", 16))
        self.data_hasher_entry4.grid(row=5, column=0, sticky="w", padx=40)
        self.data_hasher_entry4.configure(justify="center")
        self.data_hasher_button3 = ctkt.CTkButton(self.data_hasher_right_frame, text="Full view",
                                                  command=self.view_hash_hex)
        self.data_hasher_button3.grid(row=6, column=0, pady=10)

        # Setting frame
        self.setting_frame = ctkt.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.setting_frame.grid(row=0, column=0, sticky="nsew")
        self.setting_frame.grid_columnconfigure(1, weight=1)
        self.setting_frame.grid_rowconfigure(2, weight=1)

        # label frame
        self.setting_label_frame = ctkt.CTkFrame(self.setting_frame, fg_color="transparent")
        self.setting_label_frame.grid(row=0, column=1, sticky="nsew")
        self.setting_label_frame.grid_columnconfigure(1, weight=1)
        self.setting_label_frame.grid_rowconfigure(2, weight=1)
        # label
        self.setting_label = ctkt.CTkLabel(self.setting_label_frame, text="App Setting",
                                           font=ctkt.CTkFont(size=25, weight="bold"))
        self.setting_label.grid(row=0, column=1, padx=5, pady=5, sticky="n")

        # lines divider
        self.divider_line_canvas1 = CTkCanvas(self.setting_frame, height=1, bg="black")
        self.divider_line_canvas1.grid(row=1, column=0, columnspan=2, sticky="ew", pady=2)

        # left frame
        self.setting_left_frame = ctkt.CTkFrame(self.setting_frame, fg_color="transparent")
        self.setting_left_frame.grid(row=2, column=1, sticky="nsw")
        self.setting_left_frame.grid_columnconfigure(1, weight=1)
        self.setting_left_frame.grid_rowconfigure(5, weight=1)

        self.sign_out_button = ctkt.CTkButton(self.setting_left_frame, text="Sign Out", width=1080, height=85,
                                              font=ctkt.CTkFont(size=25, weight="bold"), command=self.sign_out)
        self.sign_out_button.grid(row=1, column=0, padx=10, pady=30, sticky="news")
        self.user_policy_button = ctkt.CTkButton(self.setting_left_frame, text="View User Policy", width=1080,
                                                 height=85, font=ctkt.CTkFont(size=25, weight="bold"),
                                                 command=self.show_user_policy)
        self.user_policy_button.grid(row=3, column=0, padx=10, pady=30, sticky="news")
        self.appearance_mode_menu = ctkt.CTkOptionMenu(self.setting_left_frame, values=["Dark", "Light", "System"],
                                                       command=self.change_appearance_mode_event)
        self.appearance_mode_menu.grid(row=6, column=0, padx=10, pady=5, sticky="sw")

        # select default frame
        self.select_frame_by_name("home")

    def select_frame_by_name(self, name):
        # set button color for selected button
        self.home_button.configure(fg_color=("gray75", "gray25") if name == "home" else "transparent")
        self.password_generation_button.configure(
            fg_color=("gray75", "gray25") if name == "password_generation" else "transparent")
        self.password_checker_button.configure(
            fg_color=("gray75", "gray25") if name == "password_checker" else "transparent")
        self.data_encryption_button.configure(
            fg_color=("gray75", "gray25") if name == "data_encryption" else "transparent")
        self.data_hasher_button.configure(fg_color=("gray75", "gray25") if name == "data_hasher" else "transparent")
        # self.password_management_button.configure(
        #     fg_color=("gray75", "gray25") if name == "password_management" else "transparent")
        self.setting_button.configure(fg_color=("gray75", "gray25") if name == "setting" else "transparent")

        # show selected frame
        if name == "home":
            self.home_frame.grid(row=1, column=0, sticky="nsew")
        else:
            self.home_frame.grid_forget()
        if name == "password_generation":
            self.password_generation_frame.grid(row=1, column=0, sticky="nsew")
        else:
            self.password_generation_frame.grid_forget()
        if name == "password_checker":
            self.password_checker_frame.grid(row=1, column=0, sticky="nsew")
        else:
            self.password_checker_frame.grid_forget()
        if name == "data_encryption":
            self.data_encryption_frame.grid(row=1, column=0, sticky="nsew")
        else:
            self.data_encryption_frame.grid_forget()
        if name == "data_hasher":
            self.data_hasher_frame.grid(row=1, column=0, sticky="nsew")
        else:
            self.data_hasher_frame.grid_forget()
        if name == "setting":
            self.setting_frame.grid(row=1, column=0, sticky="nsew")
        else:
            self.setting_frame.grid_forget()

    def home_button_event(self):
        self.select_frame_by_name("home")

    def password_generation_button_event(self):
        self.select_frame_by_name("password_generation")

    def password_checker_button_event(self):
        self.select_frame_by_name("password_checker")

    def data_encryption_button_event(self):
        self.select_frame_by_name("data_encryption")

    def data_hasher_button_event(self):
        self.select_frame_by_name("data_hasher")

    def setting_button_event(self):
        self.select_frame_by_name("setting")

    def change_appearance_mode_event(self, new_appearance_mode):
        ctkt.set_appearance_mode(new_appearance_mode)

    # Password Generator function
    def pass_generate(self):
        self.low_alpha = string.ascii_lowercase
        self.up_alpha = string.ascii_uppercase
        self.number = string.digits
        self.spec_char = string.punctuation
        self.all = self.low_alpha + self.up_alpha + self.number + self.spec_char

        try:
            # Check for empty input
            if not self.password_length_entry.get():
                raise ValueError("Please enter a value for password length.")

            # Convert to integer and validate length
            self.pass_length = int(self.password_length_entry.get())
            if not 1 <= self.pass_length <= 70:  # Adjust min and max values as needed
                raise ValueError("Password length must be between 1 and 70 characters.")

        except ValueError as e:
            if not self.password_length_entry.get():  # Empty input
                self.messagebox = CTkMessagebox(title="Empty Input",
                                                message="Please enter a value for password length.",
                                                icon="warning")
            elif not self.password_length_entry.get().isdigit():  # String input (not digits)
                self.messagebox = CTkMessagebox(title="Invalid Input",
                                                message="Please enter a valid integer for password length.",
                                                icon="warning")
                self.password_length_entry.delete(0, 'end')  # Clear the entry field
            else:  # Other ValueError (e.g., out-of-range length)
                self.messagebox = CTkMessagebox(title="Invalid Length", message=str(e), icon="warning")
                self.password_length_entry.delete(0, 'end')  # Clear the entry field
            return  # Exit the function on any error

        chosen_chars = ""
        # Combine characters based on selected checkboxes
        if self.check_box1.get() == True:
            chosen_chars += self.number
        if self.check_box2.get() == True:
            chosen_chars += self.spec_char
        if self.check_box3.get() == True:
            chosen_chars += self.up_alpha
        if self.check_box4.get() == True:
            chosen_chars += self.low_alpha
        if not any([self.check_box1.get(), self.check_box2.get(), self.check_box3.get(), self.check_box4.get()]):
            self.messagebox = CTkMessagebox(title="Error",
                                            message="Please select at least one option to generate a password.",
                                            icon="warning")
            return

        sample_size = min(self.pass_length, len(chosen_chars))

        # Generate password using random.sample and join to remove spaces
        password = ''.join(random.sample(chosen_chars, sample_size))
        self.output_entry.delete(0, 'end')  # Clear the entry before inserting
        self.output_entry.insert(0, password)
        return password  # Return the generated password for potential further use

    def copy_password(self):
        password = self.output_entry.get()  # Retrieve the password from the entry field

        if not password:  # Check if the entry box is empty
            self.messagebox = CTkMessagebox(title="Error",
                                            message="There's no password to copy. Please generate a password first.",
                                            icon="warning")
            return

        pyperclip.copy(password)  # Copy the password to the clipboard
        self.output_entry.configure(state="disabled")  # Disable the entry field for security
        self.copy_button.configure(state="disabled")  # Disable the copy button to prevent duplicate copies
        self.messagebox = CTkMessagebox(title="Password Copied",
                                        message="Password has been copied to your clipboard!",
                                        icon="check")  # Display success message

    def change_color_label(self, password):
        self.has_digits = any(char.isdigit() for char in password)
        self.has_lowercase = any(char.islower() for char in password)
        self.has_uppercase = any(char.isupper() for char in password)
        self.has_special_chars = any(char in string.punctuation for char in password)
        self.is_long_enough = len(password) > 8

        self.password_check_label1.configure(text_color="green" if self.is_long_enough else "red")
        self.password_check_label2.configure(text_color="green" if self.has_digits else "red")
        self.password_check_label3.configure(text_color="green" if self.has_uppercase else "red")
        self.password_check_label4.configure(text_color="green" if self.has_lowercase else "red")
        self.password_check_label5.configure(text_color="green" if self.has_special_chars else "red")

    def pass_entry_check(self, password):
        self.change_color_label(password)

    def update_progress_bar(self, event):
        password = self.pass_check_entry.get()
        progress = 0.0
        complexity_requirements = 100.0
        digits_value = 4 / complexity_requirements
        uppercase_value = 4 / complexity_requirements
        lowercase_value = 2.5 / complexity_requirements
        spec_value = 5 / complexity_requirements
        length_value = 1.3 / complexity_requirements

        for char in password:
            if char.isdigit() and progress < complexity_requirements:
                progress += digits_value
            elif char.isupper() and progress < complexity_requirements:
                progress += uppercase_value
            elif char.islower() and progress < complexity_requirements:
                progress += lowercase_value
            elif re.search(r"[^\w\s]", char) and progress < complexity_requirements:
                progress += spec_value

        for i in range(len(password) - 8):
            length_value += 0.01

        if len(password) > 8 and progress < complexity_requirements:
            progress += length_value

        self.progress_bar.set(min(progress, complexity_requirements))
        if progress < 0.4:
            self.progress_bar.configure(progress_color="orange")  # Set color to orange
            self.pass_label.grid_forget()
            self.pass_weak_label.grid_forget()
            self.pass_medium_label.grid_forget()
            self.pass_strong_label.grid_forget()
            self.pass_weak_label.grid(row=4, column=0)  # Show weak label
        elif progress < 0.8:
            self.progress_bar.configure(progress_color="yellow")  # Set color to yellow
            self.pass_label.grid_forget()
            self.pass_weak_label.grid_forget()  # Hide other labels
            self.pass_strong_label.grid_forget()
            self.pass_medium_label.grid(row=4, column=0)  # Show medium label
        else:
            self.progress_bar.configure(progress_color="green")  # Set color to green
            self.pass_label.grid_forget()
            self.pass_weak_label.grid_forget()  # Hide other labels
            self.pass_medium_label.grid_forget()
            self.pass_strong_label.grid(row=4, column=0)  # Show strong label

        if not password:
            self.progress_bar.configure(progress_color="black")  # Set color to orange
            self.progress_bar.set(0.0)
            self.pass_weak_label.grid_forget()
            self.pass_medium_label.grid_forget()
            self.pass_strong_label.grid_forget()
            self.pass_label.grid(row=4, column=0)

    def generate_key(self):
        """Generates a key using Fernet and displays it in the entry field."""
        self.key = Fernet.generate_key()  # Generate a new key
        self.data_encrypt_entry2.delete(0, ctkt.END)  # Clear the entry field
        self.data_encrypt_entry2.insert(0, self.key.decode())  # Display the generated key
        self.encrypt_button2.configure(state="normal")  # Enable the "Copy Key" button

    def copy_key(self):
        if not self.data_encrypt_entry2.get():
            self.messagebox = CTkMessagebox(title="Key not founded",
                                            message="Please generate or enter a key before clicking Copy.",
                                            icon="warning")
            return
        # If a key is present, proceed with copying:
        self.clipboard_clear()  # Clear existing clipboard content (optional)
        self.clipboard_append(self.data_encrypt_entry2.get())  # Copy the key from the entry field
        self.messagebox = CTkMessagebox(title="Key Copied", message="The key has been copied to your clipboard.",
                                        icon="check")
        self.data_encrypt_entry2.configure(state="disabled")  # Disable entry field
        self.encrypt_button2.configure(state="disabled")  # Disable "Copy Key" button

    def encrypt_data(self):
        self.fernet = Fernet(self.key)
        self.encrypt_data = self.data_encrypt_entry1.get()  # Get the data from the entry field
        if self.encrypt_data == "":
            self.messagebox = CTkMessagebox(title="No Data Entered",
                                            message="Please enter the data you want to encrypt.",
                                            icon="warning")
            return
        self.encrypted_data = self.fernet.encrypt(self.encrypt_data.encode()).decode()
        self.data_encrypt_entry4.delete(0, ctkt.END)  # Clear the encrypted text entry field (if present)
        self.data_encrypt_entry4.insert(0, self.encrypted_data)
        self.messagebox = CTkMessagebox(title="Encryption Successful", message="Your data has been encrypted.",
                                        icon="check")

    def view_encrypt_value(self):
        if not self.data_encrypt_entry4.get():
            self.messagebox = CTkMessagebox(title="Copied Fail", message="No data to copy, please generate data first.",
                                            icon="warning")
            return
        self.entry_value = self.data_encrypt_entry4.get()
        self.clipboard_clear()  # Clear existing clipboard content (optional)
        self.clipboard_append(self.data_encrypt_entry4.get())  # Copy the key from the entry field
        self.messagebox = CTkMessagebox(title="Data Copied", message=f"{self.entry_value}",
                                        icon="check", width=450)
        self.data_encrypt_entry4.configure(state="disabled")  # Disable entry field
        self.encrypt_button4.configure(state="disabled")  # Disable "Copy Key" button

    def decrypt_data(self):
        self.decrypt_data = self.data_decrypt_entry1.get()
        if self.decrypt_data == "":
            self.messagebox = CTkMessagebox(title="No Encrypted Data",
                                            message="Please enter the encrypted data you want to decrypt.",
                                            icon="warning")
            return
        self.key = self.data_decrypt_entry2.get()
        if self.key == "":
            self.messagebox = CTkMessagebox(title="No Key Entered", message="Please enter the key used for encryption.",
                                            icon="warning")
            return
        try:
            fernet = Fernet(self.key.encode())  # Convert key to bytes for Fernet
            decrypted_data = fernet.decrypt(self.decrypt_data.encode()).decode()
            self.data_decrypt_entry4.delete(0, ctkt.END)  # Clear the decrypted data entry field
            self.data_decrypt_entry4.insert(0, decrypted_data)
            self.messagebox = CTkMessagebox(title="Decryption Successful", message="Your data has been decrypted.",
                                            icon="check")
        except:
            self.messagebox = CTkMessagebox(title="Invalid Key/Data",
                                            message="The provided key/Data is not valid for the encrypted data.",
                                            icon="warning")

    def view_decrypt_value(self):
        """Retrieves the value from the entry field and displays it in a message box."""
        self.entry_value = self.data_decrypt_entry4.get()
        if not self.entry_value:
            self.messagebox = CTkMessagebox(title="Error", message="There are no data to view", icon="warning")
            return
        self.messagebox = CTkMessagebox(title="Entry Value",
                                        message=f"{self.entry_value}")

    def hash_data_with_salt(self, data, salt):
        self.hashed_data = hashlib.sha256(salt + data.encode()).digest()
        return self.hashed_data, self.hashed_data.hex()

    def get_hash(self):
        self.data = self.data_hasher_entry1.get()
        self.salt = self.data_hasher_entry2.get()
        if not self.data:
            self.messagebox = CTkMessagebox(title="Empty entry field", message="Please insert at least 1 character to hashing.",
                                            icon="warning")
            return
        if not self.salt:
            self.messagebox = CTkMessagebox(title="Empty salt entry", message="Please insert character in the salt entry",
                                            icon="warning")
            return
        self.hashed_data, self.hex_hash = self.hash_data_with_salt(self.data, self.salt.encode())
        self.data_hasher_entry3.delete(0, "end")
        self.data_hasher_entry4.delete(0, "end")

        # Insert encoded and hex forms into respective entries
        self.data_hasher_entry3.insert(0, str(self.hashed_data))
        self.data_hasher_entry4.insert(0, self.hex_hash)

    def view_hash_encode(self):
        self.hash_encode = self.data_hasher_entry3.get()
        if not self.hash_encode:
            self.messagebox = CTkMessagebox(title="Error", message="There are no data to view", icon="warning")
            return
        self.messagebox = CTkMessagebox(title="Encoded form",
                                        message=f"{self.hash_encode}")

    def view_hash_hex(self):
        self.hash_hex = self.data_hasher_entry4.get()
        if not self.hash_hex:
            self.messagebox = CTkMessagebox(title="Error", message="There are no data to view", icon="warning")
            return
        self.messagebox = CTkMessagebox(title="Hex form",
                                        message=f"{self.hash_hex}")

    def show_user_policy(self):
        self.user_policy_window = UserPolicy()
        self.user_policy_window.grab_set()
        self.user_policy_window.mainloop()

    def sign_out(self):
        self.messagebox = CTkMessagebox(title="Sign out confirm", message="Are you want to sign out?",
                                        icon="question", option_1="No", option_2="Yes")
        sign_out = self.messagebox.get()
        if sign_out == "Yes":
            self.destroy()
            LoginPage().mainloop()

    def on_closing(self):
        self.messagebox = CTkMessagebox(title="Exit?", message="Do you want to close the program?",
                                        icon="question", option_1="No", option_2="Yes")
        response = self.messagebox.get()
        if response == "Yes":
            self.destroy()


class UserPolicy(ctkt.CTk):
    def __init__(self):
        super().__init__()

        ctkt.set_appearance_mode("dark")
        self.title("User Policy")
        self.geometry("600x400")
        self.resizable(False, False)

        # Main Frame
        self.user_policy_frame = ctkt.CTkFrame(self)
        self.user_policy_frame.pack(fill="both", expand=True)
        # Create Canvas
        self.canvas = ctkt.CTkCanvas(self.user_policy_frame)
        self.canvas.pack(side="left", fill="both", expand=True)
        # Create Scrollbar
        self.scrollbar = ctkt.CTkScrollbar(self.user_policy_frame,
                                           command=self.canvas.yview)
        self.scrollbar.pack(side="right", fill="y")
        # Canvas Config
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        # Inner Frame for Scrollable Content (place your policy text here)
        self.inner_frame = ctkt.CTkFrame(self.canvas)
        self.canvas.create_window((0, 0), window=self.inner_frame, anchor="nw")

        self.user_policy = """Welcome to PassGenX | Secure your password - Simplify your life

             1. Introduction

             We are appreciative that you have chosen PassGenX to protect your passwords. The terms and conditions that apply to your use of our app are described in this User Policy. You acknowledge and agree to abide by our Privacy Policy and this User Policy by using or accessing PassGenX.

             2. Account Creation and Security

             2.1 Account Creation: You must register for an account with accurate and current information in order to use PassGenX. You bear full responsibility for safeguarding the privacy of your login credentials (password and username) and for any actions taken using your account.

             2.2 Security: To ensure the security of your account, please take the appropriate steps.
              Make sure you log out of your account after every session and don't give out your login credentials to anyone else. Please contact [contact email/phone number] right away if you suspect a security breach or any unauthorized access.

             3. Data Privacy and Security

             3.1 Data Collection and Storage: PassGenX is concerned about data privacy.
              We don't gather or keep your passwords on file. Additionally, unless it's mandated by law, we never rent, sell, or otherwise disclose your personal information to outside parties without getting your permission.

             3.2 Encryption: To guarantee the highest level of security, all passwords and sensitive data are encrypted using industry-standard encryption protocols.

             3.3 Data Access: Our staff closely abides by data access controls, and your data can only be accessed by authorized individuals who require it for legal or support-related purposes.

             4. User Responsibilities

             4.1 Data Accuracy: It is your responsibility to keep the information in your account current and accurate.

             4.2 Usage Guidelines: You acknowledge that you will only use PassGenX in accordance with all applicable laws and regulations and only for legitimate purposes.

             4.3 Prohibited Activities: You are not allowed to do anything that could damage the app, its users, or break any laws. Activities such as hacking, phishing, spamming, and the distribution of malicious software are prohibited.

             5. App Updates and Maintenance

             5.1 Updates: We might occasionally publish app updates to enhance functionality and security.
             It is advised that you maintain the most recent version of your app.

             5.2 Maintenance: Even though we work hard to ensure a seamless and uninterrupted experience, occasionally maintenance may be required. Our goal is to arrange these maintenance windows during times when there is little traffic.

             6. Termination

             6.1 Account Termination: You can follow the instructions on the app to terminate your account at any time.
             Upon termination, all information related to your account will be removed.

             6.2 Termination by PassGenX: If we believe there has been any breach of this User Policy or if it is mandated by law, we reserve the right to cancel or suspend your account.

             7. Changes to User Policy

             7.1 Updates: We might occasionally update this User Policy.
             Any updates will be sent out via email or posted on the app.

             7.2 Acceptance: You are considered to have agreed to the updated terms if you use PassGenX after the User Policy has been updated.

            For any inquiries or concerns about this User Policy, please get in touch with our support staff at [support email/phone number].

             PassGenX Beta version 1.0 by Tom Ngo (Ngo Nguyen Anh Hao)

             Last updated: [25-04-2024]"""
        self.policy_label = ctkt.CTkLabel(self.inner_frame, text=self.user_policy, bg_color="white", fg_color="black",
                                          justify=ctkt.LEFT, wraplength=550,
                                          font=ctkt.CTkFont(size=14))
        self.policy_label.pack(padx=20, pady=10, anchor=ctkt.NW)


if __name__ == "__main__":
    login_page = LoginPage()
    login_page.mainloop()