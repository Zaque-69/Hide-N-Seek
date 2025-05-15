import customtkinter as ctk
import os
import subprocess
import tkinter

from customtkinter import CTkImage
from PIL import Image
from tkinter import filedialog, messagebox

BUTTON_BORDER = "#585025"
VIRUS_COLOR = "#EEC541"
TEXT_WHITE = "#F4F2E6"
TEXTBOX_COLOR = "#1D1F1E"
HOVER_TEXTBOX_COLOR = "#151515"
BORDER_BUTTON_COLOR = "#363837"
VIBRANT_RED = "#137ED0"

class HideNSeek(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Verificare Path")
        self.geometry("900x530")
        self.resizable(False, False)
        ctk.set_appearance_mode("Dark")

        self.create_textboxes()
        self.create_other_widgets()
        self.create_buttons()

    def create_textboxes(self):
        self.output_textbox_yararules = ctk.CTkTextbox(self, width=660, height=150, text_color=VIBRANT_RED)
        self.output_textbox_yararules.place(x=30, y=140)

        self.output_textbox_scannedfiles = ctk.CTkTextbox(self, width=660, height=150)
        self.output_textbox_scannedfiles.place(x=30, y=310)

        self.output_textbox_files = ctk.CTkTextbox(self, width=35, height=30, text_color=TEXT_WHITE)
        self.output_textbox_files.place(x=600, y=95)

        self.output_textbox_virus = ctk.CTkTextbox(self, width=35, height=30, text_color=VIBRANT_RED)
        self.output_textbox_virus.place(x=645, y=95)

    def create_buttons(self):
        folder = ctk.CTkImage(dark_image=Image.open("./assets/folder.png"), size=(30, 30))
        qs = ctk.CTkImage(dark_image=Image.open("./assets/quickscan.png"), size=(100, 100))
        ext = ctk.CTkImage(dark_image=Image.open("./assets/file.png"), size=(100, 100))
        trash = ctk.CTkImage(dark_image=Image.open("./assets/trash.png"), size=(25, 25))

        self.button_verifica = ctk.CTkButton(self, text="SCAN", width=120, fg_color=TEXTBOX_COLOR, border_width=2, border_color=BORDER_BUTTON_COLOR,
            hover_color=HOVER_TEXTBOX_COLOR, corner_radius=4, command=self.start_scan)
        self.button_verifica.place(x=575, y=60)

        self.folder_button = ctk.CTkButton(self, width=60, height=60, image=folder, text="", border_width=2, border_color=BORDER_BUTTON_COLOR,
            fg_color=TEXTBOX_COLOR, hover_color=HOVER_TEXTBOX_COLOR, corner_radius=4, command=self.browse_folder)
        self.folder_button.place(x=335, y=60)

        self.qs_button = ctk.CTkButton(self, width=130, height=130, image=qs, text="", border_width=2, border_color=BORDER_BUTTON_COLOR,
            fg_color=TEXTBOX_COLOR, hover_color=HOVER_TEXTBOX_COLOR, corner_radius=4, command=self.quick_scan)
        self.qs_button.place(x=740, y=20)

        self.ext_button = ctk.CTkButton(self, width=130, height=130, image=ext, text="", border_width=2, border_color=BORDER_BUTTON_COLOR,
            fg_color=TEXTBOX_COLOR, hover_color=HOVER_TEXTBOX_COLOR, corner_radius=4, command=self.extension_check)
        self.ext_button.place(x=740, y=180)

        self.trash_button = ctk.CTkButton(self, width=35, height=35, image=trash, text="", border_width=2, border_color=BORDER_BUTTON_COLOR,
            fg_color=TEXTBOX_COLOR, hover_color=HOVER_TEXTBOX_COLOR, corner_radius=4, command=self.delete_content)
        self.trash_button.place(x=655, y=480)

    def create_other_widgets(self):
        self.label_titlu = ctk.CTkLabel(self, text="Hide 'N Seek", font=ctk.CTkFont(size=20, weight="bold"))
        self.label_titlu.place(x=30, y=20)

        self.frame_input = ctk.CTkFrame(self)
        self.frame_input.place(x=30, y=60)

        self.frame_root_password = ctk.CTkFrame(self)
        self.frame_root_password.place(x=405, y=60)

        ctk.CTkLabel(self.frame_input, text="Enter a path to scan :").pack()
        self.entry_path = ctk.CTkEntry(self.frame_input, width=295, placeholder_text="Ex: /home/user/Downloads/directory")
        self.entry_path.pack()

        ctk.CTkLabel(self.frame_root_password, text="Root password :").pack()
        self.root_password = ctk.CTkEntry(self.frame_root_password, width=160, placeholder_text="Ex: admin")
        self.root_password.pack()

        self.line = ctk.CTkFrame(self, width=2, height=530, fg_color="#1D1F1E")
        self.line.place(x=720, y=0)

        self.delete = ctk.CTkEntry(self, width=615, height=35, placeholder_text="Path to delete file/folder.")
        self.delete.place(x=30, y=480)

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.entry_path.delete(0, tkinter.END)
            self.entry_path.insert(0, path)

    def info_msgbox(self, info):
        messagebox.showinfo("INFO", info)

    def error_msgbox(self, err):
        messagebox.showerror("ERROR", err)

    def show_infected_files(self, path):
        try:
            result = subprocess.run(f"nim c -r hidenseek.nim -m {path}", text=True, shell=True, capture_output=True)
            return '\n'.join(result.stdout.splitlines()[:-1])
        except Exception as e:
            self.error_msgbox(e)
            return ""

    def insert_infected_files(self, output):
        self.output_textbox_yararules.configure(state="normal")
        self.output_textbox_yararules.delete("1.0", "end")
        self.output_textbox_yararules.insert("end", output)
        self.output_textbox_yararules.configure(state="disabled")

    def quick_scan(self):
        output = ""
        raw_paths = ["$HOME/Desktop/python", "$HOME/Downloads"]
        paths = [os.path.expandvars(path) for path in raw_paths]

        for path in paths:
            output += self.show_infected_files(path)

            self.insert_clean_files(path)
            self.insert_infected_files(output)

    def count_files(self, path):
        try:
            return sum(self.count_files(os.path.join(path, f)) if os.path.isdir(os.path.join(path, f)) else 1 for f in os.listdir(path))
        except PermissionError:
            return 0

    def files_rec(self, path):
        files = []
        try:
            for entry in os.listdir(path):
                full_path = os.path.join(path, entry)
                if os.path.isfile(full_path):
                    files.append(full_path)
                elif os.path.isdir(full_path):
                    files.extend(self.files_rec(full_path))
        except PermissionError:
            pass
        return files

    def insert_counted_files_textbox(self, count):
        self.output_textbox_files.configure(state="normal")
        self.output_textbox_files.delete("1.0", "end")
        self.output_textbox_files.insert("end", str(count))
        self.output_textbox_files.configure(state="disabled")

    def count_infected_files(self):
        try:
            with open("infected.txt") as f:
                output = "".join(f.readlines()[:-1])
            subprocess.call("rm infected.txt", shell=True)
        except Exception:
            output = "0"
        self.output_textbox_virus.configure(state="normal")
        self.output_textbox_virus.delete("1.0", "end")
        self.output_textbox_virus.insert("end", output)
        self.output_textbox_virus.configure(state="disabled")

    def delete_content(self):
        path = self.delete.get()
        self.info_msgbox("Scanning is starting")
        if os.path.isfile(path):
            subprocess.call(f"rm {path}", shell=True)
        else:
            subprocess.call(f"rm -rf {path}", shell=True)

    def insert_clean_files(self, path):
        total_files = self.files_rec(path)
        infected_files = self.show_infected_files(path).splitlines()
        infected_names = [line.split()[1] for line in infected_files if '/' in line and len(line.split()) > 1]
        clean_files = [f for f in total_files if f not in infected_names]

        output = "\n".join([f"[✓] OK {f}" for f in clean_files])
        self.output_textbox_scannedfiles.configure(state="normal")
        self.output_textbox_scannedfiles.delete("1.0", "end")
        self.output_textbox_scannedfiles.insert("end", output)
        self.output_textbox_scannedfiles.configure(state="disabled")

    def start_scan(self):
        path = self.entry_path.get()
        self.insert_infected_files(self.show_infected_files(path))
        self.insert_counted_files_textbox(self.count_files(path))
        self.insert_clean_files(path)

    def show_extension_changed_files(self, path):
        try:
            result = subprocess.run(f"nim c -r hidenseek.nim -e {path}", text=True, shell=True, capture_output=True)
            return '\n'.join(result.stdout.splitlines()[:-1])
        except Exception as e:
            self.error_msgbox(e)
            return ""

    def extension_check(self) : 
        path = self.entry_path.get()

        output = self.show_extension_changed_files(path).splitlines()
        output = list(set(output))

        for i in range(0, len(output)) : 
            output[i] += '\n'

        aux = ""
        for file in output : 
            aux += file        

        self.output_textbox_yararules.configure(state="normal")
        self.output_textbox_yararules.delete("1.0", "end")
        self.output_textbox_yararules.insert("end", aux)
        self.output_textbox_yararules.configure(state="disabled")

if __name__ == "__main__":
    app = HideNSeek()
    app.mainloop()