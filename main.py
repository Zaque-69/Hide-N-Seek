import os
import subprocess
import tkinter
from tkinter import filedialog, messagebox

import customtkinter as ctk
from customtkinter import CTkImage
from PIL import Image

BUTTON_BORDER = "#585025"
VIRUS_COLOR = "#EEC541"
TEXT_WHITE = "#F4F2E6"
TEXTBOX_COLOR = "#1D1F1E"
HOVER_TEXTBOX_COLOR = "#151515"
BORDER_BUTTON_COLOR = "#363837"
VIBRANT_YELLOW = "#E4C44C"

class HideNSeek(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Verificare Path")
        self.geometry("900x530")
        self.resizable(False, False)
        ctk.set_appearance_mode("Dark")

        self.create_widgets()

    def create_widgets(self):
        self.label_titlu = ctk.CTkLabel(self, text = "Hide 'N Seek", font = ctk.CTkFont(size = 20, weight = "bold"))
        self.label_titlu.place(x = 30, y = 20)

        self.frame_input = ctk.CTkFrame(self)
        self.frame_input.place(x = 30, y = 60)

        self.label_path = ctk.CTkLabel(self.frame_input, text = "Enter a path to scan :")
        self.label_path.pack()

        self.entry_path = ctk.CTkEntry(self.frame_input, width = 400, placeholder_text = "Ex: /home/user/Downloads")
        self.entry_path.pack()

        self.output_textbox_yararules = ctk.CTkTextbox(self, width = 660, height = 150, text_color = VIBRANT_YELLOW)
        self.output_textbox_yararules.place(x = 30, y = 140)

        self.output_textbox_scannedfiles = ctk.CTkTextbox(self, width = 660, height = 150)
        self.output_textbox_scannedfiles.place(x = 30, y = 310)

        self.output_textbox_files = ctk.CTkTextbox(self, width = 55, height = 30, text_color = TEXT_WHITE)
        self.output_textbox_files.place(x = 577, y = 95)

        self.output_textbox_virus = ctk.CTkTextbox(self, width = 55, height = 30, text_color = VIBRANT_YELLOW)
        self.output_textbox_virus.place(x = 640, y = 95)

        self.button_verifica = ctk.CTkButton(self, text = "SCAN", width = 120, command = self.start_scan,
            fg_color = TEXTBOX_COLOR, border_width = 2, border_color = BORDER_BUTTON_COLOR,
            hover_color = HOVER_TEXTBOX_COLOR, corner_radius = 4)
        self.button_verifica.place(x = 575, y = 60)

        folder_img = CTkImage(dark_image = Image.open("./assets/folder.png"), size = (30, 30))
        self.folder_button = ctk.CTkButton(self, width = 60, height = 60, image = folder_img, text = "", command = self.browse_folder,
            fg_color = TEXTBOX_COLOR, border_width = 2, border_color = BORDER_BUTTON_COLOR,
            hover_color = HOVER_TEXTBOX_COLOR, corner_radius = 4)
        self.folder_button.place(x = 440, y = 60)

        self.clear_button = ctk.CTkButton(self, text = "CLEAR", width = 60, height = 60, command = self.clear_textboxes,
            fg_color = TEXTBOX_COLOR, border_width = 2, border_color = BORDER_BUTTON_COLOR,
            hover_color = HOVER_TEXTBOX_COLOR, corner_radius = 4)
        self.clear_button.place(x = 508, y = 60)

        quick_img = CTkImage(dark_image = Image.open("./assets/quickscan.png"), size = (100, 100))
        self.qs_button = ctk.CTkButton(self, width = 130, height = 160, image = quick_img, text = "", command = self.quick_scan,
            fg_color = TEXTBOX_COLOR, border_width = 2, border_color = BORDER_BUTTON_COLOR,
            hover_color = HOVER_TEXTBOX_COLOR, corner_radius = 4)
        self.qs_button.place(x = 740, y = 100)

        ext_img = CTkImage(dark_image = Image.open("./assets/file.png"), size = (100, 100))
        self.ext_button = ctk.CTkButton(self, width = 130, height = 160, image = ext_img, text = "", command = self.extension_check,
            fg_color = TEXTBOX_COLOR, border_width = 2, border_color = BORDER_BUTTON_COLOR,
            hover_color = HOVER_TEXTBOX_COLOR, corner_radius = 4)
        self.ext_button.place(x = 740, y = 280)

        trash_img = CTkImage(dark_image = Image.open("./assets/trash.png"), size = (25, 25))
        self.trash_button = ctk.CTkButton(self, width = 35, height = 35, image = trash_img, text = "", command = self.delete_content,
            fg_color = TEXTBOX_COLOR, border_width = 2, border_color = BORDER_BUTTON_COLOR,
            hover_color = HOVER_TEXTBOX_COLOR, corner_radius = 4)
        self.trash_button.place(x = 655, y = 480)

        self.separator = ctk.CTkFrame(self, width = 2, height = 530, fg_color = TEXTBOX_COLOR)
        self.separator.place(x = 720, y = 0)

        self.delete = ctk.CTkEntry(self, width = 615, height = 35, placeholder_text = "Path to delete file.")
        self.delete.place(x = 30, y = 480)

    def browse_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.entry_path.delete(0, tkinter.END)
            self.entry_path.insert(0, path)

    def clear_textboxes(self):
        self.output_textbox_yararules.delete("1.0", "end")
        self.output_textbox_scannedfiles.delete("1.0", "end")
        self.output_textbox_files.delete("1.0", "end")
        self.output_textbox_virus.delete("1.0", "end")

    def run_scan(self, option, path):
        try:
            result = subprocess.run("nim c -r hidenseek.nim " + option + " " + path,
                shell = True, capture_output = True, text = True)
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                lines.pop()
            return lines
        except Exception as e:
            messagebox.showerror("ERROR", str(e))
            return []

    def files_rec(self, path):
        lista = []
        try:
            for item in os.listdir(path):
                full = os.path.join(path, item)
                if os.path.isfile(full):
                    lista.append(full)
                elif os.path.isdir(full):
                    lista.extend(self.files_rec(full))
        except Exception as e:
            pass
        return lista

    def insert_clean_files(self, path, infected_list):
        all_files = self.files_rec(path)
        infected_files = []

        for line in infected_list:
            parts = line.split()
            if len(parts) > 1:
                if len(parts) < 3 : 
                    infected_files.append(parts[1])
                else : 
                    infected_files.append(parts[0])
        
        for file in all_files:
            if file not in infected_files:
                self.output_textbox_scannedfiles.insert("end", "[✓] OK " + file + "\n")

    def count_files(self, path):
        total = 0
        try:
            for f in os.listdir(path):
                full = os.path.join(path, f)
                if os.path.isdir(full):
                    total = total + self.count_files(full)
                else:
                    total = total + 1
        except Exception as e:
            messagebox.showerror("ERROR", e)
        return total

    def delete_content(self):
        path = self.delete.get()

        os.system(f"rm {path}")
        messagebox.showinfo("INFO", "Deleted successfully")

    def number_of_viruses(self, keyword):
        content = self.output_textbox_yararules.get("1.0", "end")
        return content.count(keyword)

    def quick_scan(self):
        paths = [os.path.expanduser("~/Desktop"), os.path.expanduser("~/Downloads")]
        for path in paths:
            output = self.run_scan("-m", path)
            for line in output:
                self.output_textbox_yararules.insert("end", line + "\n")
            self.insert_clean_files(path, output)

        self.output_textbox_virus.delete("1.0", "end")
        self.output_textbox_virus.insert("end", str(self.number_of_viruses("Linux")))

        self.output_textbox_files.delete("1.0", "end")
        self.output_textbox_files.insert("end", str((self.count_files(os.path.expanduser("~/Desktop/python")) + self.count_files(os.path.expanduser("~/Downloads"))) - self.number_of_viruses("Linux")))

    def extension_check(self):
        path = self.entry_path.get()
        output = self.run_scan("-e", path)

        l = []
        for linie in output:
            if linie not in l:
                l.append(linie)
        self.output_textbox_yararules.delete("1.0", "end")

        for linie in l:
            self.output_textbox_yararules.insert("end", linie + "\n")

        self.insert_clean_files(path, l)
        messagebox.showinfo("INFO", "Succes!")

        self.output_textbox_virus.delete("1.0", "end")
        self.output_textbox_virus.insert("end", str(self.number_of_viruses("has")))

        self.output_textbox_files.delete("1.0", "end")
        self.output_textbox_files.insert("end", str(self.count_files(path) - self.number_of_viruses("has")))

    def start_scan(self):
        path = self.entry_path.get()
        output = self.run_scan("-m", path)
        self.output_textbox_yararules.delete("1.0", "end")

        for line in output:
            self.output_textbox_yararules.insert("end", line + "\n")

        self.output_textbox_virus.delete("1.0", "end")
        self.output_textbox_virus.insert("end", str(self.number_of_viruses("Linux")))

        self.output_textbox_files.delete("1.0", "end")
        self.output_textbox_files.insert("end", str(self.count_files(path) - self.number_of_viruses("Linux")))

        self.insert_clean_files(path, output)

        messagebox.showinfo("INFO", "Success!")


if __name__ == "__main__":
    app = HideNSeek()
    app.mainloop()
