import customtkinter as ctk
import os
import subprocess

DARK_VIBRANT_YELLOW = "#978417"
DARK_DARK_VIBRANT_YELLOW = "#74671f"
BUTTON_BORDER = "#585025"
VIRUS_COLOR = "#EEC541"
TEXT_WHITE = "#F4F2E6"

class HideNSeek(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Verificare Path")
        self.geometry("1200x600")
        self.resizable(False, False)

        ctk.set_appearance_mode("Dark")

        self.create_textboxes()
        self.create_buttons()
        self.create_other_widgets()

    def create_textboxes(self) : 
        self.output_textbox_yararules = ctk.CTkTextbox(self, width = 650, height = 200, text_color = VIRUS_COLOR )
        self.output_textbox_yararules.place( x = 40, y = 140)
        self.output_textbox_yararules.configure( state = "disabled" )

        self.output_textbox_scannedfiles = ctk.CTkTextbox(self, width = 650, height = 200)
        self.output_textbox_scannedfiles.place( x = 40, y = 360)
        self.output_textbox_scannedfiles.configure( state = "disabled" )

        self.output_textbox_files = ctk.CTkTextbox( self, width = 35, height = 30, text_color = TEXT_WHITE )
        self.output_textbox_files.place( x = 580, y = 100)
        self.output_textbox_files.configure( state = "disabled" )

        self.output_textbox_virus = ctk.CTkTextbox( self, width = 35, height = 30, text_color = VIRUS_COLOR )
        self.output_textbox_virus.place( x = 620, y = 100)
        self.output_textbox_virus.configure( state = "disabled" )

    def create_buttons(self) : 
        self.button_verifica = ctk.CTkButton( self, text="SCAN", fg_color = DARK_VIBRANT_YELLOW, hover_color = DARK_DARK_VIBRANT_YELLOW, border_color = BUTTON_BORDER, corner_radius = 4, command=self.start_scan )
        self.button_verifica.place( x = 550, y = 60 )

    def create_other_widgets(self) : 
        self.label_titlu = ctk.CTkLabel( self, text = "Hide 'N Seek", font = ctk.CTkFont(size = 20, weight = "bold") )
        self.label_titlu.place( x = 40, y = 20 )

        self.frame_input = ctk.CTkFrame(self)
        self.frame_input.place( x = 40, y = 60 )

        self.frame_root_password = ctk.CTkFrame(self)
        self.frame_root_password.place( x = 335, y = 60 )

        self.label_path = ctk.CTkLabel( self.frame_input, text = "Enter a path to scan :")
        self.label_path.pack()

        self.entry_path = ctk.CTkEntry( self.frame_input, width = 280, placeholder_text="Ex: /home/user/Downloads/directory" )
        self.entry_path.pack()

        self.label_path = ctk.CTkLabel( self.frame_root_password, text="Enter the root password : ")
        self.label_path.pack()

        self.entry_path = ctk.CTkEntry( self.frame_root_password, width = 200, placeholder_text="Ex: admin" )
        self.entry_path.pack()
    
    def scan_path(self) :
        path = self.entry_path.get()
        files = ""

        if len(path) > 0 : 
            subprocess.call(f"nim c -r hidenseek.nim -m {path} > infected.txt", shell = True )
            files = open("infected.txt", "r").read()
        else : 
            files = "No such path. Please try again with another one!"

        self.output_textbox_yararules.configure( state = "normal" )
        self.output_textbox_yararules.delete( "1.0", "end" )
        self.output_textbox_yararules.insert( "end", files )
        self.output_textbox_yararules.configure( state = "disabled" )

    def count_files_scanned(self) :
        path = self.entry_path.get()
        count_files = len(os.listdir(path))

        self.output_textbox_files.configure( state = "normal" )
        self.output_textbox_files.delete( "1.0", "end" )
        self.output_textbox_files.insert("end", count_files )
        self.output_textbox_files.configure( state="disabled" )

    def count_infected_files(self) : 
        with open("infected.txt", 'r') as fp:
            lines = len(fp.readlines())
        subprocess.call( "rm infected.txt", shell = True )

        self.output_textbox_virus.configure( state="normal" )
        self.output_textbox_virus.delete( "1.0", "end" )
        self.output_textbox_virus.insert("end", lines - 1 )
        self.output_textbox_virus.configure( state="disabled" )

    def start_scan(self) : 
        path = self.entry_path.get()
        self.scan_path()

        if len(path) > 0 : 
            self.count_files_scanned()
            self.count_infected_files()

if __name__ == "__main__":
    app = HideNSeek()
    app.mainloop()
