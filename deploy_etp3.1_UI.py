import tkinter as tk
from tkinter import ttk
import threading
import time

class CompetitionStatusGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Competition Status Tracker")
        self.root.geometry("400x300")
        self.root.resizable(False, False)

        # Variables
        self.is_running = False
        self.count = 0
        self.status_var = tk.StringVar(value="Ready")
        self.count_var = tk.StringVar(value="0")

        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_ui(self):
        # Title
        title_label = tk.Label(self.root, text="Competition Status", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        # Status Label
        status_frame = tk.Frame(self.root)
        status_frame.pack(pady=5)
        tk.Label(status_frame, text="Status:", font=("Arial", 10)).pack(side=tk.LEFT)
        tk.Label(status_frame, textvariable=self.status_var, font=("Arial", 10, "bold"), fg="blue").pack(side=tk.LEFT, padx=5)

        # Count Label
        count_frame = tk.Frame(self.root)
        count_frame.pack(pady=5)
        tk.Label(count_frame, text="Count:", font=("Arial", 10)).pack(side=tk.LEFT)
        tk.Label(count_frame, textvariable=self.count_var, font=("Arial", 10, "bold"), fg="green").pack(side=tk.LEFT, padx=5)

        # Progress Bar (Loading Bar)
        self.progress = ttk.Progressbar(self.root, mode='determinate', length=300, maximum=100)
        self.progress.pack(pady=20)

        # Buttons Frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=20)

        self.start_btn = tk.Button(button_frame, text="Start", command=self.start_competition, bg='green', fg='white', width=10)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.pause_btn = tk.Button(button_frame, text="Pause", command=self.pause_competition, bg='orange', fg='white', width=10, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)

        self.reset_btn = tk.Button(button_frame, text="Reset", command=self.reset_competition, bg='red', fg='white', width=10)
        self.reset_btn.pack(side=tk.LEFT, padx=5)

    def start_competition(self):
        if not self.is_running:
            self.is_running = True
            self.start_btn.config(state=tk.DISABLED)
            self.pause_btn.config(state=tk.NORMAL)
            self.status_var.set("Running")
            self.update_thread = threading.Thread(target=self.update_status, daemon=True)
            self.update_thread.start()

    def pause_competition(self):
        if self.is_running:
            self.is_running = False
            self.pause_btn.config(state=tk.DISABLED)
            self.status_var.set("Paused")
        else:
            self.start_competition()  # Resume if paused

    def reset_competition(self):
        self.is_running = False
        self.count = 0
        self.count_var.set("0")
        self.progress['value'] = 0
        self.status_var.set("Ready")
        self.start_btn.config(state=tk.NORMAL)
        self.pause_btn.config(state=tk.DISABLED)

    def update_status(self):
        while self.is_running:
            self.count += 1
            self.count_var.set(str(self.count))
            progress_value = min((self.count % 100) + 1, 100)  # Cycle progress 1-100
            self.progress['value'] = progress_value
            self.root.update_idletasks()
            time.sleep(0.5)  # Update every 0.5 seconds

    def on_closing(self):
        self.is_running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CompetitionStatusGUI(root)
    root.mainloop()