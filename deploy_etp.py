import os
import logging
import shutil
import paramiko
import socket
import pandas as pd
from stat import S_ISDIR
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from threading import Thread, Event
from concurrent.futures import ThreadPoolExecutor, as_completed
import atexit

# Configuration - Adjust as needed
DEFAULT_SOURCE_FOLDER = r'C:\Source\ETPStoreFrontV5.5'
HOST_USER = 'linuxadmin'
HOST_PASS = 'St0re@dm1n'
TILL_USER = 'posuser'
TILL_PASS = 'till@123'
TILL_START_OCTET = 111  # Till1 -> .112, Till2 -> .113, etc.
TILL_DEST_BASE = '/home/posuser/ETPSuite/ETPStoreFrontV5.5'
HOST_DEST = '/home/linuxadmin/ETPStoreFrontV5.5'
TIMEOUT_CONNECT = 3
TIMEOUT_TRANSFER = 6
MAX_WORKERS = 5

SOURCE_FOLDER = DEFAULT_SOURCE_FOLDER

class DeploymentGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ETP Deployment Tool")
        self.root.geometry("900x750")

        self.source_folder = tk.StringVar(value=DEFAULT_SOURCE_FOLDER)
        self.config_file = tk.StringVar(value='deployment_config.xlsx')
        self.manual_host_ip = tk.StringVar()
        self.manual_till_nums = tk.StringVar()
        self.stop_event = Event()
        self.is_deploying = False
        self.is_reattempting = False
        self.is_manual = False
        self.logger = None
        self.deployment_thread = None
        self.reattempt_thread = None
        self.manual_thread = None
        self.excel_log = None
        self.last_results_file = None
        self.total_tasks = 0
        self.completed_tasks = 0
        self.results = []

        self.setup_ui()
        self.setup_logging()
        atexit.register(self.save_on_exit)

    def save_on_exit(self):
        if self.results and self.excel_log:
            try:
                pd.DataFrame(self.results).to_excel(self.excel_log, index=False)
                self.logger.info("Emergency save completed on exit.")
            except Exception as e:
                self.logger.error(f"Emergency save failed: {str(e)}")

    def setup_ui(self):
        # Source Folder
        tk.Label(self.root, text="Source Folder:").pack(pady=5)
        source_frame = tk.Frame(self.root)
        source_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Entry(source_frame, textvariable=self.source_folder, width=70).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(source_frame, text="Browse", command=self.browse_source).pack(side=tk.RIGHT, padx=5)

        # Config File
        tk.Label(self.root, text="Config Excel File:").pack(pady=5)
        config_frame = tk.Frame(self.root)
        config_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Entry(config_frame, textvariable=self.config_file, width=70).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(config_frame, text="Browse", command=self.browse_config).pack(side=tk.RIGHT, padx=5)

        # Manual Deployment Section
        manual_frame = tk.LabelFrame(self.root, text="Manual Deployment", padx=15, pady=15)
        manual_frame.pack(pady=15, fill=tk.X, padx=20)

        tk.Label(manual_frame, text="Host IP (e.g., 10.0.70.12):").grid(row=0, column=0, sticky=tk.W, pady=8)
        tk.Entry(manual_frame, textvariable=self.manual_host_ip, width=35).grid(row=0, column=1, padx=10, pady=8)

        tk.Label(manual_frame, text="Till Numbers (e.g., 1,3,4):").grid(row=1, column=0, sticky=tk.W, pady=8)
        tk.Entry(manual_frame, textvariable=self.manual_till_nums, width=35).grid(row=1, column=1, padx=10, pady=8)

        self.manual_btn = tk.Button(manual_frame, text="Manual Deploy", command=self.start_manual, bg='purple', fg='white', width=20, font=("Arial", 10, "bold"))
        self.manual_btn.grid(row=2, column=0, columnspan=2, pady=15)

        # Main Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        self.start_btn = tk.Button(button_frame, text="Start Deployment", command=self.start_deployment, bg='green', fg='white', width=18)
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = tk.Button(button_frame, text="Stop Deployment", command=self.stop_deployment, bg='red', fg='white', width=18, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        self.reattempt_btn = tk.Button(button_frame, text="Reattempt Failed Tills", command=self.start_reattempt, bg='blue', fg='white', width=22)
        self.reattempt_btn.pack(side=tk.LEFT, padx=10)

        # Progress
        self.progress = ttk.Progressbar(self.root, mode='determinate', length=600)
        self.progress.pack(pady=15, padx=20, fill=tk.X)

        self.progress_label = tk.Label(self.root, text="0% Complete", font=("Arial", 12))
        self.progress_label.pack(pady=5)

        # Status
        self.status_label = tk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 10))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

        # Log Area
        tk.Label(self.root, text="Log Output:").pack(pady=(10,5), anchor=tk.W, padx=20)
        self.log_text = scrolledtext.ScrolledText(self.root, height=15, font=("Consolas", 10))
        self.log_text.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

        # Results Button
        self.results_btn = tk.Button(self.root, text="Open Results Excel", command=self.open_results, state=tk.DISABLED)
        self.results_btn.pack(pady=10)

    def setup_logging(self):
        self.log_filename = f'deployment_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        file_handler = logging.FileHandler(self.log_filename)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)

        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget

            def emit(self, record):
                msg = self.format(record)
                self.text_widget.insert(tk.END, msg + '\n')
                self.text_widget.see(tk.END)

        gui_handler = TextHandler(self.log_text)
        gui_handler.setFormatter(formatter)
        self.logger.addHandler(gui_handler)

    def browse_source(self):
        folder = filedialog.askdirectory(initialdir=self.source_folder.get())
        if folder:
            self.source_folder.set(folder)

    def browse_config(self):
        file = filedialog.askopenfilename(filetypes=[("Excel files", "*.xlsx;*.xls")])
        if file:
            self.config_file.set(file)

    def disable_all_buttons(self):
        self.start_btn.config(state=tk.DISABLED)
        self.reattempt_btn.config(state=tk.DISABLED)
        self.manual_btn.config(state=tk.DISABLED)
        self.results_btn.config(state=tk.DISABLED)

    def enable_all_buttons(self):
        self.start_btn.config(state=tk.NORMAL)
        self.reattempt_btn.config(state=tk.NORMAL)
        self.manual_btn.config(state=tk.NORMAL)
        self.results_btn.config(state=tk.NORMAL if self.excel_log else tk.DISABLED)

    def start_deployment(self):
        if self.is_deploying or self.is_manual or self.is_reattempting:
            return

        source_path = self.source_folder.get()
        config_path = self.config_file.get()
        if not os.path.exists(source_path):
            messagebox.showerror("Error", "Source folder does not exist!")
            return
        if not os.path.exists(config_path):
            messagebox.showerror("Error", "Config file does not exist!")
            return

        global SOURCE_FOLDER
        SOURCE_FOLDER = source_path

        try:
            df = pd.read_excel(config_path)
            self.total_tasks = len(df)
        except Exception as e:
            messagebox.showerror("Error", f"Cannot read config: {e}")
            return

        self.is_deploying = True
        self.disable_all_buttons()
        self.stop_btn.config(state=tk.NORMAL)
        self.stop_event.clear()
        self.progress['value'] = 0
        self.progress_label.config(text="0% Complete")
        self.status_label.config(text="Deploying from config...")

        self.deployment_thread = Thread(target=self.run_deployment, args=(config_path,))
        self.deployment_thread.daemon = True
        self.deployment_thread.start()

    def stop_deployment(self):
        self.stop_event.set()
        self.status_label.config(text="Stopping... Please wait.")

    def start_manual(self):
        if self.is_deploying or self.is_manual or self.is_reattempting:
            return

        host_ip = self.manual_host_ip.get().strip()
        till_str = self.manual_till_nums.get().strip()

        if not host_ip or not till_str:
            messagebox.showerror("Error", "Please enter Host IP and Till numbers!")
            return

        try:
            till_nums = [int(x.strip()) for x in till_str.split(',') if x.strip().isdigit()]
            if not till_nums:
                raise ValueError
        except:
            messagebox.showerror("Error", "Invalid till numbers. Use comma-separated integers.")
            return

        source_path = self.source_folder.get()
        if not os.path.exists(source_path):
            messagebox.showerror("Error", "Source folder does not exist!")
            return

        global SOURCE_FOLDER
        SOURCE_FOLDER = source_path

        prefix = '.'.join(host_ip.split('.')[:3])
        till_ips = [f"{prefix}.{TILL_START_OCTET + n}" for n in till_nums]

        self.total_tasks = len(till_ips)
        self.completed_tasks = 0

        self.is_manual = True
        self.disable_all_buttons()
        self.stop_btn.config(state=tk.NORMAL)
        self.stop_event.clear()
        self.progress['value'] = 0
        self.progress_label.config(text="0% Complete")
        self.status_label.config(text="Manual deployment in progress...")

        self.manual_thread = Thread(target=self.run_manual_deployment, args=(till_ips,))
        self.manual_thread.daemon = True
        self.manual_thread.start()

    def run_manual_deployment(self, till_ips):
        try:
            for till_ip in till_ips:
                if self.stop_event.is_set():
                    self.logger.info("Manual deployment stopped by user.")
                    break

                self.logger.info(f"MANUAL: Deploying to Till {till_ip}")
                success = self.direct_upload_to_till(till_ip)
                status = "Success" if success else "Failure"
                self.logger.info(f"MANUAL: Till {till_ip} -> {status}")

                self.completed_tasks += 1
                percent = (self.completed_tasks / self.total_tasks) * 100
                self.root.after(0, lambda p=percent: (
                    self.progress.config(value=p),
                    self.progress_label.config(text=f"{int(p)}% Complete")
                ))

        except Exception as e:
            self.logger.error(f"Manual deployment error: {e}")
        finally:
            self.root.after(0, self.manual_complete)

    def direct_upload_to_till(self, till_ip):
        transport = connect_transport(till_ip, TILL_USER, TILL_PASS, TIMEOUT_CONNECT, logger=self.logger)
        if not transport:
            return False

        transport.sock.settimeout(TIMEOUT_TRANSFER)
        sftp = paramiko.SFTPClient.from_transport(transport)
        try:
            # Ensure destination exists
            try:
                sftp.stat(TILL_DEST_BASE)
            except FileNotFoundError:
                parent = '/home/posuser/ETPSuite'
                try:
                    sftp.stat(parent)
                except FileNotFoundError:
                    sftp.mkdir(parent)
                sftp.mkdir(TILL_DEST_BASE)

            upload_folder(sftp, SOURCE_FOLDER, TILL_DEST_BASE, self.logger)
            return True
        except Exception as e:
            self.logger.error(f"Upload failed to {till_ip}: {e}")
            return False
        finally:
            sftp.close()
            transport.close()

    def manual_complete(self):
        self.is_manual = False
        self.enable_all_buttons()
        self.stop_btn.config(state=tk.DISABLED)
        self.progress['value'] = 100
        self.progress_label.config(text="100% Complete")
        self.status_label.config(text="Manual Deployment Complete")
        messagebox.showinfo("Success", "Manual deployment finished. Check log for details.")

    # Rest of your existing functions (start_reattempt, run_reattempt, etc.) remain unchanged
    # ... (keep your existing reattempt, deployment, etc. code here)

    def deployment_complete(self):
        self.is_deploying = False
        self.enable_all_buttons()
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_label.config(text="Deployment Complete")
        self.results_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Complete", "Deployment finished successfully!")

    def open_results(self):
        if self.excel_log and os.path.exists(self.excel_log):
            os.startfile(self.excel_log)

# Keep all your existing helper functions below (is_port_reachable, connect_transport, upload_folder, etc.)
# They are unchanged from your working version

def is_port_reachable(host, port, timeout, logger):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

def connect_transport(host, username, password, timeout, port=22, logger=None):
    if logger is None:
        logger = logging.getLogger(__name__)
    logger.info(f"Attempting to connect to {host}:{port} as {username}")

    if not is_port_reachable(host, port, timeout, logger):
        logger.error(f"Cannot reach {host}:{port}")
        return None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        transport.auth_password(username, password)
        transport.set_keepalive(30)
        logger.info(f"Authenticated to {host}")
        return transport
    except Exception as e:
        logger.error(f"Connection failed to {host}: {e}")
        return None

def upload_folder(sftp, local_dir, remote_dir, logger):
    if not os.path.isdir(local_dir):
        raise Exception(f"Local folder not found: {local_dir}")

    try:
        sftp.mkdir(remote_dir)
    except IOError:
        pass  # Already exists

    for item in os.listdir(local_dir):
        local_path = os.path.join(local_dir, item)
        remote_path = remote_dir + '/' + item
        try:
            if os.path.isdir(local_path):
                upload_folder(sftp, local_path, remote_path, logger)
            else:
                sftp.put(local_path, remote_path)
                logger.debug(f"Uploaded: {item}")
        except Exception as e:
            logger.error(f"Failed to upload {item}: {e}")
            raise

# Add your existing deploy_to_host, copy_dir_between_sfpts, delete_remote_folder if needed
# (They are not required for manual mode since we do direct upload)

if __name__ == "__main__":
    root = tk.Tk()
    app = DeploymentGUI(root)
    root.mainloop()