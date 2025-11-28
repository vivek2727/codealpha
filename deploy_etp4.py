import os
import logging
import shutil
import paramiko
import socket
import pandas as pd
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from stat import S_ISDIR
from datetime import datetime
from threading import Thread

# Configuration - Adjust as needed
DEFAULT_SOURCE_FOLDER = r'C:\Source\ETPStoreFrontV5.5'
HOST_USER = 'linuxadmin'
HOST_PASS = 'St0re@dm1n'  # Confirmed as per your message
TILL_USER = 'posuser'
TILL_PASS = 'till@123'
TILL_START_OCTET = 111  # Till1 -> .112, Till2 -> .113, etc. (111 + till_num)
TILL_DEST_BASE = '/home/posuser/ETPSuite/ETPStoreFrontV5.5'  # As per requirement
HOST_DEST = '/home/linuxadmin/ETPStoreFrontV5.5'  # Fixed for hosts
TIMEOUT_CONNECT = 3  # Seconds for connection attempts
TIMEOUT_TRANSFER = 6  # Approximate for transfer operations (paramiko timeouts)
MAX_RETRIES = 3  # Number of retry attempts for failed connections/transfers
RETRY_DELAY = 5  # Seconds to wait between retries

class DeploymentGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ETP Deployment Tool")
        self.root.geometry("800x600")

        # Variables
        self.source_folder = tk.StringVar(value=DEFAULT_SOURCE_FOLDER)
        self.config_file = tk.StringVar(value='deployment_config.xlsx')
        self.log_filename = None
        self.excel_log = None
        self.logger = None
        self.deployment_thread = None
        self.is_deploying = False

        self.setup_ui()
        self.setup_logging()

    def setup_ui(self):
        # Source Folder
        tk.Label(self.root, text="Source Folder:").pack(pady=5)
        source_frame = tk.Frame(self.root)
        source_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Entry(source_frame, textvariable=self.source_folder, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(source_frame, text="Browse", command=self.browse_source).pack(side=tk.RIGHT, padx=5)

        # Config File
        tk.Label(self.root, text="Config Excel:").pack(pady=5)
        config_frame = tk.Frame(self.root)
        config_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Entry(config_frame, textvariable=self.config_file, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(config_frame, text="Browse", command=self.browse_config).pack(side=tk.RIGHT, padx=5)

        # Start Button
        self.start_btn = tk.Button(self.root, text="Start Deployment", command=self.start_deployment, bg='green', fg='white')
        self.start_btn.pack(pady=10)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(pady=5, fill=tk.X, padx=10)

        # Status Label
        self.status_label = tk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Log Text Area
        tk.Label(self.root, text="Log:").pack(pady=5)
        self.log_text = scrolledtext.ScrolledText(self.root, height=20, width=80)
        self.log_text.pack(pady=5, fill=tk.BOTH, expand=True, padx=10)

        # Results Button
        self.results_btn = tk.Button(self.root, text="Open Results Excel", command=self.open_results, state=tk.DISABLED)
        self.results_btn.pack(pady=5)

    def setup_logging(self):
        self.log_filename = f'deployment_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
        file_handler = logging.FileHandler(self.log_filename)
        stream_handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        stream_handler.setFormatter(formatter)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(stream_handler)

        # Redirect stream to GUI
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                logging.Handler.__init__(self)
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
        file = filedialog.askopenfilename(initialdir='.', filetypes=[("Excel files", "*.xlsx *.xls")])
        if file:
            self.config_file.set(file)

    def start_deployment(self):
        if self.is_deploying:
            return

        global SOURCE_FOLDER
        SOURCE_FOLDER = self.source_folder.get()
        if not os.path.exists(SOURCE_FOLDER):
            messagebox.showerror("Error", "Source folder does not exist!")
            return

        if not os.path.exists(self.config_file.get()):
            messagebox.showerror("Error", "Config file does not exist!")
            return

        self.is_deploying = True
        self.start_btn.config(state=tk.DISABLED)
        self.progress.start()
        self.status_label.config(text="Deploying...")

        self.deployment_thread = Thread(target=self.run_deployment)
        self.deployment_thread.daemon = True
        self.deployment_thread.start()

    def run_deployment(self):
        try:
            main_func(self.logger)  # Call the main deployment logic
            self.root.after(0, self.deployment_complete)
        except Exception as e:
            self.logger.error(f"Deployment failed: {str(e)}")
            self.root.after(0, self.deployment_complete)

    def deployment_complete(self):
        self.is_deploying = False
        self.start_btn.config(state=tk.NORMAL)
        self.progress.stop()
        self.status_label.config(text="Deployment Complete")
        self.results_btn.config(state=tk.NORMAL)
        messagebox.showinfo("Complete", "Deployment finished. Check log for details.")

    def open_results(self):
        if self.excel_log and os.path.exists(self.excel_log):
            os.startfile(self.excel_log)

def is_port_reachable(host, port, timeout):
    """Check if the host's port is reachable within timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            logging.getLogger(__name__).debug(f"Port {port} on {host} is reachable")
            return True
        else:
            logging.getLogger(__name__).warning(f"Port {port} on {host} is not reachable (error code: {result})")
            return False
    except socket.timeout:
        logging.getLogger(__name__).error(f"Timeout while checking port {port} on {host}")
        return False
    except Exception as e:
        logging.getLogger(__name__).error(f"Error checking port {port} on {host}: {str(e)}")
        return False

def connect_transport(host, username, password, timeout, port=22):
    """Connect to SSH transport with timeout."""
    logger = logging.getLogger(__name__)
    logger.info(f"Attempting to connect to {host}:{port} as {username} (timeout: {timeout}s)")
    
    # Pre-check port reachability
    if not is_port_reachable(host, port, timeout):
        logger.error(f"Cannot reach {host} on port {port}. Check network, firewall, or SSH service.")
        return None
    
    sock = None
    transport = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        logger.debug("TCP connect initiated...")
        sock.connect((host, port))
        logger.debug("TCP connect successful. Starting SSH handshake...")
        
        transport = paramiko.Transport(sock)
        transport.banner_timeout = timeout
        transport.packetizer.REKEY_BYTES = 5000000  # Reduce rekey to avoid long waits
        transport.start_client(timeout=timeout)
        
        logger.debug("SSH handshake started. Authenticating...")
        transport.auth_password(username, password)
        transport.set_keepalive(30)
        logger.info(f"Successfully connected and authenticated to {host} as {username}")
        return transport
        
    except paramiko.AuthenticationException:
        logger.error(f"Authentication failed for {username}@{host}. Check username/password.")
        return None
    except paramiko.SSHException as e:
        logger.error(f"SSH error connecting to {host}: {str(e)}")
        return None
    except socket.timeout:
        logger.error(f"Timeout during connection/handshake to {host} after {timeout}s")
        return None
    except Exception as e:
        logger.error(f"Unexpected error connecting to {host} as {username}: {str(e)}")
        return None
    finally:
        if sock and not transport:
            sock.close()

def upload_folder(sftp, local_dir, remote_dir):
    """Recursively upload local folder contents to remote directory."""
    if not os.path.isdir(local_dir):
        raise Exception(f"Local folder not found: {local_dir}")

    try:
        sftp.mkdir(remote_dir)
        logging.getLogger(__name__).info(f"Created remote directory: {remote_dir}")
    except IOError:
        logging.getLogger(__name__).debug(f"Remote directory already exists: {remote_dir}")

    for item in os.listdir(local_dir):
        local_item = os.path.join(local_dir, item)
        remote_item = f"{remote_dir}/{item}"
        try:
            if os.path.isdir(local_item):
                upload_folder(sftp, local_item, remote_item)
            else:
                sftp.put(local_item, remote_item)
                logging.getLogger(__name__).debug(f"Uploaded file: {item}")
        except Exception as e:
            logging.getLogger(__name__).error(f"Failed to upload {item}: {str(e)}")
            raise  # Re-raise to fail the whole operation

def copy_dir_between_sfpts(sftp_src, sftp_dest, src_dir, dst_dir):
    """Recursively copy directory contents from one SFTP to another. Overwrites existing files; does not delete extras."""
    logger = logging.getLogger(__name__)
    try:
        attrs = sftp_src.listdir_attr(src_dir)
    except Exception as e:
        logger.error(f"Cannot list source directory {src_dir}: {str(e)}")
        raise e  # Raise to trigger retry

    try:
        sftp_dest.stat(dst_dir)
        logger.debug(f"Destination {dst_dir} exists")
    except FileNotFoundError:
        sftp_dest.mkdir(dst_dir)
        logger.info(f"Created destination directory: {dst_dir}")
    except Exception as e:
        logger.error(f"Cannot access/create destination {dst_dir}: {str(e)}")
        raise e  # Raise to trigger retry

    for attr in attrs:
        if attr.filename.startswith('.'):
            continue  # Skip hidden files
        src_item = f"{src_dir}/{attr.filename}"
        dst_item = f"{dst_dir}/{attr.filename}"
        try:
            if S_ISDIR(attr.st_mode):
                copy_dir_between_sfpts(sftp_src, sftp_dest, src_item, dst_item)
            else:
                # Stream copy without temp files; overwrites if exists
                with sftp_src.open(src_item, 'rb') as fr:
                    with sftp_dest.open(dst_item, 'wb') as fw:
                        shutil.copyfileobj(fr, fw)
                logger.debug(f"Copied {attr.filename}")
        except Exception as e:
            logger.error(f"Failed to copy {attr.filename}: {str(e)}")
            raise e  # Raise to trigger retry for the whole operation

def retry_operation(operation, max_retries=MAX_RETRIES, delay=RETRY_DELAY):
    """Generic retry decorator for operations that may fail."""
    logger = logging.getLogger(__name__)
    for attempt in range(1, max_retries + 1):
        try:
            return operation()
        except Exception as e:
            logger.warning(f"Attempt {attempt}/{max_retries} failed: {str(e)}")
            if attempt == max_retries:
                logger.error(f"All {max_retries} attempts failed. Giving up.")
                raise
            time.sleep(delay)
    return None

def deploy_to_host(host_ip, max_till, results, logger):
    """Deploy to a single host and its tills, appending results."""
    # Compute network prefix for tills (first 3 octets of host_ip)
    prefix = '.'.join(host_ip.split('.')[:3])

    logger.info(f"Processing host {host_ip} with {max_till} tills (prefix: {prefix})")

    # Step 1: Copy folder from local to host (with retry)
    logger.info(f"Step 1: Copying ETPStoreFrontV5.5 from local to host {host_ip}")
    if not os.path.exists(SOURCE_FOLDER):
        logger.error(f"Source folder not found: {SOURCE_FOLDER}")
        return False

    def upload_to_host():
        host_transport = connect_transport(host_ip, HOST_USER, HOST_PASS, TIMEOUT_CONNECT)
        if not host_transport:
            raise Exception(f"Failed to connect to host {host_ip}")
        sftp_host = paramiko.SFTPClient.from_transport(host_transport)
        try:
            upload_folder(sftp_host, SOURCE_FOLDER, HOST_DEST)
        finally:
            sftp_host.close()
            host_transport.close()

    upload_success = False
    try:
        retry_operation(upload_to_host)
        logger.info(f"Step 1 completed: Folder uploaded to host {host_ip} successfully")
        upload_success = True
    except Exception as e:
        logger.error(f"Step 1 failed for host {host_ip} after retries: {str(e)}")

    if not upload_success:
        return False

    # Step 2: Distribute from host to tills (with retry per till)
    logger.info(f"Step 2: Distributing from host {host_ip} to tills")
    host_transport = connect_transport(host_ip, HOST_USER, HOST_PASS, TIMEOUT_CONNECT)
    if not host_transport:
        logger.error(f"Failed to reconnect to host {host_ip} for distribution.")
        return False

    host_transport.set_keepalive(30)
    sftp_host = paramiko.SFTPClient.from_transport(host_transport)
    till_success_count = 0
    try:
        for till_num in range(1, max_till + 1):
            till_octet = TILL_START_OCTET + till_num  # 111 + 1 = 112 for Till1
            till_ip = f"{prefix}.{till_octet}"
            logger.info(f"Processing Till{till_num} ({till_ip}) for host {host_ip}")

            def transfer_to_till():
                till_transport = connect_transport(till_ip, TILL_USER, TILL_PASS, TIMEOUT_CONNECT)
                if not till_transport:
                    raise Exception(f"Failed to connect to {till_ip}")
                till_transport.sock.settimeout(TIMEOUT_TRANSFER)
                sftp_till = paramiko.SFTPClient.from_transport(till_transport)
                try:
                    # Check/create TILL_DEST_BASE (includes ETPStoreFrontV5.5)
                    try:
                        sftp_till.stat(TILL_DEST_BASE)
                        logger.info(f"Destination exists on Till{till_num}")
                    except FileNotFoundError:
                        # Create parent ETPSuite if needed
                        parent_dir = '/home/posuser/ETPSuite'
                        try:
                            sftp_till.stat(parent_dir)
                        except FileNotFoundError:
                            sftp_till.mkdir(parent_dir)
                            logger.info(f"Created parent directory {parent_dir} on Till{till_num}")
                        sftp_till.mkdir(TILL_DEST_BASE)
                        logger.info(f"Created {TILL_DEST_BASE} on Till{till_num}")
                    except PermissionError:
                        raise Exception("Rights to create/access destination not present")
                    except Exception as e:
                        raise Exception(f"Cannot access destination: {str(e)}")

                    # Copy contents of HOST_DEST into TILL_DEST_BASE (overwrites, no deletions)
                    copy_dir_between_sfpts(sftp_host, sftp_till, HOST_DEST, TILL_DEST_BASE)
                finally:
                    sftp_till.close()
                    till_transport.close()

            transfer_success = False
            try:
                retry_operation(transfer_to_till)
                logger.info(f"Transfer completed successfully for Till{till_num}")
                transfer_success = True
                till_success_count += 1
            except Exception as e:
                logger.error(f"Transfer failed for Till{till_num} ({till_ip}) after retries: {str(e)}")

            status = 'Success' if transfer_success else 'Failure'
            results.append({'HostIP': host_ip, 'TillIP': till_ip, 'Status': status})
            logger.info(f"Status for Till{till_num} ({till_ip}): {status}")

    finally:
        sftp_host.close()
        host_transport.close()

    logger.info(f"Host {host_ip} deployment complete: {till_success_count}/{max_till} tills successful")
    return True

def main_func(logger):
    global SOURCE_FOLDER, excel_log
    # Get config file path
    config_file = gui.config_file.get() if 'gui' in globals() else 'deployment_config.xlsx'

    if not os.path.exists(config_file):
        logger.error(f"Config file not found: {config_file}")
        return

    try:
        df_config = pd.read_excel(config_file)
        if 'HostIP' not in df_config.columns or 'MaxTill' not in df_config.columns:
            logger.error("Config Excel must have columns: 'HostIP' and 'MaxTill'")
            return
    except Exception as e:
        logger.error(f"Failed to read config file {config_file}: {str(e)}")
        return

    results = []
    host_success_count = 0

    for index, row in df_config.iterrows():
        host_ip = str(row['HostIP']).strip()
        try:
            max_till = int(row['MaxTill'])
            if max_till <= 0:
                logger.warning(f"Invalid MaxTill {max_till} for {host_ip}; skipping")
                continue
        except (ValueError, TypeError):
            logger.error(f"Invalid MaxTill for {host_ip}; skipping")
            continue

        # Deploy to this host
        if deploy_to_host(host_ip, max_till, results, logger):
            host_success_count += 1

    # Save results to Excel
    excel_log = f'deployment_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    pd.DataFrame(results).to_excel(excel_log, index=False)
    logger.info(f"Deployment complete. Detailed log: {logger.name}.log")
    logger.info(f"Summary Excel log saved to: {excel_log}")
    logger.info(f"Processed {host_success_count}/{len(df_config)} hosts successfully")

if __name__ == "__main__":
    # Note: Run with Python 3.x. Install paramiko and pandas: pip install paramiko pandas openpyxl
    root = tk.Tk()
    gui = DeploymentGUI(root)
    root.mainloop()
