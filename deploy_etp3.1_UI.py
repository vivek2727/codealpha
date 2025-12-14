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

class DeploymentGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ETP Deployment Tool")
        self.root.geometry("800x600")

        # Variables
        self.config_file = tk.StringVar(value='deployment_config.xlsx')
        self.stop_event = Event()
        self.is_deploying = False
        self.logger = None
        self.deployment_thread = None
        self.excel_log = None

        self.setup_ui()
        self.setup_logging()

    def setup_ui(self):
        # Config File Selection
        tk.Label(self.root, text="Config Excel File:").pack(pady=5)
        config_frame = tk.Frame(self.root)
        config_frame.pack(pady=5, fill=tk.X, padx=10)
        tk.Entry(config_frame, textvariable=self.config_file, width=60).pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(config_frame, text="Browse", command=self.browse_config).pack(side=tk.RIGHT, padx=5)

        # Buttons Frame
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)

        self.start_btn = tk.Button(button_frame, text="Start Deployment", command=self.start_deployment, bg='green', fg='white', width=15)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(button_frame, text="Stop Deployment", command=self.stop_deployment, bg='red', fg='white', width=15, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, mode='indeterminate', length=400)
        self.progress.pack(pady=10, fill=tk.X, padx=10)

        # Status Label
        self.status_label = tk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

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
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)

        # Redirect to GUI
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

    def browse_config(self):
        file = filedialog.askopenfilename(initialdir='.', filetypes=[("Excel files", "*.xlsx *.xls")])
        if file:
            self.config_file.set(file)

    def start_deployment(self):
        if self.is_deploying:
            return

        config_path = self.config_file.get()
        if not os.path.exists(config_path):
            messagebox.showerror("Error", "Config file does not exist!")
            return

        self.is_deploying = True
        self.stop_event.clear()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress.start()
        self.status_label.config(text="Deploying...")

        self.deployment_thread = Thread(target=self.run_deployment, args=(config_path,))
        self.deployment_thread.daemon = True
        self.deployment_thread.start()

    def stop_deployment(self):
        if self.is_deploying:
            self.stop_event.set()
            self.status_label.config(text="Stopping...")
            self.logger.info("Stop signal sent. Deployment will stop after current operation.")

    def run_deployment(self, config_file):
        try:
            # Run the main logic
            results = []
            host_success_count = 0

            try:
                df_config = pd.read_excel(config_file)
                if 'HostIP' not in df_config.columns or 'MaxTill' not in df_config.columns:
                    self.logger.error("Config Excel must have columns: 'HostIP' and 'MaxTill'")
                    return
            except Exception as e:
                self.logger.error(f"Failed to read config file {config_file}: {str(e)}")
                return

            for index, row in df_config.iterrows():
                if self.stop_event.is_set():
                    self.logger.info("Deployment stopped by user.")
                    break

                host_ip = str(row['HostIP']).strip()
                try:
                    max_till = int(row['MaxTill'])
                    if max_till <= 0:
                        self.logger.warning(f"Invalid MaxTill {max_till} for {host_ip}; skipping")
                        continue
                except (ValueError, TypeError):
                    self.logger.error(f"Invalid MaxTill for {host_ip}; skipping")
                    continue

                # Deploy to this host (pass stop_event to check in deploy_to_host if needed)
                if deploy_to_host(host_ip, max_till, results, self.stop_event, self.logger):
                    host_success_count += 1

            # Save results to Excel
            self.excel_log = f'deployment_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
            pd.DataFrame(results).to_excel(self.excel_log, index=False)
            self.logger.info(f"Deployment complete. Detailed log: {self.log_filename}")
            self.logger.info(f"Summary Excel log saved to: {self.excel_log}")
            self.logger.info(f"Processed {host_success_count}/{len(df_config)} hosts successfully")

        except Exception as e:
            self.logger.error(f"Deployment failed: {str(e)}")
        finally:
            self.root.after(0, self.deployment_complete)

    def deployment_complete(self):
        self.is_deploying = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.stop()
        self.status_label.config(text="Deployment Complete" if not self.stop_event.is_set() else "Deployment Stopped")
        self.results_btn.config(state=tk.NORMAL)
        if not self.stop_event.is_set():
            messagebox.showinfo("Complete", "Deployment finished. Check log for details.")

    def open_results(self):
        if self.excel_log and os.path.exists(self.excel_log):
            os.startfile(self.excel_log)

def is_port_reachable(host, port, timeout, logger):
    """Check if the host's port is reachable within timeout."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            logger.debug(f"Port {port} on {host} is reachable")
            return True
        else:
            logger.warning(f"Port {port} on {host} is not reachable (error code: {result})")
            return False
    except socket.timeout:
        logger.error(f"Timeout while checking port {port} on {host}")
        return False
    except Exception as e:
        logger.error(f"Error checking port {port} on {host}: {str(e)}")
        return False

def connect_transport(host, username, password, timeout, port=22, logger=None):
    """Connect to SSH transport with timeout."""
    if logger is None:
        logger = logging.getLogger(__name__)
    logger.info(f"Attempting to connect to {host}:{port} as {username} (timeout: {timeout}s)")

    # Pre-check port reachability
    if not is_port_reachable(host, port, timeout, logger):
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

def upload_folder(sftp, local_dir, remote_dir, logger):
    """Recursively upload local folder contents to remote directory."""
    if not os.path.isdir(local_dir):
        raise Exception(f"Local folder not found: {local_dir}")

    try:
        sftp.mkdir(remote_dir)
        logger.info(f"Created remote directory: {remote_dir}")
    except IOError:
        logger.debug(f"Remote directory already exists: {remote_dir}")

    for item in os.listdir(local_dir):
        local_item = os.path.join(local_dir, item)
        remote_item = f"{remote_dir}/{item}"
        try:
            if os.path.isdir(local_item):
                upload_folder(sftp, local_item, remote_item, logger)
            else:
                sftp.put(local_item, remote_item)
                logger.debug(f"Uploaded file: {item}")
        except Exception as e:
            logger.error(f"Failed to upload {item}: {str(e)}")
            raise  # Re-raise to fail the whole operation

def copy_dir_between_sfpts(sftp_src, sftp_dest, src_dir, dst_dir, logger):
    """Recursively copy directory contents from one SFTP to another. Overwrites existing files; does not delete extras."""
    try:
        attrs = sftp_src.listdir_attr(src_dir)
    except Exception as e:
        logger.error(f"Cannot list source directory {src_dir}: {str(e)}")
        return

    try:
        sftp_dest.stat(dst_dir)
        logger.debug(f"Destination {dst_dir} exists")
    except FileNotFoundError:
        sftp_dest.mkdir(dst_dir)
        logger.info(f"Created destination directory: {dst_dir}")
    except Exception as e:
        logger.error(f"Cannot access/create destination {dst_dir}: {str(e)}")
        return

    for attr in attrs:
        if attr.filename.startswith('.'):
            continue  # Skip hidden files
        src_item = f"{src_dir}/{attr.filename}"
        dst_item = f"{dst_dir}/{attr.filename}"
        try:
            if S_ISDIR(attr.st_mode):
                copy_dir_between_sfpts(sftp_src, sftp_dest, src_item, dst_item, logger)
            else:
                # Stream copy without temp files; overwrites if exists
                with sftp_src.open(src_item, 'rb') as fr:
                    with sftp_dest.open(dst_item, 'wb') as fw:
                        shutil.copyfileobj(fr, fw)
                logger.debug(f"Copied {attr.filename}")
        except Exception as e:
            logger.error(f"Failed to copy {attr.filename}: {str(e)}")
            # Continue to next item

def delete_remote_folder(sftp, remote_dir, logger):
    """Recursively delete a remote directory and its contents."""
    try:
        attrs = sftp.listdir_attr(remote_dir)
    except Exception as e:
        logger.warning(f"Cannot list remote directory {remote_dir} for deletion: {str(e)}")
        return

    for attr in attrs:
        if attr.filename.startswith('.'):
            continue  # Skip hidden files
        item = f"{remote_dir}/{attr.filename}"
        try:
            if S_ISDIR(attr.st_mode):
                delete_remote_folder(sftp, item, logger)
            else:
                sftp.remove(item)
                logger.debug(f"Deleted file: {attr.filename}")
        except Exception as e:
            logger.error(f"Failed to delete {item}: {str(e)}")
            # Continue to next item

    try:
        sftp.rmdir(remote_dir)
        logger.info(f"Deleted directory: {remote_dir}")
    except Exception as e:
        logger.error(f"Failed to delete directory {remote_dir}: {str(e)}")

def deploy_to_host(host_ip, max_till, results, stop_event, logger):
    """Deploy to a single host and its tills, appending results."""
    # Compute network prefix for tills (first 3 octets of host_ip)
    prefix = '.'.join(host_ip.split('.')[:3])

    logger.info(f"Processing host {host_ip} with {max_till} tills (prefix: {prefix})")

    # Step 1: Copy folder from local to host
    logger.info(f"Step 1: Copying ETPStoreFrontV5.5 from local to host {host_ip}")
    if not os.path.exists(SOURCE_FOLDER):
        logger.error(f"Source folder not found: {SOURCE_FOLDER}")
        return False

    host_transport = connect_transport(host_ip, HOST_USER, HOST_PASS, TIMEOUT_CONNECT, logger=logger)
    if not host_transport:
        logger.error(f"Failed to connect to host {host_ip}. Skipping.")
        return False

    sftp_host = paramiko.SFTPClient.from_transport(host_transport)
    upload_success = False
    try:
        upload_folder(sftp_host, SOURCE_FOLDER, HOST_DEST, logger)
        logger.info(f"Step 1 completed: Folder uploaded to host {host_ip} successfully")
        upload_success = True
    except Exception as e:
        logger.error(f"Step 1 failed for host {host_ip}: {str(e)}")
    finally:
        sftp_host.close()

    if not upload_success:
        host_transport.close()
        return False

    # Keep host connection open for Step 2
    host_transport.set_keepalive(30)

    # Step 2: Distribute from host to tills
    logger.info(f"Step 2: Distributing from host {host_ip} to tills")
    sftp_host = paramiko.SFTPClient.from_transport(host_transport)
    till_success_count = 0
    try:
        for till_num in range(1, max_till + 1):
            if stop_event.is_set():
                logger.info(f"Stop signal received during till distribution for host {host_ip}")
                break

            till_octet = TILL_START_OCTET + till_num  # 111 + 1 = 112 for Till1
            till_ip = f"{prefix}.{till_octet}"
            logger.info(f"Processing Till{till_num} ({till_ip}) for host {host_ip}")

            till_transport = connect_transport(till_ip, TILL_USER, TILL_PASS, TIMEOUT_CONNECT, logger=logger)
            transfer_success = False
            if not till_transport:
                logger.warning(f"Till{till_num} ({till_ip}) is not in network")
                results.append({'HostIP': host_ip, 'TillIP': till_ip, 'Status': 'Failure'})
                continue

            # Set timeout on transport socket before creating SFTP
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
                copy_dir_between_sfpts(sftp_host, sftp_till, HOST_DEST, TILL_DEST_BASE, logger)
                logger.info(f"Transfer completed successfully for Till{till_num}")
                transfer_success = True
                till_success_count += 1

            except Exception as e:
                logger.error(f"Transfer failed for Till{till_num} ({till_ip}): {str(e)}")
            finally:
                sftp_till.close()
                if till_transport:
                    till_transport.close()

            status = 'Success' if transfer_success else 'Failure'
            results.append({'HostIP': host_ip, 'TillIP': till_ip, 'Status': status})
            logger.info(f"Status for Till{till_num} ({till_ip}): {status}")

    finally:
        sftp_host.close()
        host_transport.close()

    # Cleanup: Delete the folder on host after distribution
    if not stop_event.is_set():  # Only cleanup if not stopped mid-way
        logger.info(f"Step 3: Cleaning up folder on host {host_ip}")
        host_transport_cleanup = connect_transport(host_ip, HOST_USER, HOST_PASS, TIMEOUT_CONNECT, logger=logger)
        if host_transport_cleanup:
            sftp_cleanup = paramiko.SFTPClient.from_transport(host_transport_cleanup)
            try:
                delete_remote_folder(sftp_cleanup, HOST_DEST, logger)
                logger.info(f"Cleanup completed for host {host_ip}")
            except Exception as e:
                logger.error(f"Cleanup failed for host {host_ip}: {str(e)}")
            finally:
                sftp_cleanup.close()
                host_transport_cleanup.close()
        else:
            logger.warning(f"Could not reconnect to host {host_ip} for cleanup")

    logger.info(f"Host {host_ip} deployment complete: {till_success_count}/{max_till} tills successful")
    return True

if __name__ == "__main__":
    # Note: Run with Python 3.x. Install paramiko and pandas: pip install paramiko pandas openpyxl
    root = tk.Tk()
    app = DeploymentGUI(root)
    root.mainloop()