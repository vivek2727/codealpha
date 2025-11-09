import os
import logging
import shutil
import paramiko
import socket
from stat import S_ISDIR
from datetime import datetime

# Configuration - Adjust as needed
SOURCE_FOLDER = r'C:\Source\ETPStoreFrontV5.5'
HOST_IP = '10.13.0.23'
HOST_USER = 'linuxadmin'
HOST_PASS = 'St0re@dm1n'  # Confirmed as per your message
HOST_DEST = '/home/linuxadmin/ETPStoreFrontV5.5'
TILL_USER = 'posuser'
TILL_PASS = 'till@123'
TILL_DEST_BASE = '/home/posuser/ETPSuite'
MAX_TILL = 20  # Assumption: Up to Till20; adjust based on your max till number
TIMEOUT_CONNECT = 3  # Seconds for connection attempts
TIMEOUT_TRANSFER = 6  # Approximate for transfer operations (paramiko timeouts)

# Setup logging: Logs to file and console
log_filename = f'deployment_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def connect_transport(host, username, password, timeout):
    """Connect to SSH transport with timeout."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        transport = paramiko.Transport(sock)
        transport.connect(username=username, password=password)
        transport.set_keepalive(30)  # Keep connection alive
        logger.debug(f"Successfully connected to {host} as {username}")
        return transport
    except socket.timeout:
        logger.error(f"Connection to {host} timed out after {timeout} seconds")
        return None
    except Exception as e:
        logger.error(f"Failed to connect to {host} as {username}: {str(e)}")
        if 'transport' in locals():
            transport.close()
        return None

def upload_folder(sftp, local_dir, remote_dir):
    """Recursively upload local folder contents to remote directory."""
    if not os.path.isdir(local_dir):
        raise Exception(f"Local folder not found: {local_dir}")

    try:
        sftp.mkdir(remote_dir)
    except IOError:
        pass  # Directory already exists

    for item in os.listdir(local_dir):
        local_item = os.path.join(local_dir, item)
        remote_item = f"{remote_dir}/{item}"
        try:
            if os.path.isdir(local_item):
                upload_folder(sftp, local_item, remote_item)
            else:
                sftp.put(local_item, remote_item)
                logger.debug(f"Uploaded file: {item}")
        except Exception as e:
            logger.error(f"Failed to upload {item}: {str(e)}")
            raise  # Re-raise to fail the whole operation

def copy_dir_between_sfpts(sftp_src, sftp_dest, src_dir, dst_dir):
    """Recursively copy directory contents from one SFTP to another."""
    try:
        attrs = sftp_src.listdir_attr(src_dir)
    except Exception as e:
        logger.error(f"Cannot list source directory {src_dir}: {str(e)}")
        return

    try:
        sftp_dest.stat(dst_dir)
    except FileNotFoundError:
        sftp_dest.mkdir(dst_dir)
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
                copy_dir_between_sfpts(sftp_src, sftp_dest, src_item, dst_item)
            else:
                # Stream copy without temp files
                with sftp_src.open(src_item, 'rb') as fr:
                    with sftp_dest.open(dst_item, 'wb') as fw:
                        shutil.copyfileobj(fr, fw)
                logger.debug(f"Copied {attr.filename}")
        except Exception as e:
            logger.error(f"Failed to copy {attr.filename}: {str(e)}")
            # Continue to next item

def main():
    logger.info("Starting deployment script")

    # Step 1: Copy folder from local Windows to host
    logger.info("Step 1: Copying ETPStoreFrontV5.5 from local to host")
    if not os.path.exists(SOURCE_FOLDER):
        logger.error(f"Source folder not found: {SOURCE_FOLDER}")
        return

    host_transport = connect_transport(HOST_IP, HOST_USER, HOST_PASS, TIMEOUT_CONNECT)
    if not host_transport:
        logger.error("Failed to connect to host. Aborting.")
        return

    sftp_host = paramiko.SFTPClient.from_transport(host_transport)
    try:
        upload_folder(sftp_host, SOURCE_FOLDER, HOST_DEST)
        logger.info("Step 1 completed: Folder uploaded to host successfully")
    except Exception as e:
        logger.error(f"Step 1 failed: {str(e)}")
        sftp_host.close()
        host_transport.close()
        return
    finally:
        sftp_host.close()

    # Step 2: Distribute from host to tills (contents of HOST_DEST to TILL_DEST_BASE on each till)
    logger.info("Step 2: Distributing from host to tills")
    sftp_host = paramiko.SFTPClient.from_transport(host_transport)  # Re-open for distribution
    try:
        for till_num in range(1, MAX_TILL + 1):
            till_ip = f"10.13.0.{34 + till_num}"
            logger.info(f"Processing Till{till_num} ({till_ip})")

            till_transport = connect_transport(till_ip, TILL_USER, TILL_PASS, TIMEOUT_CONNECT)
            if not till_transport:
                logger.warning(f"Till{till_num} ({till_ip}) is not in network")
                continue

            sftp_till = paramiko.SFTPClient.from_transport(till_transport)
            transfer_success = False
            try:
                # Check/create ETPSuite
                try:
                    sftp_till.stat(TILL_DEST_BASE)
                    logger.info(f"ETPSuite exists on Till{till_num}")
                except FileNotFoundError:
                    sftp_till.mkdir(TILL_DEST_BASE)
                    logger.info(f"Created ETPSuite on Till{till_num}")
                except PermissionError:
                    raise Exception("Rights to create/access ETPSuite not present")
                except Exception as e:
                    raise Exception(f"Cannot access ETPSuite: {str(e)}")

                # Copy contents (with 6s timeout approximation via transport)
                till_transport.sock.settimeout(TIMEOUT_TRANSFER)
                copy_dir_between_sfpts(sftp_host, sftp_till, HOST_DEST, TILL_DEST_BASE)
                logger.info(f"Transfer completed successfully for Till{till_num}")
                transfer_success = True

            except Exception as e:
                logger.error(f"Transfer failed for Till{till_num} ({till_ip}): {str(e)}")
            finally:
                sftp_till.close()
                if till_transport:
                    till_transport.close()

            if not transfer_success:
                logger.warning(f"Status for Till{till_num}: Failed (proceeding to next)")

    finally:
        sftp_host.close()
        host_transport.close()

    logger.info(f"Deployment complete. Log saved to: {log_filename}")

if __name__ == "__main__":
    # Note: Run with Python 3.x. Install paramiko: pip install paramiko
    main()