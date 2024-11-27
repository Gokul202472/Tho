import os
import time
import psutil
import hashlib

# Path to monitor for unauthorized file changes
MONITOR_PATH = "C:/important_folder"

# Log file to store detected issues
LOG_FILE = "anti_hacking_log.txt"

# Initial hash values of files in the folder
file_hashes = {}

def log_event(event):
    """Logs an event to the log file."""
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.ctime()}: {event}\n")

def monitor_files():
    """Monitor file changes in the specified folder."""
    global file_hashes
    for root, _, files in os.walk(MONITOR_PATH):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "rb") as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                if file_path not in file_hashes:
                    file_hashes[file_path] = file_hash
                elif file_hashes[file_path] != file_hash:
                    log_event(f"File modified: {file_path}")
                    file_hashes[file_path] = file_hash
            except Exception as e:
                log_event(f"Error reading file {file_path}: {e}")

def monitor_processes():
    """Monitor running processes for suspicious activity."""
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username']):
        try:
            process_info = proc.info
            if process_info['name'] == "unknown_process":  # Example suspicious process
                log_event(f"Suspicious process detected: {process_info}")
        except Exception as e:
            log_event(f"Error monitoring process: {e}")

def monitor_failed_logins():
    """Monitor failed login attempts (example for Linux systems)."""
    try:
        with open("/var/log/auth.log", "r") as log:
            lines = log.readlines()
            for line in lines[-10:]:  # Check the last 10 lines
                if "Failed password" in line:
                    log_event(f"Failed login attempt detected: {line.strip()}")
    except FileNotFoundError:
        log_event("Login monitoring not supported on this system.")

def main():
    """Main function to run monitoring tasks."""
    print("Anti-Hacking Monitoring started. Logging to:", LOG_FILE)
    log_event("Monitoring started.")

    while True:
        try:
            monitor_files()
            monitor_processes()
            monitor_failed_logins()
            time.sleep(10)  # Monitor every 10 seconds
        except KeyboardInterrupt:
            log_event("Monitoring stopped.")
            print("Monitoring stopped.")
            break

if __name__ == "__main__":
    main()
