import os
import subprocess
import logging
import shutil

# Logging configs
logging.basicConfig(
    filename='security_hardening.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def execute_command(command):
    """Executes shell command and logs output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"SUCCESS: {command} - {result.stdout}")
        else:
            logging.error(f"ERROR: {command} - {result.stderr}")
    except Exception as e:
        logging.error(f"EXCEPTION: {command} - {str(e)}")

def check_root_privileges():
    """Makes sure script runs with root privileges."""
    if os.geteuid() != 0:
        logging.error("ERROR: This script must be run as root! Exiting.")
        exit(1)

def backup_configs():
    """Backs up configuration files before making changes."""
    logging.info("Backing up important configuration files...")
    config_files = [
        '/etc/ssh/sshd_config', 
        '/etc/login.defs',
        '/etc/ufw/before.rules'
    ]
    backup_dir = '/root/security_hardening_backups'
    os.makedirs(backup_dir, exist_ok=True)
    
    for file in config_files:
        if os.path.exists(file):
            shutil.copy(file, os.path.join(backup_dir, os.path.basename(file) + '.bak'))
            logging.info(f"Backup created: {file} -> {backup_dir}")

def disable_root_login():
    """Disables root login over SSH."""
    logging.info("Disabling root login over SSH...")
    execute_command("sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config")
    execute_command("systemctl restart sshd")

def enforce_password_policies():
    """Enforces strong password policies."""
    logging.info("Enforcing strong password policies...")
    execute_command("sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs")
    execute_command("sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs")
    execute_command("sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs")

def configure_firewall():
    """Configures strict firewall policy."""
    logging.info("Configuring firewall settings...")
    execute_command("ufw default deny incoming")
    execute_command("ufw default allow outgoing")
    execute_command("ufw allow ssh")
    execute_command("ufw allow http")
    execute_command("ufw allow https")
    execute_command("ufw enable")

def disable_unused_services():
    """Disables unused and insecure services."""
    logging.info("Disabling unused services...")
    services = ['telnet', 'ftp', 'nfs', 'rsh', 'rexec', 'smb', 'rpcbind']
    for service in services:
        execute_command(f"systemctl disable {service}")
        execute_command(f"systemctl stop {service}")

def apply_system_updates():
    """Applies all pending system updates."""
    logging.info("Applying system updates...")
    execute_command("apt update && apt upgrade -y")
    execute_command("apt autoremove -y")

def enable_audit_logs():
    """Enables security auditing and logs system events."""
    logging.info("Enabling audit logs...")
    execute_command("auditctl -e 1")
    execute_command("cat /var/log/auth.log | grep 'Failed password'")

def configure_fail2ban():
    """Installs and configures Fail2Ban for brute-force attack protection."""
    logging.info("Installing and configuring Fail2Ban...")
    execute_command("apt install fail2ban -y")
    execute_command("systemctl enable fail2ban")
    execute_command("systemctl restart fail2ban")

def restrict_sudo_access():
    """Restricts sudo access to authorized users only."""
    logging.info("Restricting sudo access...")
    execute_command("echo 'Defaults logfile=/var/log/sudo.log' >> /etc/sudoers")
    execute_command("sed -i 's/^%sudo.*/# %sudo/' /etc/sudoers")

def disable_usb_storage():
    """Prevents unauthorized USB storage device usage."""
    logging.info("Disabling USB storage...")
    execute_command("echo 'blacklist usb-storage' > /etc/modprobe.d/usb-storage.conf")
    execute_command("update-initramfs -u")

def enforce_secure_kernel_parameters():
    """Enhances system security by modifying kernel parameters."""
    logging.info("Applying secure kernel parameters...")
    with open('/etc/sysctl.conf', 'a') as sysctl:
        sysctl.write('\n# Security Hardening\n')
        sysctl.write('net.ipv4.conf.all.rp_filter=1\n')
        sysctl.write('net.ipv4.conf.default.rp_filter=1\n')
        sysctl.write('net.ipv4.tcp_syncookies=1\n')
    execute_command("sysctl -p")

def main():
    check_root_privileges()
    logging.info("Starting system hardening...")
    backup_configs()
    disable_root_login()
    enforce_password_policies()
    configure_firewall()
    disable_unused_services()
    apply_system_updates()
    enable_audit_logs()
    configure_fail2ban()
    restrict_sudo_access()
    disable_usb_storage()
    enforce_secure_kernel_parameters()
    logging.info("Process completed.")

if __name__ == "__main__":
    main()
