# SMTP Scanner v2.0 - Enhanced Email Notification Version

A powerful, multi-threaded SMTP authentication scanner that tests SMTP servers on multiple ports and automatically sends all working authenticated SMTP credentials to a specified receiver email address.

## Features

- **Multi-port scanning**: Tests ports 25, 465, 587, and 2525
- **Multi-threaded**: Configurable thread count for fast scanning
- **Automatic email notifications**: Sends working SMTP credentials to receiver email
- **Multiple output formats**: TXT, CSV, and JSON formats
- **Real-time progress updates**: Shows scan progress and found credentials
- **Batch notifications**: Sends updates every 5 working SMTPs found
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

1. **Initialize the scanner** (creates sample files and email configuration):
```bash
python3 smtp_scanner.py a
```

2. **Configure email settings** in `email_config.json`:
```json
{
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email": "your_sender@gmail.com",
    "password": "your_app_password",
    "recipient": "receiver@gmail.com",
    "use_ssl": false
}
```

3. **Add target IPs** to `ips.txt`:
```
192.168.1.100
mail.example.com
smtp.company.com
```

4. **Run the scanner**:
```bash
python3 smtp_scanner.py 10 1 1
```

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

## Configuration Files

### email_config.json
Configure your email settings for receiving scan results:

```json
{
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email": "your_sender@gmail.com",
    "password": "your_app_password_here",
    "recipient": "receiver@gmail.com",
    "use_ssl": false,
    "_instructions": {
        "smtp_server": "SMTP server address (e.g., smtp.gmail.com, smtp.outlook.com)",
        "smtp_port": "SMTP port (587 for TLS, 465 for SSL, 25 for plain)",
        "email": "Your sender email address",
        "password": "Your email password or app-specific password",
        "recipient": "Email address to receive the scan results",
        "use_ssl": "Set to true for port 465 (SSL), false for others"
    }
}
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