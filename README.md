# SMTP Scanner

A comprehensive Python-based SMTP scanner that tests authentication on multiple SMTP servers and ports, then sends results via email.

## Features

- **Multi-threaded scanning** for fast performance
- **Multiple SMTP ports support**: 25, 465, 587, 2525
- **Authentication testing** with username/password combinations
- **Email notifications** with scan results
- **Detailed logging** with verbose and debug modes
- **SSL/TLS support** for secure connections
- **Server information gathering** (welcome messages, features)
- **Results export** to text and JSON formats

## Installation

No additional packages required - uses only Python standard library modules:
- `socket`, `sys`, `base64`, `queue`, `threading`
- `smtplib`, `ssl`, `time`, `json`
- `email` (MIMEText, MIMEMultipart, MIMEBase, encoders)
- `os`, `random`

## Usage

### 1. Create Input Files

First, create the necessary input files:

```bash
python3 smtp_scanner.py a
```

This creates:
- `ips.txt` - Target IP addresses/hostnames
- `users.txt` - Usernames to test
- `pass.txt` - Passwords to test
- `email_config.json` - Email configuration template

### 2. Configure Files

**ips.txt** - Add target SMTP servers:
```
mail.example.com
192.168.1.100
smtp.company.com
```

**users.txt** - Add usernames to test:
```
admin
user
test
mail
smtp
postmaster
```

**pass.txt** - Add passwords to test:
```
password
123456
admin
pass
test

mail
```

**email_config.json** - Configure email notifications:
```json
{
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "email": "your_email@gmail.com",
    "password": "your_app_password",
    "recipient": "recipient@gmail.com"
}
```

### 3. Run Scanner

Basic usage:
```bash
python3 smtp_scanner.py <threads> [verbose] [debug]
```

Examples:
```bash
# Run with 10 threads
python3 smtp_scanner.py 10

# Run with 20 threads, verbose output
python3 smtp_scanner.py 20 1

# Run with 15 threads, verbose and debug output
python3 smtp_scanner.py 15 1 1
```

Parameters:
- `threads`: Number of concurrent threads (recommended: 10-50)
- `verbose`: Show scanning progress (1 = on, 0 = off)
- `debug`: Show detailed debug information (1 = on, 0 = off)

## SMTP Ports Scanned

The scanner automatically tests these common SMTP ports:
- **Port 25**: Standard SMTP (usually unencrypted)
- **Port 465**: SMTP over SSL (SMTPS)
- **Port 587**: SMTP with STARTTLS (submission port)
- **Port 2525**: Alternative SMTP port

## Output Files

### working_smtps.txt
Simple format with working credentials:
```
admin:password@mail.example.com:587
user:123456@192.168.1.100:465
```

### working_smtps_detailed.json
Detailed information in JSON format:
```json
{"host": "mail.example.com", "port": 587, "username": "admin", "password": "password", "welcome": "220 mail.example.com ESMTP", "features": "250-mail.example.com\n250-PIPELINING\n250-SIZE 35882577\n250-STARTTLS", "timestamp": "2024-01-15 10:30:45"}
```

## Email Notifications

When working SMTP servers are found, the scanner can automatically send results via email including:
- Summary of scan results
- List of working SMTP servers with credentials
- Detailed JSON file as attachment
- Timestamp and server information

## Security Notes

⚠️ **Important Security Considerations:**

1. **Legal Use Only**: Only scan SMTP servers you own or have explicit permission to test
2. **Credential Security**: Store credentials securely and delete result files after use
3. **Network Impact**: Use reasonable thread counts to avoid overwhelming target servers
4. **Email Security**: Use app passwords for Gmail, not your main password

## Advanced Features

### Custom Port Scanning
Modify the `smtp_ports` list in the code to scan additional ports:
```python
self.smtp_ports = [25, 465, 587, 2525, 8025, 8587]
```

### Timeout Configuration
Adjust connection timeouts in the code:
- `test_smtp_connection()`: Default 10 seconds
- `test_smtp_auth()`: Default 15 seconds
- `get_smtp_info()`: Default 10 seconds

### Threading Optimization
- **Low-end systems**: 5-10 threads
- **Standard systems**: 10-20 threads
- **High-end systems**: 20-50 threads
- **Servers**: 50+ threads (monitor system resources)

## Troubleshooting

### Common Issues

1. **No results found**:
   - Check if target servers are reachable
   - Verify username/password combinations
   - Try different ports

2. **Email sending fails**:
   - Check email configuration in `email_config.json`
   - Use app passwords for Gmail
   - Verify SMTP server settings

3. **Connection timeouts**:
   - Reduce thread count
   - Increase timeout values in code
   - Check network connectivity

4. **Permission errors**:
   - Run with appropriate permissions
   - Check file write permissions
   - Ensure network access is allowed

### Debug Mode

Enable debug mode for detailed troubleshooting:
```bash
python3 smtp_scanner.py 10 1 1
```

This shows:
- Connection attempts
- Authentication failures
- Server responses
- Error details

## Example Session

```bash
$ python3 smtp_scanner.py a
[INFO] Created sample ips.txt file
[INFO] Created sample users.txt file  
[INFO] Created sample pass.txt file
[INFO] Created email_config.json template. Please configure your email settings.

$ python3 smtp_scanner.py 10 1 0
[INFO] Starting SMTP scanner with 10 threads
[INFO] Loaded 5 IPs, 7 users, 8 passwords
[INFO] Total combinations to test: 1120
[SCAN] Testing admin@mail.example.com:587
[SUCCESS] Working SMTP found: admin@password123@mail.example.com:587
[SCAN] Testing user@192.168.1.100:465
[SUCCESS] Working SMTP found: user@test@192.168.1.100:465

[INFO] Scan completed. Found 2 working SMTP servers
[SUCCESS] Results emailed to recipient@gmail.com
```

## License

This tool is for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations.