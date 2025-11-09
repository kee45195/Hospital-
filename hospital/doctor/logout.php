<?php
require_once '../config/config.php';

// Check if doctor is logged in
if (!isset($_SESSION['doctor_id'])) {
    header('Location: login.php');
    exit();
}

// Clear all doctor session variables
unset($_SESSION['doctor_id']);
unset($_SESSION['doctor_name']);
unset($_SESSION['doctor_email']);
unset($_SESSION['doctor_specialization']);
unset($_SESSION['user_type']);

// Clear remember me cookie if it exists
if (isset($_COOKIE['doctor_remember_token'])) {
    setcookie('doctor_remember_token', '', time() - 3600, '/', '', true, true);
}

// Destroy the session
session_destroy();

// Start a new session for the logout message
session_start();
$_SESSION['logout_message'] = 'You have been successfully logged out.';

// Redirect to login page
header('Location: login.php');
exit();
?>