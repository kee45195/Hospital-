<?php
require_once 'config/config.php';

// Check if user is logged in
if (!isLoggedIn()) {
    header('Location: login.php');
    exit();
}

// Logout the user
logoutPatient();

// Set success message for login page
setFlashMessage('success', 'You have been successfully logged out.');

// Redirect to login page
header('Location: login.php');
exit();
?>