<?php
// Session management for Hospital Management System

// Session configuration (must be set before session_start)
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 0); // Set to 1 if using HTTPS

// Start session if not already started
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Check if user is logged in
function isLoggedIn() {
    return isset($_SESSION['patient_id']) && !empty($_SESSION['patient_id']);
}

// Get current patient ID
function getCurrentPatientId() {
    return isset($_SESSION['patient_id']) ? $_SESSION['patient_id'] : null;
}

// Get current patient data
function getCurrentPatient() {
    if (!isLoggedIn()) {
        return null;
    }
    
    return [
        'id' => $_SESSION['patient_id'],
        'name' => $_SESSION['patient_name'] ?? '',
        'email' => $_SESSION['patient_email'] ?? ''
    ];
}

// Login user
function loginPatient($patient) {
    $_SESSION['patient_id'] = $patient['id'];
    $_SESSION['patient_name'] = $patient['name'];
    $_SESSION['patient_email'] = $patient['email'];
    
    // Regenerate session ID for security
    session_regenerate_id(true);
}

// Logout user
function logoutPatient() {
    // Unset all session variables
    $_SESSION = [];
    
    // Destroy the session cookie
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    // Destroy the session
    session_destroy();
}

// Redirect to login if not authenticated
function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: /Hospital/login.php');
        exit();
    }
}

// Redirect to dashboard if already logged in
function redirectIfLoggedIn() {
    if (isLoggedIn()) {
        header('Location: /Hospital/dashboard.php');
        exit();
    }
}

// Set flash message
function setFlashMessage($type, $message) {
    $_SESSION['flash_message'] = [
        'type' => $type, // success, error, warning, info
        'message' => $message
    ];
}

// Get and clear flash message
function getFlashMessage() {
    if (isset($_SESSION['flash_message'])) {
        $message = $_SESSION['flash_message'];
        unset($_SESSION['flash_message']);
        return $message;
    }
    return null;
}

// CSRF Token functions
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}
?>