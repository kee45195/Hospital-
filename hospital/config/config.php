<?php
// Main configuration file for Hospital Management System

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Timezone
date_default_timezone_set('America/New_York');

// Application constants
define('APP_NAME', 'MediCare Hospital');
define('APP_VERSION', '1.0.0');
define('BASE_URL', '/Hospital');
define('UPLOAD_PATH', __DIR__ . '/../uploads/');
define('MAX_FILE_SIZE', 5 * 1024 * 1024); // 5MB

// Include configuration files
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/session.php';
require_once __DIR__ . '/functions.php';

// Hospital color palette
define('COLOR_PRIMARY', '#009688');     // Teal
define('COLOR_SECONDARY', '#8BC34A');   // Light Green
define('COLOR_ACCENT', '#F06292');      // Soft Pink
define('COLOR_BACKGROUND', '#F5F5F5');  // Light Gray
define('COLOR_TEXT', '#212121');        // Charcoal

// Medical specializations
function getMedicalSpecializations() {
    return [
        'Cardiology' => 'Heart and cardiovascular system',
        'Dermatology' => 'Skin, hair, and nails',
        'Endocrinology' => 'Hormones and metabolism',
        'Gastroenterology' => 'Digestive system',
        'General Medicine' => 'Primary healthcare',
        'Gynecology' => 'Women\'s reproductive health',
        'Neurology' => 'Nervous system',
        'Oncology' => 'Cancer treatment',
        'Orthopedics' => 'Bones, joints, and muscles',
        'Pediatrics' => 'Children\'s healthcare',
        'Psychiatry' => 'Mental health',
        'Pulmonology' => 'Respiratory system',
        'Radiology' => 'Medical imaging',
        'Urology' => 'Urinary system'
    ];
}

// Appointment statuses
function getAppointmentStatuses() {
    return [
        'Pending' => 'Waiting for confirmation',
        'Confirmed' => 'Appointment confirmed',
        'Completed' => 'Consultation completed',
        'Cancelled' => 'Appointment cancelled'
    ];
}

// Gender options
function getGenderOptions() {
    return ['Male', 'Female', 'Other'];
}

// Working hours options
function getWorkingHoursOptions() {
    return [
        '7:00 AM - 3:00 PM' => 'Morning Shift',
        '8:00 AM - 4:00 PM' => 'Regular Morning',
        '9:00 AM - 5:00 PM' => 'Standard Hours',
        '10:00 AM - 6:00 PM' => 'Late Morning',
        '8:00 AM - 6:00 PM' => 'Extended Hours'
    ];
}

// Working days options
function getWorkingDaysOptions() {
    return [
        'Monday-Friday' => 'Weekdays Only',
        'Monday-Saturday' => 'Monday to Saturday',
        'Tuesday-Saturday' => 'Tuesday to Saturday',
        'Monday-Thursday' => 'Monday to Thursday',
        'Monday,Wednesday,Friday' => 'Alternate Days'
    ];
}

// Create uploads directory if it doesn't exist
if (!file_exists(UPLOAD_PATH)) {
    mkdir(UPLOAD_PATH, 0755, true);
}

// Create subdirectories for uploads
$upload_subdirs = ['profiles', 'documents', 'temp'];
foreach ($upload_subdirs as $subdir) {
    $path = UPLOAD_PATH . $subdir . '/';
    if (!file_exists($path)) {
        mkdir($path, 0755, true);
    }
}
?>