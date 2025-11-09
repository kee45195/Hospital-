<?php
// Common functions for Hospital Management System

// Sanitize input data
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// Validate email format
function isValidEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

// Hash password
function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

// Verify password
function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Format date for display
function formatDate($date, $format = 'M d, Y') {
    return date($format, strtotime($date));
}

// Format time for display
function formatTime($time, $format = 'g:i A') {
    return date($format, strtotime($time));
}

// Format datetime for display
function formatDateTime($datetime, $format = 'M d, Y g:i A') {
    return date($format, strtotime($datetime));
}

// Get age from date of birth
function calculateAge($birthdate) {
    $today = new DateTime();
    $birth = new DateTime($birthdate);
    return $today->diff($birth)->y;
}

// Generate random appointment time slots
function generateTimeSlots($start_time = '09:00', $end_time = '17:00', $interval = 30) {
    $slots = [];
    $start = new DateTime($start_time);
    $end = new DateTime($end_time);
    $interval = new DateInterval('PT' . $interval . 'M');
    
    while ($start < $end) {
        $slots[] = $start->format('H:i');
        $start->add($interval);
    }
    
    return $slots;
}

// Check if appointment slot is available
function isSlotAvailable($pdo, $doctor_id, $date, $time) {
    $stmt = $pdo->prepare("
        SELECT COUNT(*) FROM appointments 
        WHERE doctor_id = ? AND appointment_date = ? AND appointment_time = ? 
        AND status != 'Cancelled'
    ");
    $stmt->execute([$doctor_id, $date, $time]);
    return $stmt->fetchColumn() == 0;
}

// Get appointment status badge class
function getStatusBadgeClass($status) {
    switch (strtolower($status)) {
        case 'pending':
            return 'badge-warning';
        case 'confirmed':
            return 'badge-success';
        case 'completed':
            return 'badge-info';
        case 'cancelled':
            return 'badge-danger';
        default:
            return 'badge-secondary';
    }
}

// Validate phone number (basic validation)
function isValidPhone($phone) {
    return preg_match('/^[\+]?[1-9][\d]{0,15}$/', $phone);
}

// Generate unique filename for uploads
function generateUniqueFilename($original_filename) {
    $extension = pathinfo($original_filename, PATHINFO_EXTENSION);
    return uniqid() . '_' . time() . '.' . $extension;
}

// Get file extension
function getFileExtension($filename) {
    return strtolower(pathinfo($filename, PATHINFO_EXTENSION));
}

// Check if file is image
function isImageFile($filename) {
    $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    return in_array(getFileExtension($filename), $allowed_extensions);
}

// Truncate text
function truncateText($text, $length = 100, $suffix = '...') {
    if (strlen($text) <= $length) {
        return $text;
    }
    return substr($text, 0, $length) . $suffix;
}

// Get days of week array
function getDaysOfWeek() {
    return [
        'Monday', 'Tuesday', 'Wednesday', 'Thursday', 
        'Friday', 'Saturday', 'Sunday'
    ];
}

// Parse working days string
function parseWorkingDays($working_days) {
    if (strpos($working_days, '-') !== false) {
        // Range format like "Monday-Friday"
        $parts = explode('-', $working_days);
        $days = getDaysOfWeek();
        $start_index = array_search(trim($parts[0]), $days);
        $end_index = array_search(trim($parts[1]), $days);
        
        if ($start_index !== false && $end_index !== false) {
            return array_slice($days, $start_index, $end_index - $start_index + 1);
        }
    } else {
        // Comma-separated format like "Monday,Wednesday,Friday"
        return array_map('trim', explode(',', $working_days));
    }
    
    return [];
}

// Check if doctor is available on specific day
function isDoctorAvailableOnDay($working_days, $day) {
    $available_days = parseWorkingDays($working_days);
    return in_array($day, $available_days);
}

// Get next available dates for a doctor
function getNextAvailableDates($working_days, $days_ahead = 30) {
    $available_dates = [];
    $available_days = parseWorkingDays($working_days);
    
    for ($i = 1; $i <= $days_ahead; $i++) {
        $date = date('Y-m-d', strtotime("+$i days"));
        $day_name = date('l', strtotime($date));
        
        if (in_array($day_name, $available_days)) {
            $available_dates[] = $date;
        }
    }
    
    return $available_dates;
}
?>