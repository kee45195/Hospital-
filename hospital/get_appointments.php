<?php
session_start();
require_once 'config/database.php';

// Check if user is logged in and is a patient
if (!isset($_SESSION['patient_id']) || empty($_SESSION['patient_id'])) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

$patient_id = $_SESSION['patient_id'];
$doctor_id = isset($_GET['doctor_id']) ? (int)$_GET['doctor_id'] : 0;

if ($doctor_id <= 0) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid doctor ID']);
    exit();
}

try {
    // Get completed appointments for the patient with the selected doctor
    $stmt = $pdo->prepare("
        SELECT id, appointment_date, appointment_time 
        FROM appointments 
        WHERE patient_id = ? AND doctor_id = ? AND status = 'Confirmed'
        ORDER BY appointment_date DESC, appointment_time DESC
    ");
    
    $stmt->execute([$patient_id, $doctor_id]);
    $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    // Format the appointments for better display
    foreach ($appointments as &$appointment) {
        $appointment['appointment_date'] = date('M d, Y', strtotime($appointment['appointment_date']));
        $appointment['appointment_time'] = date('g:i A', strtotime($appointment['appointment_time']));
    }
    
    header('Content-Type: application/json');
    echo json_encode($appointments);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error']);
}
?>