<?php
require_once '../config/config.php';

// Check if doctor is logged in
if (!isset($_SESSION['doctor_id'])) {
    http_response_code(403);
    echo '<div class="alert alert-danger"><i class="fas fa-lock me-2"></i>Access denied. Please log in.</div>';
    exit();
}

$doctor_id = $_SESSION['doctor_id'];
$patient_id = (int)($_GET['patient_id'] ?? 0);

if ($patient_id <= 0) {
    echo '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Invalid patient ID.</div>';
    exit();
}

try {
    // Get patient info
    $stmt = $pdo->prepare("SELECT name FROM patients WHERE id = ?");
    $stmt->execute([$patient_id]);
    $patient = $stmt->fetch();
    
    if (!$patient) {
        echo '<div class="alert alert-danger"><i class="fas fa-user-times me-2"></i>Patient not found.</div>';
        exit();
    }
    
    // Get medical records for this patient by this doctor
    $stmt = $pdo->prepare("
        SELECT mh.*, d.name as doctor_name
        FROM medical_history mh
        LEFT JOIN doctors d ON mh.doctor_id = d.id
        WHERE mh.patient_id = ? AND mh.doctor_id = ?
        ORDER BY mh.consultation_date DESC, mh.created_at DESC
    ");
    $stmt->execute([$patient_id, $doctor_id]);
    $records = $stmt->fetchAll();
    
    if (empty($records)) {
        echo '<div class="alert alert-info text-center py-4">';
        echo '<i class="fas fa-file-medical" style="font-size: 3rem; color: #ccc;"></i>';
        echo '<h5 class="mt-3 text-muted">No Medical Records</h5>';
        echo '<p class="text-muted">No medical records found for this patient. Add the first record to get started.</p>';
        echo '</div>';
    } else {
        foreach ($records as $record) {
            echo '<div class="medical-record">';
            echo '<div class="d-flex justify-content-between align-items-start mb-2">';
            echo '<div class="record-date">';
            echo '<i class="fas fa-calendar me-1"></i>' . formatDate($record['consultation_date']);
            if ($record['updated_at'] && $record['updated_at'] != $record['created_at']) {
                echo ' <small class="text-muted">(Updated: ' . formatDateTime($record['updated_at']) . ')</small>';
            }
            echo '</div>';
            echo '<button type="button" class="btn btn-outline-primary btn-sm" ';
            echo 'onclick="showEditModal(' . $record['id'] . ', \'' . addslashes($record['diagnosis']) . '\', \'' . addslashes($record['prescription']) . '\', \'' . addslashes($record['treatment_notes']) . '\')">'; 
            echo '<i class="fas fa-edit me-1"></i>Edit';
            echo '</button>';
            echo '</div>';
            
            echo '<div class="mb-2">';
            echo '<strong class="text-primary"><i class="fas fa-stethoscope me-1"></i>Diagnosis:</strong><br>';
            echo '<div class="ms-3">' . nl2br(htmlspecialchars($record['diagnosis'])) . '</div>';
            echo '</div>';
            
            if (!empty($record['prescription'])) {
                echo '<div class="mb-2">';
                echo '<strong class="text-success"><i class="fas fa-pills me-1"></i>Prescription:</strong><br>';
                echo '<div class="ms-3">' . nl2br(htmlspecialchars($record['prescription'])) . '</div>';
                echo '</div>';
            }
            
            if (!empty($record['treatment_notes'])) {
                echo '<div class="mb-2">';
                echo '<strong class="text-info"><i class="fas fa-sticky-note me-1"></i>Notes:</strong><br>';
                echo '<div class="ms-3">' . nl2br(htmlspecialchars($record['treatment_notes'])) . '</div>';
                echo '</div>';
            }
            
            echo '<div class="text-muted small">';
            echo '<i class="fas fa-user-md me-1"></i> ' . htmlspecialchars($record['doctor_name']);
            echo '</div>';
            
            echo '</div>';
        }
    }
    
} catch (PDOException $e) {
    echo '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Database error occurred while loading records.</div>';
}
?>