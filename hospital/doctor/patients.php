<?php
require_once '../config/config.php';

// Check if doctor is logged in
if (!isset($_SESSION['doctor_id'])) {
    header('Location: login.php');
    exit();
}

$doctor_id   = $_SESSION['doctor_id'];
$doctor_name = $_SESSION['doctor_name'];
$success_message = '';
$error_message   = '';

// Handle medical record actions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        try {
            if ($action == 'add_medical_record') {
                $patient_id   = (int)($_POST['patient_id'] ?? 0);
                $diagnosis    = trim($_POST['diagnosis'] ?? '');
                $prescription = trim($_POST['prescription'] ?? '');
                $notes        = trim($_POST['notes'] ?? '');

                if (empty($diagnosis)) {
                    $error_message = 'Diagnosis is required.';
                } else {
                    $stmt = $pdo->prepare("
                        INSERT INTO medical_history (patient_id, doctor_id, diagnosis, prescription, treatment_notes, consultation_date) 
                        VALUES (?, ?, ?, ?, ?, CURDATE())
                    ");
                    $stmt->execute([$patient_id, $doctor_id, $diagnosis, $prescription, $notes]);
                    $success_message = 'Medical record added successfully.';
                }

            } elseif ($action == 'update_medical_record') {
                $record_id    = (int)($_POST['record_id'] ?? 0);
                $diagnosis    = trim($_POST['diagnosis'] ?? '');
                $prescription = trim($_POST['prescription'] ?? '');
                $notes        = trim($_POST['notes'] ?? '');

                if (empty($diagnosis)) {
                    $error_message = 'Diagnosis is required.';
                } else {
                    $stmt = $pdo->prepare("
                        UPDATE medical_history 
                           SET diagnosis = ?, prescription = ?, treatment_notes = ?, updated_at = NOW()
                         WHERE id = ? AND doctor_id = ?
                    ");
                    $stmt->execute([$diagnosis, $prescription, $notes, $record_id, $doctor_id]);
                    $success_message = 'Medical record updated successfully.';
                }
            }
        } catch (PDOException $e) {
            $error_message = 'Database error occurred. Please try again.';
        }
    }
}

// Filters & pagination
$search      = $_GET['search'] ?? '';
$filter_date = $_GET['filter_date'] ?? '';
$page        = max(1, (int)($_GET['page'] ?? 1));
$per_page    = 10;
$offset      = ($page - 1) * $per_page;

// Build WHERE conditions (for INNER JOIN results only)
$where = ["a.doctor_id = ?"];
$params = [$doctor_id];

// Search by patient fields
if ($search !== '') {
    $where[] = "(p.name LIKE ? OR p.email LIKE ? OR p.phone LIKE ?)";
    $term = '%'.$search.'%';
    $params[] = $term; $params[] = $term; $params[] = $term;
}

// Filter by appointment date
if ($filter_date !== '') {
    $where[] = "a.appointment_date = ?";
    $params[] = $filter_date;
}

$where_sql = implode(' AND ', $where);

// Fetch patients who actually have appointments with this doctor
$patients = [];
$total_patients = 0;
$total_pages = 0;

try {
    // Main list (distinct patients w/ stats, only those with at least one appointment with this doctor)
    $sql = "
        SELECT 
            p.id,
            p.name,
            p.email,
            p.phone,
            p.date_of_birth,
            p.gender,
            p.address,
            COUNT(DISTINCT a.id) AS total_appointments,
            COUNT(DISTINCT mh.id) AS total_records,
            MAX(CONCAT(a.appointment_date, ' ', a.appointment_time)) AS last_appointment_dt
        FROM patients p
        INNER JOIN appointments a 
            ON a.patient_id = p.id
        LEFT JOIN medical_history mh
            ON mh.patient_id = p.id AND mh.doctor_id = ?
        WHERE $where_sql
        GROUP BY p.id, p.name, p.email, p.phone, p.date_of_birth, p.gender, p.address
        ORDER BY last_appointment_dt DESC
        LIMIT ? OFFSET ?
    ";

    // params order: mh.doctor_id, ...filters..., limit, offset
    $list_params = array_merge([$doctor_id], $params, [$per_page, $offset]);
    $stmt = $pdo->prepare($sql);
    $stmt->execute($list_params);
    $patients = $stmt->fetchAll();

    // Count distinct patients for pagination (same filters)
    $count_sql = "
        SELECT COUNT(*) AS cnt FROM (
            SELECT DISTINCT p.id
            FROM patients p
            INNER JOIN appointments a 
                ON a.patient_id = p.id
            WHERE $where_sql
        ) AS sub
    ";
    $count_stmt = $pdo->prepare($count_sql);
    $count_stmt->execute($params); // same params as $where_sql
    $total_patients = (int)$count_stmt->fetchColumn();
    $total_pages = (int)ceil($total_patients / $per_page);

} catch (PDOException $e) {
    $error_message = 'Database error occurred: ' . $e->getMessage();
    $patients = [];
    $total_patients = 0;
    $total_pages = 0;
}

$csrf_token = generateCSRFToken();

function h($v){ return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patient Care - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: #00838F;
            --secondary-color: #A5D6A7;
            --accent-color: #7E57C2;
            --background-color: #F4F6F8;
            --text-color: #263238;
        }
        body { background-color: var(--background-color); color: var(--text-color); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .navbar { background-color: var(--primary-color) !important; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .navbar-brand { font-weight: 700; font-size: 1.5rem; }
        .nav-link { font-weight: 500; transition: all 0.3s ease; }
        .nav-link:hover { background-color: rgba(255,255,255,0.1); border-radius: 5px; }
        .main-content { padding: 2rem 0; }
        .content-card { background: white; border-radius: 15px; padding: 1.5rem; box-shadow: 0 5px 15px rgba(0,0,0,0.08); margin-bottom: 2rem; }
        .page-header { background: linear-gradient(135deg, var(--primary-color) 0%, var(--accent-color) 100%); color: white; border-radius: 15px; padding: 2rem; margin-bottom: 2rem; }
        .btn-primary { background-color: var(--primary-color); border-color: var(--primary-color); }
        .btn-primary:hover { background-color: #006064; border-color: #006064; }
        .btn-secondary { background-color: var(--secondary-color); border-color: var(--secondary-color); color: var(--text-color); }
        .btn-accent { background-color: var(--accent-color); border-color: var(--accent-color); color: white; }
        .patient-card { border: 1px solid #e0e0e0; border-radius: 10px; padding: 1.5rem; margin-bottom: 1rem; transition: all .3s ease; }
        .patient-card:hover { box-shadow: 0 5px 15px rgba(0,0,0,0.1); transform: translateY(-2px); }
        .patient-info { display: flex; align-items: center; gap: 1rem; }
        .patient-avatar { width: 60px; height: 60px; border-radius: 50%; background: var(--primary-color); display: flex; align-items: center; justify-content: center; color: white; font-size: 1.5rem; font-weight: bold; }
        .patient-details h5 { margin: 0; color: var(--primary-color); }
        .patient-meta { font-size: .9rem; color: #666; }
        .stats-badge { background: var(--background-color); padding: .25rem .75rem; border-radius: 15px; font-size: .8rem; margin-right: .5rem; }
        .search-filters { background: var(--background-color); border-radius: 10px; padding: 1.5rem; margin-bottom: 1.5rem; }
        .modal-header { background-color: var(--primary-color); color: white; }
        .form-control:focus { border-color: var(--primary-color); box-shadow: 0 0 0 0.2rem rgba(0,131,143,0.25); }
        .medical-record { border-left: 4px solid var(--accent-color); background: #f8f9fa; padding: 1rem; margin-bottom: 1rem; border-radius: 0 8px 8px 0; }
        .record-date { color: var(--accent-color); font-weight: 600; font-size: .9rem; }
        .no-patients { text-align: center; padding: 3rem; color: #666; }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">
                <i class="fas fa-hospital me-2"></i><?php echo APP_NAME; ?> - Doctor
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="dashboard.php"><i class="fas fa-tachometer-alt me-1"></i>Dashboard</a></li>
                    <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>Appointments</a></li>
                    <li class="nav-item"><a class="nav-link" href="availability.php"><i class="fas fa-clock me-1"></i>Availability</a></li>
                    <li class="nav-item"><a class="nav-link active" href="patients.php"><i class="fas fa-user-injured me-1"></i>Patients</a></li>
                    <li class="nav-item"><a class="nav-link" href="feedback.php"><i class="fas fa-star me-1"></i>Feedback</a></li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-md me-1"></i><?php echo h($doctor_name); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="main-content">
        <div class="container">
            <!-- Page Header -->
            <div class="page-header">
                <div class="row align-items-center">
                    <div class="col-md-8">
                        <h1 class="mb-2"><i class="fas fa-user-injured me-3"></i>Patient Care</h1>
                        <p class="mb-0 opacity-75">View and manage your patients' medical records</p>
                    </div>
                    <div class="col-md-4 text-end">
                        <i class="fas fa-stethoscope" style="font-size: 4rem; opacity: 0.3;"></i>
                    </div>
                </div>
            </div>

            <!-- Messages -->
            <?php if ($success_message): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <i class="fas fa-check-circle me-2"></i><?php echo h($success_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            <?php if ($error_message): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="fas fa-exclamation-circle me-2"></i><?php echo h($error_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>

            <!-- Search and Filters -->
            <div class="content-card">
                <div class="search-filters">
                    <form method="GET" class="row g-3">
                        <div class="col-md-4">
                            <label for="search" class="form-label">Search Patients</label>
                            <input type="text" class="form-control" id="search" name="search"
                                   value="<?php echo h($search); ?>" placeholder="Name, email, or phone...">
                        </div>
                        <div class="col-md-3">
                            <label for="filter_date" class="form-label">Appointment Date</label>
                            <input type="date" class="form-control" id="filter_date" name="filter_date"
                                   value="<?php echo h($filter_date); ?>">
                        </div>
                        <div class="col-md-3">
                            <label class="form-label">&nbsp;</label>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search me-1"></i>Search
                                </button>
                            </div>
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">&nbsp;</label>
                            <div class="d-grid">
                                <a href="patients.php" class="btn btn-secondary">
                                    <i class="fas fa-times me-1"></i>Clear
                                </a>
                            </div>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Patients List -->
            <div class="content-card">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h3><i class="fas fa-users me-2"></i>Your Patients (<?php echo (int)$total_patients; ?>)</h3>
                </div>

                <?php if (empty($patients)): ?>
                    <div class="no-patients">
                        <i class="fas fa-user-injured" style="font-size: 4rem; color: #ccc;"></i>
                        <h4 class="mt-3 text-muted">No patients found</h4>
                        <p class="text-muted">
                            <?php if ($search !== '' || $filter_date !== ''): ?>
                                Try adjusting your search criteria.
                            <?php else: ?>
                                There are no patients with appointments with you yet.
                            <?php endif; ?>
                        </p>
                    </div>
                <?php else: ?>
                    <?php foreach ($patients as $patient): ?>
                        <div class="patient-card">
                            <div class="row">
                                <div class="col-md-8">
                                    <div class="patient-info">
                                        <div class="patient-avatar"><?php echo strtoupper(substr($patient['name'], 0, 1)); ?></div>
                                        <div class="patient-details">
                                            <h5><?php echo h($patient['name']); ?></h5>
                                            <div class="patient-meta">
                                                <i class="fas fa-envelope me-1"></i><?php echo h($patient['email']); ?><br>
                                                <i class="fas fa-phone me-1"></i><?php echo h($patient['phone']); ?><br>
                                                <i class="fas fa-birthday-cake me-1"></i>
                                                <?php echo $patient['date_of_birth']; ?>
                                                (<?php echo ucfirst(h($patient['gender'])); ?>)
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-4 text-end">
                                    <div class="mb-2">
                                        <span class="stats-badge"><i class="fas fa-calendar me-1"></i><?php echo (int)$patient['total_appointments']; ?> appointments</span>
                                        <span class="stats-badge"><i class="fas fa-file-medical me-1"></i><?php echo (int)$patient['total_records']; ?> records</span>
                                    </div>
                                    <div class="mb-2">
                                        <small class="text-muted">
                                            Last visit:
                                            <?php 
                                                if ($patient['last_appointment_dt']) {
                                                    $dt = strtotime($patient['last_appointment_dt']);
                                                    echo date('M j, Y g:i A', $dt);
                                                } else {
                                                    echo 'Never';
                                                }
                                            ?>
                                        </small>
                                    </div>
                                    <button type="button" class="btn btn-primary btn-sm me-2"
                                            data-bs-toggle="modal" data-bs-target="#recordsModal"
                                            data-patient-id="<?php echo (int)$patient['id']; ?>"
                                            data-patient-name="<?php echo h($patient['name']); ?>">
                                        <i class="fas fa-file-medical me-1"></i>View Records
                                    </button>
                                    <button type="button" class="btn btn-accent btn-sm"
                                            data-bs-toggle="modal" data-bs-target="#addRecordModal"
                                            data-patient-id="<?php echo (int)$patient['id']; ?>"
                                            data-patient-name="<?php echo h($patient['name']); ?>">
                                        <i class="fas fa-plus me-1"></i>Add Record
                                    </button>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>

                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                        <nav aria-label="Patients pagination">
                            <ul class="pagination justify-content-center">
                                <?php if ($page > 1): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?page=<?php echo $page-1; ?>&search=<?php echo urlencode($search); ?>&filter_date=<?php echo urlencode($filter_date); ?>">
                                            <i class="fas fa-chevron-left"></i>
                                        </a>
                                    </li>
                                <?php endif; ?>
                                <?php for ($i = max(1, $page-2); $i <= min($total_pages, $page+2); $i++): ?>
                                    <li class="page-item <?php echo $i === $page ? 'active' : ''; ?>">
                                        <a class="page-link" href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>&filter_date=<?php echo urlencode($filter_date); ?>">
                                            <?php echo $i; ?>
                                        </a>
                                    </li>
                                <?php endfor; ?>
                                <?php if ($page < $total_pages): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?page=<?php echo $page+1; ?>&search=<?php echo urlencode($search); ?>&filter_date=<?php echo urlencode($filter_date); ?>">
                                            <i class="fas fa-chevron-right"></i>
                                        </a>
                                    </li>
                                <?php endif; ?>
                            </ul>
                        </nav>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <!-- View Medical Records Modal -->
    <div class="modal fade" id="recordsModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-file-medical me-2"></i>Medical Records - <span id="recordsPatientName"></span></h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="recordsContent">
                        <div class="text-center py-4">
                            <i class="fas fa-spinner fa-spin fa-2x"></i>
                            <p class="mt-2">Loading medical records...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Add Medical Record Modal -->
    <div class="modal fade" id="addRecordModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-plus me-2"></i>Add Medical Record - <span id="addRecordPatientName"></span></h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="action" value="add_medical_record">
                        <input type="hidden" name="patient_id" id="addRecordPatientId">
                        <div class="mb-3">
                            <label for="diagnosis" class="form-label">Diagnosis *</label>
                            <textarea class="form-control" id="diagnosis" name="diagnosis" rows="3" required placeholder="Enter diagnosis details..."></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="prescription" class="form-label">Prescription</label>
                            <textarea class="form-control" id="prescription" name="prescription" rows="3" placeholder="Enter prescribed medications and dosage..."></textarea>
                        </div>
                        <div class="mb-3">
                            <label for="notes" class="form-label">Additional Notes</label>
                            <textarea class="form-control" id="notes" name="notes" rows="2" placeholder="Any additional notes or observations..."></textarea>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary"><i class="fas fa-save me-2"></i>Save Record</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Edit Medical Record Modal -->
    <div class="modal fade" id="editRecordModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-edit me-2"></i>Edit Medical Record</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
        <form method="POST">
            <div class="modal-body">
                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                <input type="hidden" name="action" value="update_medical_record">
                <input type="hidden" name="record_id" id="editRecordId">
                <div class="mb-3">
                    <label for="edit_diagnosis" class="form-label">Diagnosis *</label>
                    <textarea class="form-control" id="edit_diagnosis" name="diagnosis" rows="3" required></textarea>
                </div>
                <div class="mb-3">
                    <label for="edit_prescription" class="form-label">Prescription</label>
                    <textarea class="form-control" id="edit_prescription" name="prescription" rows="3"></textarea>
                </div>
                <div class="mb-3">
                    <label for="edit_notes" class="form-label">Additional Notes</label>
                    <textarea class="form-control" id="edit_notes" name="notes" rows="2"></textarea>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="submit" class="btn btn-primary"><i class="fas fa-save me-2"></i>Update Record</button>
            </div>
        </form>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Handle view records modal
        document.getElementById('recordsModal').addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const patientId = button.getAttribute('data-patient-id');
            const patientName = button.getAttribute('data-patient-name');
            document.getElementById('recordsPatientName').textContent = patientName;

            // Load medical records via AJAX
            fetch(`get_medical_records.php?patient_id=${patientId}`)
                .then(response => response.text())
                .then(data => { document.getElementById('recordsContent').innerHTML = data; })
                .catch(() => {
                    document.getElementById('recordsContent').innerHTML =
                        '<div class="alert alert-danger"><i class="fas fa-exclamation-triangle me-2"></i>Error loading medical records.</div>';
                });
        });

        // Handle add record modal
        document.getElementById('addRecordModal').addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const patientId = button.getAttribute('data-patient-id');
            const patientName = button.getAttribute('data-patient-name');
            document.getElementById('addRecordPatientName').textContent = patientName;
            document.getElementById('addRecordPatientId').value = patientId;
        });

        // Called from AJAX-loaded content
        function showEditModal(recordId, diagnosis, prescription, notes) {
            document.getElementById('editRecordId').value = recordId;
            document.getElementById('edit_diagnosis').value = diagnosis || '';
            document.getElementById('edit_prescription').value = prescription || '';
            document.getElementById('edit_notes').value = notes || '';
            new bootstrap.Modal(document.getElementById('editRecordModal')).show();
        }
        window.showEditModal = showEditModal;
    </script>
</body>
</html>
