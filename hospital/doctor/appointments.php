<?php
require_once '../config/config.php';

// Check if doctor is logged in
if (!isset($_SESSION['doctor_id'])) {
    header('Location: login.php');
    exit();
}

$doctor_id = $_SESSION['doctor_id'];
$doctor_name = $_SESSION['doctor_name'];
$success_message = '';
$error_message = '';

// Handle appointment actions
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error_message = 'Invalid security token. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        $appointment_id = (int)($_POST['appointment_id'] ?? 0);
        
        try {
            if ($action == 'confirm') {
                $stmt = $pdo->prepare("UPDATE appointments SET status = 'Confirmed' WHERE id = ? AND doctor_id = ?");
                $stmt->execute([$appointment_id, $doctor_id]);
                $success_message = 'Appointment confirmed successfully.';
                
            } elseif ($action == 'cancel') {
                $stmt = $pdo->prepare("UPDATE appointments SET status = 'Cancelled' WHERE id = ? AND doctor_id = ?");
                $stmt->execute([$appointment_id, $doctor_id]);
                $success_message = 'Appointment cancelled successfully.';
                
            } elseif ($action == 'reschedule') {
                $new_date = $_POST['new_date'] ?? '';
                $new_time = $_POST['new_time'] ?? '';
                
                if (empty($new_date) || empty($new_time)) {
                    $error_message = 'Please provide both date and time for rescheduling.';
                } else {
                    // Check if the new slot is available
                    $stmt = $pdo->prepare("
                        SELECT COUNT(*) FROM appointments 
                        WHERE doctor_id = ? AND appointment_date = ? AND appointment_time = ? 
                        AND status IN ('Confirmed', 'Pending') AND id != ?
                    ");
                    $stmt->execute([$doctor_id, $new_date, $new_time, $appointment_id]);
                    
                    if ($stmt->fetchColumn() > 0) {
                        $error_message = 'The selected time slot is already booked.';
                    } else {
                        $stmt = $pdo->prepare("
                            UPDATE appointments 
                            SET appointment_date = ?, appointment_time = ?, status = 'Confirmed' 
                            WHERE id = ? AND doctor_id = ?
                        ");
                        $stmt->execute([$new_date, $new_time, $appointment_id, $doctor_id]);
                        $success_message = 'Appointment rescheduled successfully.';
                    }
                }
            }
        } catch (PDOException $e) {
            $error_message = 'Database error occurred. Please try again.';
        }
    }
}

// Get filter parameters
$status_filter = $_GET['status'] ?? 'all';
$date_filter   = $_GET['date'] ?? '';
$search        = $_GET['search'] ?? '';

// Build query based on filters
$where_conditions = ["a.doctor_id = ?"];
$params = [$doctor_id];

if ($status_filter != 'all') {
    $where_conditions[] = "a.status = ?";
    $params[] = $status_filter;
}

if (!empty($date_filter)) {
    $where_conditions[] = "a.appointment_date = ?";
    $params[] = $date_filter;
}

/**
 * SEARCH:
 * - Name / Email / Phone (existing)
 * - Date of Birth (new)
 *   We match against several stringified DOB formats to allow flexible typing:
 *   - ISO:       %Y-%m-%d  (e.g., 1985-07-20; also supports partial LIKE '1985-07')
 *   - D/M/Y:     %d/%m/%Y
 *   - M/D/Y:     %m/%d/%Y
 *   - Year only: YEAR(p.date_of_birth) = ? when search is strictly 4 digits
 */
if (!empty($search)) {
    $where_piece = [];
    $where_piece[] = "(p.name LIKE ? OR p.email LIKE ? OR p.phone LIKE ?)";
    $search_param = "%$search%";

    // Detect a pure year "YYYY"
    $is_year_only = preg_match('/^\d{4}$/', $search) === 1;

    // Always allow LIKE on common formatted DOB strings (helps partials: "1985-07", "07/1985", etc.)
    $where_piece[] = "DATE_FORMAT(p.date_of_birth, '%Y-%m-%d') LIKE ?";
    $where_piece[] = "DATE_FORMAT(p.date_of_birth, '%d/%m/%Y') LIKE ?";
    $where_piece[] = "DATE_FORMAT(p.date_of_birth, '%m/%d/%Y') LIKE ?";

    // If it's precisely a 4-digit year, also match YEAR(dob) = ?
    if ($is_year_only) {
        $where_piece[] = "YEAR(p.date_of_birth) = ?";
    }

    $where_conditions[] = '(' . implode(' OR ', $where_piece) . ')';

    // Bind params (order must match the ORs above)
    $params[] = $search_param; // name
    $params[] = $search_param; // email
    $params[] = $search_param; // phone
    $params[] = $search_param; // ISO LIKE
    $params[] = $search_param; // D/M/Y LIKE
    $params[] = $search_param; // M/D/Y LIKE
    if ($is_year_only) {
        $params[] = (int)$search; // YEAR =
    }
}

$where_clause = implode(' AND ', $where_conditions);

try {
    // Get appointments with pagination
    $page = max(1, (int)($_GET['page'] ?? 1));
    $per_page = 10;
    $offset = ($page - 1) * $per_page;
    
    // Count total appointments
    $count_query = "SELECT COUNT(*) 
                    FROM appointments a 
                    JOIN patients p ON a.patient_id = p.id 
                    WHERE $where_clause";
    $stmt = $pdo->prepare($count_query);
    $stmt->execute($params);
    $total_appointments = (int)$stmt->fetchColumn();
    $total_pages = (int)ceil($total_appointments / $per_page);
    
    // Get appointments
    $query = "
        SELECT a.*, 
               p.name AS patient_name, 
               p.email AS patient_email, 
               p.phone AS patient_phone, 
               p.date_of_birth AS patient_dob
        FROM appointments a 
        JOIN patients p ON a.patient_id = p.id 
        WHERE $where_clause
        ORDER BY a.appointment_date DESC, a.appointment_time DESC
        LIMIT $per_page OFFSET $offset
    ";
    $stmt = $pdo->prepare($query);
    $stmt->execute($params);
    $appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
} catch (PDOException $e) {
    $error_message = 'Database error occurred.';
    $appointments = [];
}

$csrf_token = generateCSRFToken();

/**
 * Helper: calculate age from DOB (Y-m-d or any strtotime-parsable string)
 */
function calculateAgeFromDob(?string $dob): ?int {
    if (empty($dob)) return null;
    $ts = strtotime($dob);
    if ($ts === false) return null;
    $dobDate = new DateTime(date('Y-m-d', $ts));
    $today = new DateTime('today');
    return (int)$dobDate->diff($today)->y;
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Appointments Management - <?php echo APP_NAME; ?></title>
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
        
        body {
            background-color: var(--background-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .navbar {
            background-color: var(--primary-color) !important;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
        }
        
        .nav-link {
            font-weight: 500;
            transition: all 0.3s ease;
        }
        
        .nav-link:hover {
            background-color: rgba(255, 255, 255, 0.1);
            border-radius: 5px;
        }
        
        .main-content {
            padding: 2rem 0;
        }
        
        .content-card {
            background: white;
            border-radius: 15px;
            padding: 1.5rem;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.08);
            margin-bottom: 2rem;
        }
        
        .page-header {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--accent-color) 100%);
            color: white;
            border-radius: 15px;
            padding: 2rem;
            margin-bottom: 2rem;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .btn-primary:hover {
            background-color: #006064;
            border-color: #006064;
        }
        
        .btn-secondary {
            background-color: var(--secondary-color);
            border-color: var(--secondary-color);
            color: var(--text-color);
        }
        
        .btn-accent {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
            color: white;
        }
        
        .status-badge {
            font-size: 0.75rem;
            padding: 0.4rem 0.8rem;
            border-radius: 20px;
            font-weight: 600;
        }
        
        .status-pending {
            background-color: #FFF3E0;
            color: #F57C00;
        }
        
        .status-confirmed {
            background-color: #E8F5E8;
            color: #2E7D32;
        }
        
        .status-cancelled {
            background-color: #FFEBEE;
            color: #C62828;
        }
        
        .appointment-card {
            border: 1px solid #e0e0e0;
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            transition: all 0.3s ease;
        }
        
        .appointment-card:hover {
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transform: translateY(-2px);
        }
        
        .filter-section {
            background: var(--background-color);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .patient-info {
            background: var(--background-color);
            border-radius: 8px;
            padding: 1rem;
        }
        
        .appointment-actions {
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }
        
        .modal-header {
            background-color: var(--primary-color);
            color: white;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.2rem rgba(0, 131, 143, 0.25);
        }
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
                    <li class="nav-item">
                        <a class="nav-link" href="dashboard.php">
                            <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="appointments.php">
                            <i class="fas fa-calendar-check me-1"></i>Appointments
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="availability.php">
                            <i class="fas fa-clock me-1"></i>Availability
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="patients.php">
                            <i class="fas fa-user-injured me-1"></i>Patients
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="feedback.php">
                            <i class="fas fa-star me-1"></i>Feedback
                        </a>
                    </li>
                </ul>
                
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-md me-1"></i><?php echo htmlspecialchars($doctor_name); ?>
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
                        <h1 class="mb-2"><i class="fas fa-calendar-check me-3"></i>Appointments Management</h1>
                        <p class="mb-0 opacity-75">View, confirm, reschedule, and manage your patient appointments</p>
                    </div>
                    <div class="col-md-4 text-end">
                        <i class="fas fa-calendar-alt" style="font-size: 4rem; opacity: 0.3;"></i>
                    </div>
                </div>
            </div>
            
            <!-- Messages -->
            <?php if ($success_message): ?>
                <div class="alert alert-success alert-dismissible fade show" role="alert">
                    <i class="fas fa-check-circle me-2"></i><?php echo htmlspecialchars($success_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <?php if ($error_message): ?>
                <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    <i class="fas fa-exclamation-circle me-2"></i><?php echo htmlspecialchars($error_message); ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            <?php endif; ?>
            
            <!-- Filters -->
            <div class="filter-section">
                <form method="GET" action="">
                    <div class="row g-3">
                        <div class="col-md-3">
                            <label for="status" class="form-label">Status</label>
                            <select class="form-select" id="status" name="status">
                                <option value="all" <?php echo $status_filter == 'all' ? 'selected' : ''; ?>>All Status</option>
                                <option value="Pending" <?php echo $status_filter == 'Pending' ? 'selected' : ''; ?>>Pending</option>
                                <option value="Confirmed" <?php echo $status_filter == 'Confirmed' ? 'selected' : ''; ?>>Confirmed</option>
                                <option value="Cancelled" <?php echo $status_filter == 'Cancelled' ? 'selected' : ''; ?>>Cancelled</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <label for="date" class="form-label">Date</label>
                            <input type="date" class="form-control" id="date" name="date" value="<?php echo htmlspecialchars($date_filter); ?>">
                        </div>
                        <div class="col-md-4">
                            <label for="search" class="form-label">Search Patient / DOB</label>
                            <input type="text" class="form-control" id="search" name="search" 
                                   placeholder="Name, email, phone, or DOB (e.g., 1985-07-20 or 20/07/1985)" 
                                   value="<?php echo htmlspecialchars($search); ?>">
                        </div>
                        <div class="col-md-2">
                            <label class="form-label">&nbsp;</label>
                            <div class="d-grid">
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-search me-1"></i>Filter
                                </button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
            
            <!-- Appointments List -->
            <div class="content-card">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <h3><i class="fas fa-list me-2"></i>Appointments (<?php echo $total_appointments; ?>)</h3>
                    <?php if (!empty($status_filter) || !empty($date_filter) || !empty($search)): ?>
                        <a href="appointments.php" class="btn btn-outline-secondary btn-sm">
                            <i class="fas fa-times me-1"></i>Clear Filters
                        </a>
                    <?php endif; ?>
                </div>
                
                <?php if (empty($appointments)): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-calendar-times" style="font-size: 4rem; color: #ccc;"></i>
                        <h4 class="mt-3 text-muted">No appointments found</h4>
                        <p class="text-muted">No appointments match your current filters.</p>
                        <a href="availability.php" class="btn btn-primary">
                            <i class="fas fa-clock me-2"></i>Set Your Availability
                        </a>
                    </div>
                <?php else: ?>
                    <?php foreach ($appointments as $appointment): 
                        $age = calculateAgeFromDob($appointment['patient_dob']);
                        $dobPretty = '';
                        if (!empty($appointment['patient_dob']) && strtotime($appointment['patient_dob']) !== false) {
                            $dobPretty = date('F j, Y', strtotime($appointment['patient_dob']));
                        }
                    ?>
                        <div class="appointment-card">
                            <div class="row">
                                <div class="col-md-8">
                                    <div class="patient-info">
                                        <div class="row">
                                            <div class="col-md-7">
                                                <h5 class="mb-2">
                                                    <i class="fas fa-user me-2"></i><?php echo htmlspecialchars($appointment['patient_name']); ?>
                                                    <span class="status-badge status-<?php echo strtolower($appointment['status']); ?> ms-2">
                                                        <?php echo htmlspecialchars($appointment['status']); ?>
                                                    </span>
                                                </h5>
                                                <p class="mb-1">
                                                    <i class="fas fa-envelope me-2"></i><?php echo htmlspecialchars($appointment['patient_email']); ?>
                                                </p>
                                                <p class="mb-1">
                                                    <i class="fas fa-phone me-2"></i><?php echo htmlspecialchars($appointment['patient_phone']); ?>
                                                </p>
                                                <p class="mb-0">
                                                    <i class="fas fa-birthday-cake me-2"></i>
                                                    <?php if ($dobPretty): ?>
                                                        DOB: <?php echo htmlspecialchars($dobPretty); ?>
                                                        <?php if ($age !== null): ?>
                                                            <span class="ms-2">| Age: <?php echo (int)$age; ?></span>
                                                        <?php endif; ?>
                                                    <?php else: ?>
                                                        DOB: <em>Not available</em>
                                                    <?php endif; ?>
                                                </p>
                                            </div>
                                            <div class="col-md-5">
                                                <h6 class="text-primary mb-2">
                                                    <i class="fas fa-calendar me-2"></i>Appointment Details
                                                </h6>
                                                <p class="mb-1">
                                                    <strong>Date:</strong> <?php echo date('l, F j, Y', strtotime($appointment['appointment_date'])); ?>
                                                </p>
                                                <p class="mb-1">
                                                    <strong>Time:</strong> <?php echo date('g:i A', strtotime($appointment['appointment_time'])); ?>
                                                </p>
                                                <?php if (!empty($appointment['notes'])): ?>
                                                    <p class="mb-0">
                                                        <strong>Notes:</strong> <?php echo htmlspecialchars($appointment['notes']); ?>
                                                    </p>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <div class="appointment-actions">
                                        <?php if ($appointment['status'] == 'Pending'): ?>
                                            <form method="POST" class="d-inline">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                <input type="hidden" name="action" value="confirm">
                                                <input type="hidden" name="appointment_id" value="<?php echo (int)$appointment['id']; ?>">
                                                <button type="submit" class="btn btn-success btn-sm">
                                                    <i class="fas fa-check me-1"></i>Confirm
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                        
                                        <?php if (in_array($appointment['status'], ['Pending', 'Confirmed'])): ?>
                                            <button type="button" class="btn btn-accent btn-sm" 
                                                    data-bs-toggle="modal" data-bs-target="#rescheduleModal" 
                                                    data-appointment-id="<?php echo (int)$appointment['id']; ?>"
                                                    data-current-date="<?php echo htmlspecialchars($appointment['appointment_date']); ?>"
                                                    data-current-time="<?php echo htmlspecialchars($appointment['appointment_time']); ?>"
                                                    data-patient-name="<?php echo htmlspecialchars($appointment['patient_name']); ?>">
                                                <i class="fas fa-calendar-alt me-1"></i>Reschedule
                                            </button>
                                            
                                            <form method="POST" class="d-inline" 
                                                  onsubmit="return confirm('Are you sure you want to cancel this appointment?')">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                                <input type="hidden" name="action" value="cancel">
                                                <input type="hidden" name="appointment_id" value="<?php echo (int)$appointment['id']; ?>">
                                                <button type="submit" class="btn btn-outline-danger btn-sm">
                                                    <i class="fas fa-times me-1"></i>Cancel
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                    
                    <!-- Pagination -->
                    <?php if ($total_pages > 1): ?>
                        <nav aria-label="Appointments pagination">
                            <ul class="pagination justify-content-center">
                                <?php if ($page > 1): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?page=<?php echo $page - 1; ?>&status=<?php echo urlencode($status_filter); ?>&date=<?php echo urlencode($date_filter); ?>&search=<?php echo urlencode($search); ?>">
                                            <i class="fas fa-chevron-left"></i>
                                        </a>
                                    </li>
                                <?php endif; ?>
                                
                                <?php for ($i = max(1, $page - 2); $i <= min($total_pages, $page + 2); $i++): ?>
                                    <li class="page-item <?php echo $i == $page ? 'active' : ''; ?>">
                                        <a class="page-link" href="?page=<?php echo $i; ?>&status=<?php echo urlencode($status_filter); ?>&date=<?php echo urlencode($date_filter); ?>&search=<?php echo urlencode($search); ?>">
                                            <?php echo $i; ?>
                                        </a>
                                    </li>
                                <?php endfor; ?>
                                
                                <?php if ($page < $total_pages): ?>
                                    <li class="page-item">
                                        <a class="page-link" href="?page=<?php echo $page + 1; ?>&status=<?php echo urlencode($status_filter); ?>&date=<?php echo urlencode($date_filter); ?>&search=<?php echo urlencode($search); ?>">
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
    
    <!-- Reschedule Modal -->
    <div class="modal fade" id="rescheduleModal" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title"><i class="fas fa-calendar-alt me-2"></i>Reschedule Appointment</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <form method="POST">
                    <div class="modal-body">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                        <input type="hidden" name="action" value="reschedule">
                        <input type="hidden" name="appointment_id" id="reschedule_appointment_id">
                        
                        <div class="mb-3">
                            <label class="form-label">Patient:</label>
                            <p class="fw-bold" id="reschedule_patient_name"></p>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Current Date & Time:</label>
                            <p id="reschedule_current_datetime"></p>
                        </div>
                        
                        <div class="row">
                            <div class="col-md-6">
                                <label for="new_date" class="form-label">New Date</label>
                                <input type="date" class="form-control" id="new_date" name="new_date" 
                                       min="<?php echo date('Y-m-d'); ?>" required>
                            </div>
                            <div class="col-md-6">
                                <label for="new_time" class="form-label">New Time</label>
                                <input type="time" class="form-control" id="new_time" name="new_time" required>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Reschedule
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Handle reschedule modal
        document.getElementById('rescheduleModal').addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const appointmentId = button.getAttribute('data-appointment-id');
            const currentDate = button.getAttribute('data-current-date');
            const currentTime = button.getAttribute('data-current-time');
            const patientName = button.getAttribute('data-patient-name');
            
            document.getElementById('reschedule_appointment_id').value = appointmentId;
            document.getElementById('reschedule_patient_name').textContent = patientName;
            
            const currentDateTime = new Date(currentDate + 'T' + currentTime);
            const dateStr = currentDateTime.toLocaleDateString('en-US', { 
                weekday: 'long', 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric' 
            });
            const timeStr = currentDateTime.toLocaleTimeString('en-US', { 
                hour: 'numeric', 
                minute: '2-digit', 
                hour12: true 
            });
            document.getElementById('reschedule_current_datetime').textContent = dateStr + ' at ' + timeStr;
        });
    </script>
</body>
</html>
