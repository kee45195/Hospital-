<?php
require_once '../config/config.php';

// Check if user is logged in as receptionist
if (!isset($_SESSION['receptionist_id']) || $_SESSION['user_type'] !== 'receptionist') {
    header('Location: ../login.php');
    exit();
}

$receptionist_id = $_SESSION['receptionist_id'];
$receptionist_name = $_SESSION['receptionist_name'];

try {
    // Get pending appointments count
    $pending_stmt = $pdo->prepare("SELECT COUNT(*) as count FROM appointments WHERE status = 'Pending'");
    $pending_stmt->execute();
    $pending_count = $pending_stmt->fetch()['count'];
    
    // Get today's confirmed appointments count
    $today_stmt = $pdo->prepare("SELECT COUNT(*) as count FROM appointments WHERE status = 'Confirmed' AND appointment_date = CURDATE()");
    $today_stmt->execute();
    $today_count = $today_stmt->fetch()['count'];
    
    // Get total patients count
    $patients_stmt = $pdo->prepare("SELECT COUNT(*) as count FROM patients");
    $patients_stmt->execute();
    $patients_count = $patients_stmt->fetch()['count'];
    
    // Get recent pending appointments
    $recent_stmt = $pdo->prepare("
        SELECT a.id, a.appointment_date, a.appointment_time, a.notes,
               p.name as patient_name, p.phone as patient_phone,
               d.name as doctor_name, d.specialization
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        JOIN doctors d ON a.doctor_id = d.id
        WHERE a.status = 'Pending'
        ORDER BY a.created_at DESC
        LIMIT 5
    ");
    $recent_stmt->execute();
    $recent_appointments = $recent_stmt->fetchAll();
    
} catch (PDOException $e) {
    $error_message = 'Database error occurred.';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Receptionist Dashboard - <?php echo APP_NAME; ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<style>
:root { --primary-color:#42A5F5; --secondary-color:#81C784; --accent-color:#FFB74D; --background-color:#FAFAFA; --text-color:#212121; }
body{background-color:var(--background-color);color:var(--text-color);font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif}
.navbar{background:linear-gradient(135deg,var(--primary-color),#1976D2)!important;box-shadow:0 2px 10px rgba(0,0,0,.1)}
.navbar-brand{font-weight:700;font-size:1.5rem;color:#fff!important}
.navbar-nav .nav-link{color:#fff!important;font-weight:500;margin:0 10px;transition:.3s}
.navbar-nav .nav-link:hover{color:var(--secondary-color)!important}
.dashboard-card{background:#fff;border-radius:15px;box-shadow:0 5px 20px rgba(0,0,0,.08);border:none;transition:.3s;padding:1.5rem}
.dashboard-card:hover{transform:translateY(-5px);box-shadow:0 10px 30px rgba(0,0,0,.15)}
.stat-card{text-align:center;padding:2rem 1rem}
.stat-icon{font-size:3rem;margin-bottom:1rem}
.stat-number{font-size:2.5rem;font-weight:700;margin-bottom:.5rem}
.stat-label{color:#666;font-weight:500}
.pending-icon{color:var(--accent-color)} .today-icon{color:var(--primary-color)} .patients-icon{color:var(--secondary-color)}
.btn-primary{background-color:var(--primary-color);border-color:var(--primary-color);border-radius:25px;padding:10px 25px;font-weight:600}
.btn-primary:hover{background-color:#1976D2;border-color:#1976D2}
.btn-success{background-color:var(--secondary-color);border-color:var(--secondary-color);border-radius:25px;padding:8px 20px}
.btn-warning{background-color:var(--accent-color);border-color:var(--accent-color);border-radius:25px;padding:8px 20px;color:#fff}
.btn-info{border-radius:25px;padding:8px 20px}
.table-container{background:#fff;border-radius:15px;padding:1.5rem;box-shadow:0 5px 20px rgba(0,0,0,.08)}
.table th{background-color:var(--primary-color);color:#fff;border:none;font-weight:600}
.table td{border-color:#f0f0f0;vertical-align:middle}
.welcome-header{background:linear-gradient(135deg,var(--primary-color),#1976D2);color:#fff;padding:2rem;border-radius:15px;margin-bottom:2rem}
.page-title{color:var(--primary-color);font-weight:700;margin-bottom:2rem}
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="dashboard.php"><i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?></a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"><span class="navbar-toggler-icon"></span></button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link active" href="dashboard.php"><i class="fas fa-tachometer-alt me-1"></i>Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>Appointments</a></li>
        <li class="nav-item"><a class="nav-link" href="profile.php"><i class="fas fa-user me-1"></i>Profile</a></li>
      </ul>
      <ul class="navbar-nav">
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
            <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($receptionist_name); ?>
          </a>
          <ul class="dropdown-menu">
            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>Profile</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><a class="dropdown-item" href="../admin_logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
          </ul>
        </li>
      </ul>
    </div>
  </div>
</nav>

<div class="container mt-4">
  <div class="welcome-header text-center">
    <h1><i class="fas fa-hospital me-3"></i>Welcome, <?php echo htmlspecialchars($receptionist_name); ?>!</h1>
    <p class="mb-0">Manage appointments and assist patients with their healthcare needs</p>
  </div>

  <div class="row mb-4">
    <div class="col-md-4 mb-3">
      <div class="dashboard-card stat-card">
        <i class="fas fa-clock stat-icon pending-icon"></i>
        <div class="stat-number"><?php echo $pending_count; ?></div>
        <div class="stat-label">Pending Appointments</div>
      </div>
    </div>
    <div class="col-md-4 mb-3">
      <div class="dashboard-card stat-card">
        <i class="fas fa-calendar-day stat-icon today-icon"></i>
        <div class="stat-number"><?php echo $today_count; ?></div>
        <div class="stat-label">Today's Appointments</div>
      </div>
    </div>
    <div class="col-md-4 mb-3">
      <div class="dashboard-card stat-card">
        <i class="fas fa-users stat-icon patients-icon"></i>
        <div class="stat-number"><?php echo $patients_count; ?></div>
        <div class="stat-label">Total Patients</div>
      </div>
    </div>
  </div>

  <!-- Quick Actions -->
  <div class="row mb-4">
    <div class="col-12">
      <div class="dashboard-card">
        <h4 class="page-title"><i class="fas fa-bolt me-2"></i>Quick Actions</h4>
        <div class="row">
          <div class="col-md-3 mb-3">
            <a href="appointments.php" class="btn btn-primary w-100">
              <i class="fas fa-calendar-check me-2"></i>Manage Appointments
            </a>
          </div>
          <!-- UPDATED: jump to the doctor availability section on appointments page -->
          <div class="col-md-3 mb-3">
            <a href="appointments.php#doctor-availability" class="btn btn-success w-100">
              <i class="fas fa-clock me-2"></i>Check Doctor Availability
            </a>
          </div>
          <div class="col-md-3 mb-3">
            <a href="profile.php" class="btn btn-warning w-100">
              <i class="fas fa-user-edit me-2"></i>Update Profile
            </a>
          </div>
          <div class="col-md-3 mb-3">
            <a href="/hospital/receptionist/register.php" class="btn btn-info w-100 text-white">
              <i class="fas fa-user-plus me-2"></i>Register Offline Patient
            </a>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Recent Pending Appointments -->
  <div class="row">
    <div class="col-12">
      <div class="table-container">
        <h4 class="page-title"><i class="fas fa-list me-2"></i>Recent Pending Appointments</h4>

        <?php if (empty($recent_appointments)): ?>
          <div class="text-center py-4">
            <i class="fas fa-calendar-times" style="font-size:3rem;color:#ccc;"></i>
            <p class="text-muted mt-3">No pending appointments at the moment.</p>
          </div>
        <?php else: ?>
          <div class="table-responsive">
            <table class="table table-hover">
              <thead>
                <tr>
                  <th>Patient</th>
                  <th>Doctor</th>
                  <th>Date & Time</th>
                  <th>Notes</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <?php foreach ($recent_appointments as $appointment): ?>
                  <tr>
                    <td>
                      <strong><?php echo htmlspecialchars($appointment['patient_name']); ?></strong><br>
                      <small class="text-muted"><?php echo htmlspecialchars($appointment['patient_phone']); ?></small>
                    </td>
                    <td>
                      <strong><?php echo htmlspecialchars($appointment['doctor_name']); ?></strong><br>
                      <small class="text-muted"><?php echo htmlspecialchars($appointment['specialization']); ?></small>
                    </td>
                    <td>
                      <?php echo date('M d, Y', strtotime($appointment['appointment_date'])); ?><br>
                      <small class="text-muted"><?php echo date('g:i A', strtotime($appointment['appointment_time'])); ?></small>
                    </td>
                    <td><?php echo $appointment['notes'] ? htmlspecialchars(substr($appointment['notes'],0,50)).'...' : 'No notes'; ?></td>
                    <td>
                      <a href="appointments.php?action=confirm&id=<?php echo $appointment['id']; ?>" class="btn btn-success btn-sm me-1" title="Confirm"><i class="fas fa-check"></i></a>
                      <a href="appointments.php?action=reject&id=<?php echo $appointment['id']; ?>" class="btn btn-warning btn-sm" title="Reject"><i class="fas fa-times"></i></a>
                    </td>
                  </tr>
                <?php endforeach; ?>
              </tbody>
            </table>
          </div>
          <div class="text-center mt-3">
            <a href="appointments.php" class="btn btn-primary"><i class="fas fa-eye me-2"></i>View All Appointments</a>
          </div>
        <?php endif; ?>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
