<?php
require_once '../config/config.php';

if (!isset($_SESSION['receptionist_id']) || $_SESSION['user_type'] !== 'receptionist') {
    header('Location: ../login.php');
    exit();
}

$receptionist_name = $_SESSION['receptionist_name'] ?? 'Receptionist';
$errors = [];
$patients = [];
$appointments_by_patient = [];

try {
    $stmt = $pdo->prepare("
        SELECT
            p.id,
            p.name,
            p.email,
            p.phone,
            p.gender,
            p.date_of_birth,
            p.address,
            p.allergy,
            p.department_id,
            p.created_at,
            d.name AS department_name,
            COALESCE(stats.total_appointments, 0) AS total_appointments,
            COALESCE(stats.upcoming_appointments, 0) AS upcoming_appointments
        FROM patients p
        LEFT JOIN departments d ON p.department_id = d.id
        LEFT JOIN (
            SELECT
                patient_id,
                COUNT(*) AS total_appointments,
                SUM(CASE
                    WHEN appointment_date >= CURDATE()
                         AND status IN ('Pending', 'Confirmed') THEN 1
                    ELSE 0
                END) AS upcoming_appointments
            FROM appointments
            GROUP BY patient_id
        ) stats ON stats.patient_id = p.id
        ORDER BY p.created_at DESC
    ");
    $stmt->execute();
    $patients = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $errors[] = 'Failed to load patient records.';
}

try {
    $stmt = $pdo->prepare('
        SELECT
            a.id,
            a.patient_id,
            a.appointment_date,
            a.appointment_time,
            a.status,
            a.notes,
            d.name AS doctor_name,
            d.specialization
        FROM appointments a
        LEFT JOIN doctors d ON a.doctor_id = d.id
        ORDER BY a.appointment_date DESC, a.appointment_time DESC
    ');
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    foreach ($rows as $row) {
        $pid = (int) $row['patient_id'];
        if (!isset($appointments_by_patient[$pid])) {
            $appointments_by_patient[$pid] = [];
        }
        $appointments_by_patient[$pid][] = $row;
    }
} catch (PDOException $e) {
    $errors[] = 'Failed to load appointment details.';
}

$total_patients = count($patients);
$total_appointments = 0;
$total_upcoming = 0;

foreach ($patients as $index => $patient) {
    $patients[$index]['total_appointments'] = (int) ($patient['total_appointments'] ?? 0);
    $patients[$index]['upcoming_appointments'] = (int) ($patient['upcoming_appointments'] ?? 0);

    $total_appointments += $patients[$index]['total_appointments'];
    $total_upcoming += $patients[$index]['upcoming_appointments'];
}

function getStatusClass(string $status): string
{
    switch (strtolower($status)) {
        case 'pending':
            return 'status-badge status-pending';
        case 'confirmed':
            return 'status-badge status-confirmed';
        case 'completed':
            return 'status-badge status-completed';
        case 'cancelled':
            return 'status-badge status-cancelled';
        case 'rejected':
            return 'status-badge status-rejected';
        default:
            return 'status-badge';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Patients - <?php echo APP_NAME; ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<style>
:root {
  --primary:#42A5F5;
  --primary-dark:#1976D2;
  --secondary:#81C784;
  --accent:#FFB74D;
  --bg:#FAFAFA;
  --text:#212121;
  --muted:#6b7280;
  --card-shadow:0 6px 24px rgba(0,0,0,.06);
}
body {
  background:var(--bg);
  color:var(--text);
  font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial;
}
.navbar {
  background:linear-gradient(135deg,var(--primary),var(--primary-dark)) !important;
  box-shadow:0 2px 10px rgba(0,0,0,.08);
}
.navbar-brand,
.navbar .nav-link {
  color:#fff !important;
}
.page-title {
  font-weight:800;
  color:var(--primary);
  margin:1rem 0 1.25rem;
}
.summary-card {
  border:none;
  border-radius:16px;
  box-shadow:var(--card-shadow);
  padding:1.6rem 1.4rem;
  background:#fff;
  height:100%;
}
.summary-icon {
  font-size:2rem;
  margin-bottom:.75rem;
  color:var(--primary);
}
.summary-value {
  font-weight:700;
  font-size:1.9rem;
}
.summary-label {
  font-size:.9rem;
  color:var(--muted);
  margin:0;
}
.patient-accordion .accordion-item {
  border:none;
  border-radius:18px;
  margin-bottom:1.2rem;
  overflow:hidden;
  box-shadow:var(--card-shadow);
}
.patient-accordion .accordion-button {
  background:#fff;
  font-weight:600;
  padding:1.25rem 1.5rem;
  gap:1rem;
}
.patient-accordion .accordion-button:not(.collapsed) {
  color:var(--primary);
  box-shadow:inset 0 -1px 0 rgba(0,0,0,0.05);
}
.patient-meta {
  color:var(--muted);
  font-size:.9rem;
}
.info-chip {
  display:inline-flex;
  align-items:center;
  background:#eef2ff;
  color:#1d4ed8;
  border-radius:999px;
  padding:.35rem .75rem;
  margin-right:.4rem;
  font-size:.8rem;
  font-weight:600;
}
.section-title {
  font-weight:700;
  color:var(--primary-dark);
  margin-bottom:.75rem;
}
.detail-card {
  background:#f8fafc;
  border-radius:14px;
  padding:1rem 1.25rem;
  height:100%;
}
.detail-card h6 {
  font-weight:700;
  color:#0f172a;
  margin-bottom:.75rem;
}
.detail-list {
  list-style:none;
  padding:0;
  margin:0;
}
.detail-list li {
  display:flex;
  justify-content:space-between;
  align-items:center;
  padding:.35rem 0;
  font-size:.95rem;
}
.detail-list span.label {
  color:var(--muted);
}
.status-badge {
  padding:.35rem .6rem;
  border-radius:999px;
  font-size:.8rem;
  font-weight:700;
  display:inline-flex;
  align-items:center;
  gap:.35rem;
}
.status-pending { background:#fff3cd; color:#7a5d00; }
.status-confirmed { background:#e8f5e9; color:#1b5e20; }
.status-completed { background:#e0f2fe; color:#0c4a6e; }
.status-cancelled { background:#fee2e2; color:#991b1b; }
.status-rejected { background:#fdecec; color:#b91c1c; }
.table thead th {
  border-bottom:1px solid #e5e7eb;
  font-weight:700;
}
.table tbody td {
  vertical-align:middle;
}
.badge-pill {
  border-radius:999px;
  padding:.35rem .6rem;
  font-weight:600;
}
.empty-state {
  background:#fff;
  border-radius:18px;
  padding:2.5rem 1.5rem;
  text-align:center;
  color:var(--muted);
  box-shadow:var(--card-shadow);
}
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark">
  <div class="container">
    <a class="navbar-brand" href="dashboard.php"><i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?></a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav me-auto">
        <li class="nav-item"><a class="nav-link" href="dashboard.php"><i class="fas fa-tachometer-alt me-1"></i>Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>Appointments</a></li>
        <li class="nav-item"><a class="nav-link active" href="patients.php"><i class="fas fa-users me-1"></i>Patients</a></li>
        <li class="nav-item"><a class="nav-link" href="profile.php"><i class="fas fa-user me-1"></i>Profile</a></li>
      </ul>
      <ul class="navbar-nav">
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
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

<div class="container mt-3 mb-5">
  <h1 class="page-title"><i class="fas fa-users me-2"></i>Registered Patients</h1>
  <p class="text-muted">Overview of patient profiles along with their appointment history.</p>

  <?php if (!empty($errors)): ?>
    <div class="alert alert-danger">
      <i class="fas fa-exclamation-triangle me-2"></i>
      <ul class="mb-0">
        <?php foreach ($errors as $error): ?>
          <li><?php echo htmlspecialchars($error); ?></li>
        <?php endforeach; ?>
      </ul>
    </div>
  <?php endif; ?>

  <div class="row g-3 mb-4">
    <div class="col-md-4">
      <div class="summary-card text-center">
        <div class="summary-icon"><i class="fas fa-users"></i></div>
        <div class="summary-value"><?php echo number_format($total_patients); ?></div>
        <p class="summary-label">Total Registered Patients</p>
      </div>
    </div>
    <div class="col-md-4">
      <div class="summary-card text-center">
        <div class="summary-icon" style="color:var(--secondary);"><i class="fas fa-calendar-alt"></i></div>
        <div class="summary-value"><?php echo number_format($total_appointments); ?></div>
        <p class="summary-label">Total Appointments</p>
      </div>
    </div>
    <div class="col-md-4">
      <div class="summary-card text-center">
        <div class="summary-icon" style="color:var(--accent);"><i class="fas fa-bell"></i></div>
        <div class="summary-value"><?php echo number_format($total_upcoming); ?></div>
        <p class="summary-label">Upcoming Visits</p>
      </div>
    </div>
  </div>

  <?php if (empty($patients)): ?>
    <div class="empty-state">
      <i class="fas fa-clipboard-list fa-2x mb-3"></i>
      <h5 class="fw-bold">No patients registered yet</h5>
      <p class="mb-0">New patient registrations will appear here once patients sign up.</p>
    </div>
  <?php else: ?>
    <div class="patient-accordion accordion" id="patientsAccordion">
      <?php foreach ($patients as $idx => $patient): ?>
        <?php
          $patient_id = (int) $patient['id'];
          $patient_appointments = $appointments_by_patient[$patient_id] ?? [];
          $has_allergy = !empty($patient['allergy']);
          $age = !empty($patient['date_of_birth']) ? calculateAge($patient['date_of_birth']) : null;
        ?>
        <div class="accordion-item">
          <h2 class="accordion-header" id="heading-<?php echo $patient_id; ?>">
            <button class="accordion-button <?php echo $idx === 0 ? '' : 'collapsed'; ?>" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-<?php echo $patient_id; ?>" aria-expanded="<?php echo $idx === 0 ? 'true' : 'false'; ?>" aria-controls="collapse-<?php echo $patient_id; ?>">
              <div class="w-100">
                <div class="d-flex flex-wrap justify-content-between align-items-center mb-2 gap-2">
                  <span class="h5 mb-0"><?php echo htmlspecialchars($patient['name']); ?></span>
                  <div class="d-flex flex-wrap gap-2">
                    <span class="info-chip"><i class="fas fa-calendar me-1"></i><?php echo $patient['total_appointments']; ?> total</span>
                    <span class="info-chip" style="background:#ecfdf5;color:#047857;"><i class="fas fa-arrow-trend-up me-1"></i><?php echo $patient['upcoming_appointments']; ?> upcoming</span>
                  </div>
                </div>
                <div class="patient-meta">
                  <i class="fas fa-envelope me-1"></i><?php echo htmlspecialchars($patient['email']); ?>
                  <span class="mx-2">•</span>
                  <i class="fas fa-phone me-1"></i><?php echo htmlspecialchars($patient['phone']); ?>
                  <span class="mx-2">•</span>
                  Registered <?php echo !empty($patient['created_at']) ? formatDateTime($patient['created_at'], 'M d, Y') : 'N/A'; ?>
                </div>
              </div>
            </button>
          </h2>
          <div id="collapse-<?php echo $patient_id; ?>" class="accordion-collapse collapse <?php echo $idx === 0 ? 'show' : ''; ?>" aria-labelledby="heading-<?php echo $patient_id; ?>" data-bs-parent="#patientsAccordion">
            <div class="accordion-body bg-white">
              <div class="row g-3 mb-4">
                <div class="col-md-6">
                  <div class="detail-card h-100">
                    <h6><i class="fas fa-id-card me-2"></i>Personal Information</h6>
                    <ul class="detail-list">
                      <li><span class="label">Gender</span><span><?php echo htmlspecialchars($patient['gender']); ?></span></li>
                      <li><span class="label">Date of Birth</span><span><?php echo !empty($patient['date_of_birth']) ? formatDate($patient['date_of_birth']) : 'Not provided'; ?></span></li>
                      <li><span class="label">Age</span><span><?php echo $age !== null ? $age . ' years' : '—'; ?></span></li>
                      
                    </ul>
                  </div>
                </div>
                <div class="col-md-6">
                  <div class="detail-card h-100">
                    <h6><i class="fas fa-location-dot me-2"></i>Contact & Health</h6>
                    <ul class="detail-list">
                      <li><span class="label">Phone</span><span><?php echo htmlspecialchars($patient['phone']); ?></span></li>
                      <li><span class="label">Email</span><span><?php echo htmlspecialchars($patient['email']); ?></span></li>
                      <li class="d-flex flex-column align-items-start">
                        <span class="label">Address</span>
                        <span><?php echo nl2br(htmlspecialchars($patient['address'])); ?></span>
                      </li>
                      <li class="d-flex flex-column align-items-start">
                        <span class="label">Allergies</span>
                        <span><?php echo $has_allergy ? nl2br(htmlspecialchars($patient['allergy'])) : 'None reported'; ?></span>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>

              <h5 class="section-title"><i class="fas fa-calendar-check me-2"></i>Appointment History</h5>
              <?php if (empty($patient_appointments)): ?>
                <div class="alert alert-light border"><i class="fas fa-info-circle me-2"></i>No appointments found for this patient.</div>
              <?php else: ?>
                <div class="table-responsive">
                  <table class="table align-middle">
                    <thead>
                      <tr>
                        <th scope="col">Date</th>
                        <th scope="col">Time</th>
                        <th scope="col">Doctor</th>
                        <th scope="col">Status</th>
                        <th scope="col">Notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      <?php foreach ($patient_appointments as $appointment): ?>
                        <tr>
                          <td><?php echo !empty($appointment['appointment_date']) ? formatDate($appointment['appointment_date']) : '—'; ?></td>
                          <td><?php echo !empty($appointment['appointment_time']) ? formatTime($appointment['appointment_time']) : '—'; ?></td>
                          <td>
                            <?php echo htmlspecialchars($appointment['doctor_name'] ?? 'Unknown Doctor'); ?>
                            <?php if (!empty($appointment['specialization'])): ?>
                              <span class="badge rounded-pill text-bg-light ms-2"><?php echo htmlspecialchars($appointment['specialization']); ?></span>
                            <?php endif; ?>
                          </td>
                          <td>
                            <span class="<?php echo getStatusClass($appointment['status'] ?? ''); ?>">
                              <i class="fas fa-circle"></i><?php echo htmlspecialchars($appointment['status']); ?>
                            </span>
                          </td>
                          <td class="text-muted" style="max-width:220px;">
                            <?php echo !empty($appointment['notes']) ? nl2br(htmlspecialchars($appointment['notes'])) : '<span class="text-muted">—</span>'; ?>
                          </td>
                        </tr>
                      <?php endforeach; ?>
                    </tbody>
                  </table>
                </div>
              <?php endif; ?>
            </div>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>