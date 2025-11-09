<?php
require_once '../config/config.php';

// Check if user is logged in as receptionist
if (!isset($_SESSION['receptionist_id']) || $_SESSION['user_type'] !== 'receptionist') {
    header('Location: ../login.php');
    exit();
}

$success_message = '';
$errors = [];

/* ---------------------------------------
   Actions: Confirm / Reject appointment
---------------------------------------- */
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid security token. Please try again.';
    } else {
        $action = $_POST['action'] ?? '';
        $appointment_id = (int)($_POST['appointment_id'] ?? 0);

        if (in_array($action, ['confirm', 'reject'], true)) {
            if ($appointment_id > 0) {
                try {
                    if ($action === 'confirm') {
                        $stmt = $pdo->prepare("
                            UPDATE appointments 
                            SET status = 'Confirmed' 
                            WHERE id = ? AND LOWER(status) = 'pending'
                        ");
                        $stmt->execute([$appointment_id]);
                        $success_message = $stmt->rowCount() > 0 ? 'Appointment confirmed.' : 'Failed to confirm appointment. It may have already been processed.';
                    } else {
                        $stmt = $pdo->prepare("
                            UPDATE appointments 
                            SET status = 'Rejected' 
                            WHERE id = ? AND LOWER(status) = 'pending'
                        ");
                        $stmt->execute([$appointment_id]);
                        $success_message = $stmt->rowCount() > 0 ? 'Appointment rejected.' : 'Failed to reject appointment. It may have already been processed.';
                    }
                } catch (PDOException $e) {
                    $errors[] = 'Database error occurred. Please try again.';
                }
            } else {
                $errors[] = 'Invalid appointment ID.';
            }
        } else {
            $errors[] = 'Invalid action.';
        }
    }
}

/* ---------------------------------------
   Load Appointments (all, newest first)
---------------------------------------- */
try {
    $stmt = $pdo->prepare("
        SELECT 
            a.id, a.appointment_date, a.appointment_time, a.status, a.created_at, a.notes,
            p.name AS patient_name, p.email AS patient_email, p.phone AS patient_phone,
            d.name AS doctor_name, d.specialization
        FROM appointments a
        JOIN patients  p ON a.patient_id = p.id
        JOIN doctors   d ON a.doctor_id  = d.id
        ORDER BY a.created_at DESC
    ");
    $stmt->execute();
    $all_appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $all_appointments = [];
    $errors[] = 'Failed to load appointments.';
}

/* ---------------------------------------
   Today’s Confirmed Appointments
---------------------------------------- */
try {
    $today = date('Y-m-d');
    $stmt = $pdo->prepare("
        SELECT 
            a.id, a.appointment_date, a.appointment_time,
            p.name AS patient_name,
            d.name AS doctor_name, d.specialization
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        JOIN doctors  d ON a.doctor_id  = d.id
        WHERE a.status = 'Confirmed' AND a.appointment_date = ?
        ORDER BY a.appointment_time ASC
    ");
    $stmt->execute([$today]);
    $today_appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $today_appointments = [];
}

/* ---------------------------------------
   Read-only Doctor Availability Directory
   + Departments list for filtering
---------------------------------------- */
try {
    $dps = $pdo->query("SELECT id, name FROM departments ORDER BY name ASC");
    $departments = $dps->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $departments = [];
}

try {
    $stmt = $pdo->prepare("
        SELECT 
            d.id AS doctor_id, d.name AS doctor_name, d.specialization, d.department_id,
            dept.name AS department_name,
            da.available_day  AS day, da.start_time, da.end_time
        FROM doctors d
        LEFT JOIN departments dept ON d.department_id = dept.id
        LEFT JOIN doctor_availability da 
               ON d.id = da.doctor_id AND da.is_active = 1
        ORDER BY d.name,
                 FIELD(da.available_day, 'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'),
                 da.start_time
    ");
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $doctors_dir = [];
    foreach ($rows as $row) {
        $did = (int)$row['doctor_id'];
        if (!isset($doctors_dir[$did])) {
            $doctors_dir[$did] = [
                'id' => $did,
                'name' => $row['doctor_name'],
                'specialization' => $row['specialization'],
                'department_id' => $row['department_id'],
                'department_name' => $row['department_name'],
                'slots' => []
            ];
        }
        if (!empty($row['day'])) {
            $doctors_dir[$did]['slots'][] = [
                'day'  => $row['day'],
                'from' => $row['start_time'],
                'to'   => $row['end_time']
            ];
        }
    }
} catch (PDOException $e) {
    $doctors_dir = [];
}

$csrf_token = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Appointments - <?php echo APP_NAME; ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<style>
:root{
  --primary:#42A5F5; --primary-dark:#1976D2;
  --success:#22c55e; --warn:#FFB74D; --danger:#ef4444;
  --bg:#FAFAFA; --text:#212121; --muted:#6b7280; --chip:#f3f4f6;
  --green:#81C784;
}
html{scroll-behavior:smooth;}
body{background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,'Helvetica Neue',Arial}
.navbar{background:linear-gradient(135deg,var(--primary),var(--primary-dark)) !important;box-shadow:0 2px 10px rgba(0,0,0,.08)}
.navbar-brand,.navbar .nav-link{color:#fff !important}
.page-title{font-weight:800;color:var(--primary);margin:1rem 0 1.25rem}
.card{border:none;border-radius:16px;box-shadow:0 6px 24px rgba(0,0,0,.06)}
.card-header{border-radius:16px 16px 0 0 !important;background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#fff}
.sticky-sub{position:sticky;top:0;z-index:2;background:#fff;border-bottom:1px solid #f1f5f9}
.status-badge{padding:.35rem .6rem;border-radius:999px;font-size:.8rem;font-weight:700;display:inline-flex;align-items:center;gap:.35rem}
.status-pending{background:#fff3cd;color:#7a5d00}
.status-confirmed{background:#e8f5e9;color:#1b5e20}
.status-rejected{background:#fdecec;color:#b91c1c}
.btn-confirm{background:var(--primary);border-color:var(--primary);color:#fff;border-radius:999px;padding:.4rem .9rem}
.btn-reject{background:#fb923c;border-color:#fb923c;color:#fff;border-radius:999px;padding:.4rem .9rem}
.btn-confirm:hover{background-color:var(--primary-dark);border-color:var(--primary-dark);color:#fff}
.btn-reject:hover{background-color:#FF9800;border-color:#FF9800;color:#fff}
.table-scroll{max-height:520px;overflow-y:auto}
.table-scroll table{margin-bottom:0}
.table-scroll thead th{position:sticky;top:0;background:#fff;z-index:1}
.table thead th{font-weight:700;border-bottom:1px solid #eef2f7}
.table tbody td{vertical-align:middle}
.small-muted{color:var(--muted);font-size:.85rem}
.slot-chip{display:inline-block;background:var(--chip);border-radius:12px;padding:.35rem .6rem;margin:.15rem 0;font-size:.82rem}
.day-badge{display:inline-block;background:#eef2ff;color:#3730a3;border-radius:999px;padding:.25rem .55rem;margin-right:.35rem;font-weight:700;font-size:.75rem}
.search-wrap{display:flex;gap:.75rem;flex-wrap:wrap}
.search-wrap .form-control,.search-wrap .form-select{border-radius:999px;padding:.6rem 1rem}
.doctor-card{border:1px solid #eef2f7;border-radius:14px;padding:1rem 1.2rem;margin-bottom:1rem;transition:.2s}
.doctor-card:hover{box-shadow:0 8px 24px rgba(0,0,0,.06);transform:translateY(-1px)}
.doctor-name{font-weight:700;color:#0f172a}
.specialization{color:var(--green);font-weight:600}
.dept-pill{display:inline-block;background:#e0f2f1;color:#00695c;border-radius:999px;padding:.2rem .6rem;font-size:.72rem;font-weight:700;margin-left:.4rem}

/* highlight animation when jumping to section */
@keyframes flashBorder {
  0% { box-shadow:0 0 0 0 rgba(66,165,245,.9); }
  100% { box-shadow:0 0 0 12px rgba(66,165,245,0); }
}
.anchor-flash { animation: flashBorder 1.2s ease-out 2; }
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
        <li class="nav-item"><a class="nav-link active" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>Appointments</a></li>
        <li class="nav-item"><a class="nav-link" href="profile.php"><i class="fas fa-user me-1"></i>Profile</a></li>
      </ul>
      <ul class="navbar-nav">
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" data-bs-toggle="dropdown">
            <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($_SESSION['receptionist_name']); ?>
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

<div class="container mt-3">
  <h1 class="page-title"><i class="fas fa-calendar-check me-2"></i>Appointment Management</h1>

  <?php if ($success_message): ?>
    <div class="alert alert-success"><i class="fas fa-check-circle me-2"></i><?php echo $success_message; ?></div>
  <?php endif; ?>

  <?php if (!empty($errors)): ?>
    <div class="alert alert-danger">
      <i class="fas fa-exclamation-triangle me-2"></i>
      <ul class="mb-0"><?php foreach ($errors as $e) echo '<li>'.htmlspecialchars($e).'</li>'; ?></ul>
    </div>
  <?php endif; ?>

  <div class="row">
    <!-- Appointment Requests -->
    <div class="col-lg-8 mb-4">
      <div class="card">
        <div class="card-header">
          <h5 class="mb-0"><i class="fas fa-inbox me-2"></i>Appointment Requests (<?php echo count($all_appointments); ?>)</h5>
        </div>

        <div class="sticky-sub p-3">
          <div class="row g-2">
            <div class="col-md-4"><input id="apptSearch" type="text" class="form-control" placeholder="Search patient/doctor/specialization..."></div>
            <div class="col-md-4">
              <select id="statusFilter" class="form-select">
                <option value="">All statuses</option>
                <option value="pending">Pending</option>
                <option value="confirmed">Confirmed</option>
                <option value="rejected">Rejected</option>
              </select>
            </div>
            <div class="col-md-4 small-muted d-flex align-items-center">
              <i class="fa-regular fa-lightbulb me-2"></i>Tip: Confirm/Reject from the table actions.
            </div>
          </div>
        </div>

        <div class="card-body">
          <?php if (empty($all_appointments)): ?>
            <div class="text-center py-5 small-muted">
              <i class="fas fa-calendar-check fa-3x mb-3 opacity-50"></i>
              <div>No appointment requests found.</div>
            </div>
          <?php else: ?>
            <div class="table-responsive table-scroll">
              <table class="table" id="appointmentsTable">
                <thead>
                  <tr>
                    <th>Patient</th>
                    <th>Doctor</th>
                    <th>Date &amp; Time</th>
                    <th>Reason</th>
                    <th>Requested</th>
                    <th>Status / Actions</th>
                  </tr>
                </thead>
                <tbody>
                <?php foreach ($all_appointments as $a): ?>
                  <tr data-status="<?php echo strtolower($a['status']); ?>">
                    <td>
                      <strong><?php echo htmlspecialchars($a['patient_name']); ?></strong><br>
                      <span class="small-muted"><i class="fas fa-envelope me-1"></i><?php echo htmlspecialchars($a['patient_email']); ?> · <i class="fas fa-phone me-1"></i><?php echo htmlspecialchars($a['patient_phone']); ?></span>
                    </td>
                    <td>
                      <strong><?php echo htmlspecialchars($a['doctor_name']); ?></strong><br>
                      <span class="small-muted"><?php echo htmlspecialchars($a['specialization']); ?></span>
                    </td>
                    <td>
                      <strong><?php echo date('M d, Y', strtotime($a['appointment_date'])); ?></strong><br>
                      <span class="small-muted"><?php echo date('h:i A', strtotime($a['appointment_time'])); ?></span>
                    </td>
                    <td><?php echo !empty($a['notes']) ? '<span class="small-muted">'.htmlspecialchars($a['notes']).'</span>' : '<span class="small-muted">—</span>'; ?></td>
                    <td class="small-muted"><?php echo date('M d, h:i A', strtotime($a['created_at'])); ?></td>
                    <td>
                      <?php $st = strtolower($a['status']); ?>
                      <?php if ($st === 'pending'): ?>
                        <div class="d-flex gap-2">
                          <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="appointment_id" value="<?php echo $a['id']; ?>">
                            <input type="hidden" name="action" value="confirm">
                            <button class="btn btn-confirm btn-sm" onclick="return confirm('Confirm this appointment?')"><i class="fas fa-check me-1"></i>Confirm</button>
                          </form>
                          <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                            <input type="hidden" name="appointment_id" value="<?php echo $a['id']; ?>">
                            <input type="hidden" name="action" value="reject">
                            <button class="btn btn-reject btn-sm" onclick="return confirm('Reject this appointment?')"><i class="fas fa-times me-1"></i>Reject</button>
                          </form>
                        </div>
                      <?php elseif ($st === 'confirmed'): ?>
                        <span class="status-badge status-confirmed"><i class="fa-solid fa-circle-check"></i> Confirmed</span>
                      <?php elseif ($st === 'rejected'): ?>
                        <span class="status-badge status-rejected"><i class="fa-solid fa-circle-xmark"></i> Rejected</span>
                      <?php else: ?>
                        <span class="status-badge" style="background:#f1f5f9;color:#111827"><?php echo htmlspecialchars($a['status']); ?></span>
                      <?php endif; ?>
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

    <!-- Today's Confirmed -->
    <div class="col-lg-4 mb-4">
      <div class="card">
        <div class="card-header"><h5 class="mb-0"><i class="fas fa-calendar-day me-2"></i>Today’s Appointments</h5></div>
        <div class="card-body">
          <?php if (empty($today_appointments)): ?>
            <div class="text-center py-4 small-muted">
              <i class="fas fa-calendar-day fa-2x mb-2 opacity-50"></i>
              <div>No confirmed appointments for today.</div>
            </div>
          <?php else: ?>
            <?php foreach ($today_appointments as $t): ?>
              <div class="d-flex justify-content-between align-items-center mb-3 p-2 bg-light rounded">
                <div>
                  <strong class="d-block"><?php echo htmlspecialchars($t['patient_name']); ?></strong>
                  <span class="small-muted"><?php echo htmlspecialchars($t['doctor_name']); ?> · <?php echo date('h:i A', strtotime($t['appointment_time'])); ?></span>
                </div>
                <span class="status-badge status-confirmed">Confirmed</span>
              </div>
            <?php endforeach; ?>
          <?php endif; ?>
        </div>
      </div>
    </div>
  </div>

  <!-- Doctor Availability (anchor target) -->
  <div class="card mb-5" id="doctor-availability">
    <div class="card-header">
      <h5 class="mb-0"><i class="fas fa-user-md me-2"></i>Doctor Availability Directory</h5>
    </div>
    <div class="p-3 sticky-sub">
      <div class="search-wrap">
        <input id="docSearch" class="form-control" placeholder="Search doctor or specialization">
        <select id="deptFilter" class="form-select">
          <option value="">All departments</option>
          <?php foreach ($departments as $dep): ?>
            <option value="<?php echo (int)$dep['id']; ?>"><?php echo htmlspecialchars($dep['name']); ?></option>
          <?php endforeach; ?>
        </select>
        <select id="dayFilter" class="form-select">
          <option value="">Any day</option>
          <option>Monday</option><option>Tuesday</option><option>Wednesday</option>
          <option>Thursday</option><option>Friday</option><option>Saturday</option><option>Sunday</option>
        </select>
      </div>
    </div>
    <div class="card-body" id="doctorsList">
      <?php if (empty($doctors_dir)): ?>
        <div class="text-center py-5 small-muted">
          <i class="fas fa-user-md fa-3x mb-3 opacity-50"></i>
          <div>No doctor availability found.</div>
        </div>
      <?php else: ?>
        <div class="row" id="doctorCards">
          <?php foreach ($doctors_dir as $doc): ?>
            <div class="col-md-6 col-lg-4 doc-item"
                 data-name="<?php echo strtolower($doc['name']); ?>"
                 data-spec="<?php echo strtolower($doc['specialization']); ?>"
                 data-dept-id="<?php echo (int)$doc['department_id']; ?>"
                 data-dept-name="<?php echo strtolower((string)$doc['department_name']); ?>">
              <div class="doctor-card">
                <div class="d-flex justify-content-between align-items-start">
                  <div>
                    <div class="doctor-name"><?php echo htmlspecialchars($doc['name']); ?></div>
                    <div class="specialization">
                      <i class="fas fa-stethoscope me-1"></i><?php echo htmlspecialchars($doc['specialization']); ?>
                      <?php if (!empty($doc['department_name'])): ?>
                        <span class="dept-pill"><i class="fas fa-building me-1"></i><?php echo htmlspecialchars($doc['department_name']); ?></span>
                      <?php endif; ?>
                    </div>
                  </div>
                </div>
                <div class="mt-2">
                  <?php if (empty($doc['slots'])): ?>
                    <span class="small-muted">No active availability set.</span>
                  <?php else: ?>
                    <?php 
                      $byDay = [];
                      foreach ($doc['slots'] as $s) { $byDay[$s['day']][] = $s; }
                      foreach ($byDay as $day => $slots) {
                        echo '<div class="mb-1 day-block" data-day="'.htmlspecialchars($day).'">';
                        echo '<span class="day-badge">'.htmlspecialchars($day).'</span> ';
                        $chips = [];
                        foreach ($slots as $s) {
                          $chips[] = '<span class="slot-chip">'.date('g:i A', strtotime($s["from"])) .' - '. date('g:i A', strtotime($s["to"])) .'</span>';
                        }
                        echo implode(' ', $chips);
                        echo '</div>';
                      }
                    ?>
                  <?php endif; ?>
                </div>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
/* Appointments table filters */
(function(){
  const q = document.getElementById('apptSearch');
  const sf = document.getElementById('statusFilter');
  const rows = Array.from(document.querySelectorAll('#appointmentsTable tbody tr'));
  function apply(){
    const term = (q.value||'').toLowerCase();
    const status = (sf.value||'').toLowerCase();
    rows.forEach(tr=>{
      const text = tr.innerText.toLowerCase();
      const st = tr.getAttribute('data-status') || '';
      const okTerm = !term || text.includes(term);
      const okStatus = !status || st === status;
      tr.style.display = (okTerm && okStatus) ? '' : 'none';
    });
  }
  if(q) q.addEventListener('input', apply);
  if(sf) sf.addEventListener('change', apply);
})();

/* Doctor directory filters */
(function(){
  const input = document.getElementById('docSearch');
  const daySel = document.getElementById('dayFilter');
  const deptSel = document.getElementById('deptFilter');
  const cards = Array.from(document.querySelectorAll('#doctorCards .doc-item'));

  function matchesDay(card, wantedDay){
    if(!wantedDay) return true;
    const blocks = card.querySelectorAll('.day-block');
    for(const b of blocks){ if(b.dataset.day === wantedDay) return true; }
    return false;
  }
  function matchesDept(card, deptId){
    if(!deptId) return true;
    return (card.dataset.deptId || '') === String(deptId);
  }
  function apply(){
    const term = (input.value||'').toLowerCase();
    const wantedDay  = daySel.value;
    const wantedDept = deptSel.value;
    cards.forEach(c=>{
      const name = c.dataset.name || '';
      const spec = c.dataset.spec || '';
      const okTerm = !term || name.includes(term) || spec.includes(term);
      const okDay  = matchesDay(c, wantedDay);
      const okDept = matchesDept(c, wantedDept);
      c.style.display = (okTerm && okDay && okDept) ? '' : 'none';
    });
  }
  if(input) input.addEventListener('input', apply);
  if(daySel) daySel.addEventListener('change', apply);
  if(deptSel) deptSel.addEventListener('change', apply);
})();

/* If the page was opened with #doctor-availability, flash/highlight that section */
(function(){
  const id = 'doctor-availability';
  if (location.hash === '#'+id) {
    const el = document.getElementById(id);
    if (el) {
      // slight delay so browser scrolls first
      setTimeout(()=>{ el.classList.add('anchor-flash'); }, 120);
      // remove the effect after a bit
      setTimeout(()=>{ el.classList.remove('anchor-flash'); }, 2500);
    }
  }
})();
</script>
</body>
</html>
