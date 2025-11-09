<?php
require_once '../config/config.php';

// Require admin login
if (!isset($_SESSION['admin_id']) || $_SESSION['user_type'] !== 'admin') {
    header('Location: ../login.php?redirect=' . urlencode($_SERVER['REQUEST_URI']));
    exit();
}

$admin_id   = $_SESSION['admin_id'];
$report_type = $_GET['type'] ?? 'overview';
$date_from   = $_GET['date_from'] ?? date('Y-m-01');
$date_to     = $_GET['date_to']   ?? date('Y-m-d');

try {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM patients"); $stmt->execute(); $total_patients = (int)$stmt->fetchColumn();
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM doctors");  $stmt->execute(); $total_doctors  = (int)$stmt->fetchColumn();
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM appointments WHERE DATE(appointment_date) BETWEEN ? AND ?");
    $stmt->execute([$date_from,$date_to]); $total_appointments = (int)$stmt->fetchColumn();
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE status = 'active'");   $stmt->execute(); $active_users   = (int)$stmt->fetchColumn();
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users WHERE status = 'inactive'"); $stmt->execute(); $inactive_users = (int)$stmt->fetchColumn();

    // status
    $stmt = $pdo->prepare("SELECT LOWER(status) status, COUNT(*) count
                           FROM appointments
                           WHERE DATE(appointment_date) BETWEEN ? AND ?
                           GROUP BY LOWER(status)");
    $stmt->execute([$date_from,$date_to]);
    $appointments_by_status = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // by doctor
    $stmt = $pdo->prepare("SELECT d.name doctor_name, d.specialization, COUNT(a.id) appointment_count
                           FROM doctors d
                           LEFT JOIN appointments a ON d.id=a.doctor_id
                                AND DATE(a.appointment_date) BETWEEN ? AND ?
                           GROUP BY d.id,d.name,d.specialization
                           ORDER BY appointment_count DESC");
    $stmt->execute([$date_from,$date_to]);
    $appointments_by_doctor = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // last 7 days
    $stmt = $pdo->prepare("SELECT DATE(appointment_date) date, COUNT(*) count
                           FROM appointments
                           WHERE DATE(appointment_date) >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
                           GROUP BY DATE(appointment_date)
                           ORDER BY date ASC");
    $stmt->execute();
    $daily_appointments = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // feedback summary
    $stmt = $pdo->prepare("SELECT AVG(rating) avg_rating, COUNT(*) total_feedback
                           FROM feedback
                           WHERE DATE(created_at) BETWEEN ? AND ?");
    $stmt->execute([$date_from,$date_to]);
    $feedback_stats = $stmt->fetch(PDO::FETCH_ASSOC) ?: ['avg_rating'=>0,'total_feedback'=>0];

    $stmt = $pdo->prepare("SELECT f.*, p.name patient_name, d.name doctor_name
                           FROM feedback f
                           JOIN patients p ON f.patient_id=p.id
                           JOIN doctors d  ON f.doctor_id=d.id
                           WHERE DATE(f.created_at) BETWEEN ? AND ?
                           ORDER BY f.created_at DESC
                           LIMIT 10");
    $stmt->execute([$date_from,$date_to]);
    $recent_feedback = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error_message = 'Error generating reports: '.$e->getMessage();
    $total_patients=$total_doctors=$total_appointments=$active_users=$inactive_users=0;
    $appointments_by_status=$appointments_by_doctor=$daily_appointments=$recent_feedback=[];
    $feedback_stats=['avg_rating'=>0,'total_feedback'=>0];
}

/* ---------- Chart payloads ---------- */
$fixed = ['pending'=>0,'confirmed'=>0,'cancelled'=>0,'rejected'=>0]; $others=0;
foreach ($appointments_by_status as $row) { $k=$row['status']; $c=(int)$row['count']; if(isset($fixed[$k])) $fixed[$k]=$c; else $others+=$c; }
$pie_labels = ['Pending','Confirmed','Cancelled','Rejected'];
$pie_values = array_values($fixed);
if ($others>0) { $pie_labels[]='Others'; $pie_values[]=$others; }

$map=[]; for($i=6;$i>=0;$i--){ $d=date('Y-m-d',strtotime("-{$i} days")); $map[$d]=0; }
foreach ($daily_appointments as $r){ if(isset($map[$r['date']])) $map[$r['date']]=(int)$r['count']; }
$daily_labels = array_map(fn($d)=>date('M j', strtotime($d)), array_keys($map));
$daily_values = array_values($map);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reports - <?php echo APP_NAME; ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
<style>
:root{--primary-color:#2563EB;--secondary-color:#334155;--accent-color:#7C3AED;--background-color:#F9FAFB;--text-color:#111827;}
body{background:var(--background-color);color:var(--text-color);font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;}

/* Sidebar */
.sidebar{
  background:var(--secondary-color);
  width:250px; min-height:100vh; position:fixed; top:0; left:0; z-index:1040;
  transition:transform .25s ease-in-out;
}
.sidebar .nav-link{color:#fff;padding:12px 20px;border-radius:0;}
.sidebar .nav-link:hover,.sidebar .nav-link.active{background:var(--primary-color);color:#fff;}
        .logo { padding: 20px; text-align: center; border-bottom: 1px solid #475569; margin-bottom: 20px; }
        .logo h4 { color: #fff; margin: 0; }
.sidebar .nav-link i{width:20px;margin-right:10px;}
/* Mobile: hidden by default, slide in when .open */
@media (max-width: 992px){
  .sidebar{transform:translateX(-100%);}
  .sidebar.open{transform:translateX(0);}
}

/* Main content */
.main-content{margin-left:250px; transition:margin-left .25s;}
@media (max-width: 992px){
  .main-content{margin-left:0;}
}

/* Top bar */
.top-navbar{background:var(--primary-color);color:#fff;padding:12px 16px;box-shadow:0 2px 4px rgba(0,0,0,.1);}
.top-navbar h3{font-size:1.1rem;}
/* hamburger only on mobile */
#sidebarToggle{display:none;}
@media (max-width: 992px){ #sidebarToggle{display:inline-flex;} }

/* Page content */
.content-area{padding:18px 16px;}
.report-card{background:#fff;border-radius:14px;padding:25px;box-shadow:0 4px 6px rgba(0,0,0,.05);border:none;margin-bottom:16px;}
/* Compact chart cards */
.report-card.compact{padding:14px 14px 16px;}
.report-card.compact h5{font-size:1rem;margin-bottom:.75rem;}

/* Charts */
.chart-wrap{width:100%;aspect-ratio:4/3;min-height:150px;max-height:220px;}
@media (max-width: 575.98px){ .chart-wrap{aspect-ratio:1/1;min-height:160px;max-height:220px;} }

/* Stats */
.stat-card{background:#fff;border-radius:15px;padding:18px;box-shadow:0 4px 6px rgba(0,0,0,.05);text-align:center;}
.stat-number{font-size:2rem;font-weight:700;color:var(--primary-color);}
.stat-label{color:#6B7280;font-size:.8rem;text-transform:uppercase;letter-spacing:.5px;}
.stat-icon{font-size:1.6rem;color:var(--accent-color);margin-bottom:10px;}
.table th{background:var(--background-color);border-top:none;font-weight:600;}
.progress{height:8px;}
.rating-stars{color:#FCD34D;}

/* Backdrop for mobile sidebar */
#sidebarBackdrop{
  display:none; position:fixed; inset:0; background:rgba(0,0,0,.35); z-index:1035;
}
#sidebarBackdrop.show{display:block;}
</style>
</head>
<body>

<!-- Sidebar -->
<div class="sidebar" id="appSidebar">
   <div class="logo">
            <h4><i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?></h4>
        </div>
  <nav class="nav flex-column">
    <a class="nav-link" href="dashboard.php"><i class="fas fa-tachometer-alt"></i>Dashboard</a>
    <a class="nav-link" href="profile.php"><i class="fas fa-user"></i>Profile</a>
    <a class="nav-link" href="users.php"><i class="fas fa-users"></i>User Accounts</a>
    <a class="nav-link active" href="reports.php"><i class="fas fa-chart-bar"></i>Reports</a>
     <a class="nav-link" href="departments.php"><i class="fas fa-building"></i>Departments</a>
     <a class="nav-link" href="specializations.php"><i class="fas fa-building"></i>Specializations</a>
    <a class="nav-link" href="content.php"><i class="fas fa-edit"></i>Content Management</a>
    <a class="nav-link" href="../admin_logout.php">
                <i class="fas fa-sign-out-alt"></i>Logout
            </a>
  </nav>
</div>
<div id="sidebarBackdrop"></div>

<!-- Main -->
<div class="main-content">
  <!-- Top bar -->
  <div class="top-navbar d-flex justify-content-between align-items-center flex-wrap">
    <div class="d-flex align-items-center gap-2">
      <button class="btn btn-light btn-sm d-inline-flex align-items-center" id="sidebarToggle">
        <i class="fas fa-bars"></i>
      </button>
      <h3 class="mb-0"><i class="fas fa-chart-bar me-2"></i>Reports & Analytics</h3>
      
    </div>
    <form method="GET" class="d-flex align-items-center mt-2 mt-md-0 flex-wrap gap-2">
      <input type="hidden" name="type" value="<?php echo htmlspecialchars($report_type); ?>">
      <div class="d-flex align-items-center gap-2">
        <label class="text-white">From:</label>
        <input type="date" name="date_from" value="<?php echo htmlspecialchars($date_from); ?>" class="form-control form-control-sm" style="width:150px;">
      </div>
      <div class="d-flex align-items-center gap-2">
        <label class="text-white">To:</label>
        <input type="date" name="date_to" value="<?php echo htmlspecialchars($date_to); ?>" class="form-control form-control-sm" style="width:150px;">
      </div>
      <button class="btn btn-light btn-sm"><i class="fas fa-filter me-1"></i>Filter</button>
    </form>
  </div>

  <div class="content-area">
    <!-- Overview (unchanged) -->
    <div class="row g-3 mb-2">
      <div class="col-6 col-md-3"><div class="stat-card"><div class="stat-icon"><i class="fas fa-user-injured"></i></div><div class="stat-number"><?php echo $total_patients; ?></div><div class="stat-label">Total Patients</div></div></div>
      <div class="col-6 col-md-3"><div class="stat-card"><div class="stat-icon"><i class="fas fa-user-md"></i></div><div class="stat-number"><?php echo $total_doctors; ?></div><div class="stat-label">Total Doctors</div></div></div>
      <div class="col-6 col-md-3"><div class="stat-card"><div class="stat-icon"><i class="fas fa-calendar-check"></i></div><div class="stat-number"><?php echo $total_appointments; ?></div><div class="stat-label">Appointments (Period)</div></div></div>
      <div class="col-6 col-md-3"><div class="stat-card"><div class="stat-icon"><i class="fas fa-users"></i></div><div class="stat-number"><?php echo $active_users; ?></div><div class="stat-label">Active Users</div><small class="text-muted"><?php echo $inactive_users; ?> inactive</small></div></div>
    </div>

    <!-- Compact Charts Row -->
    <div class="row g-3 mb-3">
      <div class="col-lg-6">
        <div class="report-card compact">
          <h5 class="mb-2"><i class="fas fa-chart-pie me-2"></i>Appointments by Status</h5>
          <div class="chart-wrap"><canvas id="statusChart"></canvas></div>
          <div class="mt-2">
            <?php
              $status_class=['pending'=>'warning','confirmed'=>'success','cancelled'=>'secondary','rejected'=>'danger','others'=>'dark'];
              $display = array_combine(array_map('strtolower',$pie_labels), $pie_values);
              foreach($display as $label=>$count): ?>
              <div class="d-flex justify-content-between align-items-center mb-1">
                <span class="badge bg-<?php echo $status_class[$label] ?? 'secondary'; ?>"><?php echo ucfirst($label); ?></span>
                <strong><?php echo (int)$count; ?></strong>
              </div>
            <?php endforeach; ?>
          </div>
        </div>
      </div>

      <div class="col-lg-6">
        <div class="report-card compact">
          <h5 class="mb-2"><i class="fas fa-chart-line me-2"></i>Daily Appointments (Last 7 Days)</h5>
          <div class="chart-wrap"><canvas id="dailyChart"></canvas></div>
          <div class="mt-2">
            <?php foreach (array_combine($daily_labels,$daily_values) as $label=>$val): ?>
              <div class="d-flex justify-content-between align-items-center mb-1">
                <span><?php echo htmlspecialchars($label); ?></span>
                <div class="d-flex align-items-center">
                  <div class="progress me-2" style="width:100px;">
                    <?php $maxDaily=max(1,max($daily_values)); $pct=min(100,($val/$maxDaily)*100); ?>
                    <div class="progress-bar bg-primary" style="width:<?php echo $pct; ?>%"></div>
                  </div>
                  <strong><?php echo (int)$val; ?></strong>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        </div>
      </div>
    </div>

    <!-- Below stays the same -->
    <div class="row mb-4 g-3">
      <div class="col-lg-8">
        <div class="report-card">
          <h5 class="mb-4"><i class="fas fa-user-md me-2"></i>Appointments by Doctor</h5>
          <div class="table-responsive">
            <table class="table table-hover">
              <thead><tr><th>Doctor Name</th><th>Specialization</th><th>Appointments</th><th>Performance</th></tr></thead>
              <tbody>
              <?php if (empty($appointments_by_doctor)): ?>
                <tr><td colspan="4" class="text-center py-4">
                  <i class="fas fa-user-md fa-2x text-muted mb-2"></i>
                  <p class="text-muted">No appointment data found.</p>
                </td></tr>
              <?php else:
                $max_appointments = max(array_column($appointments_by_doctor,'appointment_count'));
                foreach ($appointments_by_doctor as $doctor): ?>
                  <tr>
                    <td><strong><?php echo htmlspecialchars($doctor['doctor_name']); ?></strong></td>
                    <td><?php echo htmlspecialchars($doctor['specialization']); ?></td>
                    <td><?php echo (int)$doctor['appointment_count']; ?></td>
                    <td><div class="progress" style="width:100px;">
                      <div class="progress-bar bg-primary" style="width:<?php echo $max_appointments>0?($doctor['appointment_count']/$max_appointments)*100:0; ?>%"></div>
                    </div></td>
                  </tr>
              <?php endforeach; endif; ?>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div class="col-lg-4">
        <div class="report-card">
          <h5 class="mb-4"><i class="fas fa-star me-2"></i>Feedback Overview</h5>
          <div class="text-center mb-4">
            <div class="stat-number text-warning"><?php echo number_format((float)$feedback_stats['avg_rating'],1); ?></div>
            <div class="rating-stars mb-2">
              <?php $r=(int)round((float)$feedback_stats['avg_rating']); for($i=1;$i<=5;$i++): ?>
                <i class="fas fa-star<?php echo $i <= $r ? '' : '-o'; ?>"></i>
              <?php endfor; ?>
            </div>
            <div class="stat-label">Average Rating</div>
            <small class="text-muted"><?php echo (int)$feedback_stats['total_feedback']; ?> reviews</small>
          </div>
          <h6 class="mb-3">Recent Feedback</h6>
          <div style="max-height:300px; overflow-y:auto;">
            <?php if (empty($recent_feedback)): ?>
              <div class="text-center py-3"><i class="fas fa-comments fa-2x text-muted mb-2"></i><p class="text-muted small">No feedback found.</p></div>
            <?php else: foreach ($recent_feedback as $fb): ?>
              <div class="border-bottom pb-2 mb-2">
                <div class="d-flex justify-content-between align-items-start">
                  <div>
                    <small class="text-muted"><?php echo htmlspecialchars($fb['patient_name']); ?></small>
                    <div class="rating-stars small">
                      <?php for($i=1;$i<=5;$i++): ?><i class="fas fa-star<?php echo $i <= (int)$fb['rating'] ? '' : '-o'; ?>"></i><?php endfor; ?>
                    </div>
                  </div>
                  <small class="text-muted"><?php echo date('M j', strtotime($fb['created_at'])); ?></small>
                </div>
                <p class="small mb-1"><?php echo htmlspecialchars(substr($fb['comment'] ?? '',0,100)) . (strlen($fb['comment'] ?? '')>100?'...':''); ?></p>
                <small class="text-muted"><?php echo htmlspecialchars($fb['doctor_name']); ?></small>
              </div>
            <?php endforeach; endif; ?>
          </div>
        </div>
      </div>
    </div>

    <div class="report-card text-center">
      <h5 class="mb-4"><i class="fas fa-download me-2"></i>Export Reports</h5>
      <div class="btn-group">
        <button class="btn btn-primary" onclick="window.print()"><i class="fas fa-print me-2"></i>Print Report</button>
        <button class="btn btn-accent" onclick="alert('CSV export functionality would be implemented here')"><i class="fas fa-file-csv me-2"></i>Export CSV</button>
        <button class="btn btn-outline-primary" onclick="alert('PDF export functionality would be implemented here')"><i class="fas fa-file-pdf me-2"></i>Export PDF</button>
      </div>
    </div>
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script>
// Sidebar toggle for mobile
const sidebar   = document.getElementById('appSidebar');
const toggleBtn = document.getElementById('sidebarToggle');
const backdrop  = document.getElementById('sidebarBackdrop');
function closeSidebar(){ sidebar.classList.remove('open'); backdrop.classList.remove('show'); }
toggleBtn.addEventListener('click', () => {
  sidebar.classList.toggle('open');
  backdrop.classList.toggle('show');
});
backdrop.addEventListener('click', closeSidebar);
window.addEventListener('resize', ()=>{ if(window.innerWidth>992) closeSidebar(); });

// Chart data
const pieLabels   = <?php echo json_encode($pie_labels); ?>;
const pieValues   = <?php echo json_encode($pie_values, JSON_NUMERIC_CHECK); ?>;
const dailyLabels = <?php echo json_encode($daily_labels); ?>;
const dailyValues = <?php echo json_encode($daily_values, JSON_NUMERIC_CHECK); ?>;

// Common small chart options
const smallFont = { size: 11 };
const commonOptions = {
  responsive: true, maintainAspectRatio: false,
  devicePixelRatio: Math.min(window.devicePixelRatio || 1, 1.5),
  plugins: { legend: { labels: { font: smallFont } }, tooltip: { bodyFont: smallFont, titleFont: smallFont } }
};

// Pie
new Chart(document.getElementById('statusChart').getContext('2d'), {
  type:'pie',
  data:{ labels: pieLabels, datasets:[{ data: pieValues }] },
  options:{ ...commonOptions, plugins:{ ...commonOptions.plugins, legend:{ position:'bottom', labels:{ font: smallFont, boxWidth:10 } } } }
});

// Line
new Chart(document.getElementById('dailyChart').getContext('2d'), {
  type:'line',
  data:{ labels: dailyLabels, datasets:[{ label:'Appointments', data: dailyValues, tension:.2, borderWidth:2, pointRadius:2, pointHoverRadius:4, fill:false }] },
  options:{
    ...commonOptions, plugins:{ ...commonOptions.plugins, legend:{ display:false } },
    scales:{ x:{ ticks:{ font: smallFont, maxRotation:0 } }, y:{ beginAtZero:true, ticks:{ precision:0, stepSize:1, font: smallFont } } }
  }
});
</script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
