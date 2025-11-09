<?php
require_once 'config/config.php';

// Require login
requireLogin();

$patient_id = getCurrentPatientId();
$doctor_id = (int)($_GET['doctor_id'] ?? 0);
$errors = [];
$success_message = '';

if ($doctor_id <= 0) {
    header('Location: doctors.php');
    exit();
}

// ------- Helpers -------
/**
 * Generate 24h time slots (e.g. "10:02", "10:32") between start/end (H:i:s) inclusive,
 * at $interval minutes.
 */
function generateSlots24(string $startHms, string $endHms, int $intervalMinutes = 30): array {
    $slots = [];
    try {
        $start = DateTime::createFromFormat('H:i:s', $startHms);
        $end   = DateTime::createFromFormat('H:i:s', $endHms);
        if (!$start || !$end) return $slots;
        $cursor = clone $start;
        while ($cursor <= $end) {
            $slots[] = $cursor->format('H:i');
            $cursor->modify("+{$intervalMinutes} minutes");
        }
    } catch (Throwable $e) {
        // ignore
    }
    return $slots;
}

/** Normalize a UI time value (like "10:32" or "10:32 AM") to H:i:s */
function normalizeToHms(string $timeStr): ?string {
    $ts = strtotime($timeStr);
    if ($ts === false) return null;
    return date('H:i:s', $ts);
}

// Get doctor information
try {
    $stmt = $pdo->prepare("SELECT * FROM doctors WHERE id = ?");
    $stmt->execute([$doctor_id]);
    $doctor = $stmt->fetch();
    
    if (!$doctor) {
        header('Location: doctors.php');
        exit();
    }
} catch (PDOException $e) {
    die('Database error: ' . $e->getMessage());
}

// Get doctor's availability from doctor_availability table
try {
    $stmt = $pdo->prepare("
        SELECT available_day, start_time, end_time 
        FROM doctor_availability 
        WHERE doctor_id = ? AND is_active = 1
        ORDER BY FIELD(available_day, 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday')
    ");
    $stmt->execute([$doctor_id]);
    $availability_data = $stmt->fetchAll();

    $working_days_array = [];
    $availability_schedule = []; // ['Monday' => ['start_time'=>'HH:MM:SS','end_time'=>'HH:MM:SS'], ...]
    
    foreach ($availability_data as $availability) {
        $day = $availability['available_day'];
        $working_days_array[] = $day;
        $availability_schedule[$day] = [
            'start_time' => $availability['start_time'],
            'end_time'   => $availability['end_time']
        ];
    }
    
    $working_days_display = !empty($working_days_array) ? implode(', ', $working_days_array) : 'Not set';
} catch (PDOException $e) {
    $working_days_array = [];
    $availability_schedule = [];
    $working_days_display = 'Not available';
}

// Handle appointment booking
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Invalid security token. Please try again.';
    } else {
        $appointment_date = sanitizeInput($_POST['appointment_date'] ?? '');
        $appointment_time_raw = sanitizeInput($_POST['appointment_time'] ?? ''); // expected "HH:MM" 24h from hidden input
        $reason = sanitizeInput($_POST['reason'] ?? '');
        
        // Basic Validation
        if (empty($appointment_date)) {
            $errors[] = 'Please select an appointment date.';
        } elseif (strtotime($appointment_date) < strtotime(date('Y-m-d'))) {
            $errors[] = 'Appointment date cannot be in the past.';
        }
        if (empty($appointment_time_raw)) {
            $errors[] = 'Please select an appointment time.';
        }
        if (empty($reason)) {
            $errors[] = 'Please provide a reason for the appointment.';
        }

        // Convert to H:i:s for comparisons/DB
        $appointment_time_hms = normalizeToHms($appointment_time_raw);
        if (!$appointment_time_hms) {
            $errors[] = 'Invalid appointment time format.';
        }

        // Check working day
        if (empty($errors) && !empty($appointment_date)) {
            $selected_day = date('l', strtotime($appointment_date));
            if (!in_array($selected_day, $working_days_array)) {
                $errors[] = 'Doctor is not available on ' . $selected_day . 's.';
            }
        }

        // Check within working hours for that day
        if (empty($errors) && !empty($appointment_date) && $appointment_time_hms) {
            $selected_day = date('l', strtotime($appointment_date));
            if (isset($availability_schedule[$selected_day])) {
                $day_schedule = $availability_schedule[$selected_day];
                $start_hms = $day_schedule['start_time']; // H:i:s
                $end_hms   = $day_schedule['end_time'];   // H:i:s

                // Compare times as strings (same format)
                $slot_hm  = substr($appointment_time_hms, 0, 5); // H:i for UX + conflict
                $start_hm = substr($start_hms, 0, 5);
                $end_hm   = substr($end_hms, 0, 5);

                if ($slot_hm < $start_hm || $slot_hm > $end_hm) {
                    $start_formatted = date('g:i A', strtotime($start_hms));
                    $end_formatted   = date('g:i A', strtotime($end_hms));
                    $errors[] = 'Selected time is outside the working hours for ' . $selected_day . ' (' . $start_formatted . ' - ' . $end_formatted . ').';
                }
            }
        }

        // Block booking in the past (same-day slots earlier than now)
        if (empty($errors) && $appointment_time_hms) {
            $selected_dt = strtotime($appointment_date . ' ' . $appointment_time_hms);
            if ($selected_dt === false || $selected_dt < time()) {
                $errors[] = 'The selected time has already passed. Please choose a future time.';
            }
        }

        // Check for existing appointments at the same time (Pending/Confirmed block)
        if (empty($errors)) {
            try {
                $stmt = $pdo->prepare("
                    SELECT id FROM appointments 
                    WHERE doctor_id = ? AND appointment_date = ? AND appointment_time = ? 
                      AND LOWER(status) IN ('pending', 'confirmed')
                    LIMIT 1
                ");
                // Store appointment_time in H:i:s; if your DB column is TIME this is correct.
                $stmt->execute([$doctor_id, $appointment_date, $appointment_time_hms]);
                if ($stmt->fetch()) {
                    $errors[] = 'This time slot is already booked. Please select another time.';
                }
            } catch (PDOException $e) {
                $errors[] = 'Database error. Please try again.';
            }
        }

        // Book the appointment if no errors
        if (empty($errors)) {
            try {
                $stmt = $pdo->prepare("
                    INSERT INTO appointments (patient_id, doctor_id, appointment_date, appointment_time, notes, status, created_at) 
                    VALUES (?, ?, ?, ?, ?, 'Pending', NOW())
                ");
                $stmt->execute([$patient_id, $doctor_id, $appointment_date, $appointment_time_hms, $reason]);
                
                $success_message = 'Appointment booked successfully! You will receive a confirmation shortly.';
                $_POST = [];
            } catch (PDOException $e) {
                $errors[] = 'Failed to book appointment. Please try again.';
            }
        }
    }
}

// Generate available time slots for each day (24h values for logic)
$all_time_slots = []; // e.g. ['Monday' => ['10:02','10:32',...], ...]
foreach ($availability_schedule as $day => $schedule) {
    $all_time_slots[$day] = generateSlots24($schedule['start_time'], $schedule['end_time'], 30);
}

$csrf_token = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Book Appointment - <?php echo htmlspecialchars($doctor['name']); ?> - <?php echo APP_NAME; ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary-color: <?php echo COLOR_PRIMARY; ?>;
            --secondary-color: <?php echo COLOR_SECONDARY; ?>;
            --accent-color: <?php echo COLOR_ACCENT; ?>;
            --background-color: <?php echo COLOR_BACKGROUND; ?>;
            --text-color: <?php echo COLOR_TEXT; ?>;
        }
        body { background-color: var(--background-color); color: var(--text-color); font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .navbar { background: linear-gradient(135deg, var(--primary-color), #00796b) !important; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .navbar-brand { font-weight: 700; font-size: 1.5rem; }
        .navbar-nav .nav-link { color: white !important; font-weight: 500; margin: 0 10px; transition: all .3s ease; }
        .navbar-nav .nav-link:hover { color: var(--secondary-color) !important; }
        .hospital-card { background: white; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); border: none; }
        .booking-header { background: linear-gradient(135deg, var(--primary-color), #00796b); color: white; padding: 2rem 0; position: relative; overflow: hidden; }
        .booking-header::before { content:''; position:absolute; inset:0; background:url('https://images.unsplash.com/photo-1576091160550-2173dba999ef?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80') center/cover; opacity:.1; }
        .doctor-summary { background: rgba(255,255,255,.1); border-radius: 15px; padding: 1.5rem; backdrop-filter: blur(10px); }
        .form-control { border-radius: 15px; border: 2px solid #e0e0e0; padding: 15px 20px; }
        .form-control:focus { border-color: var(--primary-color); box-shadow: 0 0 0 .2rem rgba(0,150,136,.25); }
        .btn-primary { background-color: var(--primary-color); border-color: var(--primary-color); border-radius: 25px; padding: 12px 30px; font-weight: 600; }
        .btn-primary:hover { background-color: #00796b; border-color: #00796b; }
        .btn-secondary { background-color: var(--secondary-color); border-color: var(--secondary-color); border-radius: 25px; color: white; }
        .alert { border-radius: 15px; border: none; }
        .time-slot { display:inline-block; margin:5px; padding:10px 15px; border:2px solid var(--primary-color); border-radius:20px; background:white; color:var(--primary-color); cursor:pointer; transition:all .3s ease; font-weight:500; }
        .time-slot:hover, .time-slot.selected { background: var(--primary-color); color: white; }
        .booking-summary { background: rgba(0,150,136,.05); border-radius: 15px; padding: 2rem; margin-top: 2rem; }
        .summary-item { display:flex; justify-content:space-between; align-items:center; padding:1rem 0; border-bottom:1px solid rgba(0,150,136,.1); }
        .summary-item:last-child { border-bottom: none; }
        .summary-label { font-weight: 600; color: var(--text-color); }
        .summary-value { color: var(--primary-color); font-weight: 500; }
        .medical-icon { color: var(--primary-color); font-size: 1.2rem; margin-right: 10px; }
        .schedule-chip { display:inline-block; background:rgba(255,255,255,.15); border:1px solid rgba(255,255,255,.25); padding:.35rem .6rem; border-radius:999px; margin:.15rem; }

        #timeSlots{
    min-height: 120px;
    max-height: 360px;          /* <= choose the height you like */
    overflow-y: auto;           /* <= enables vertical scrolling */
    background: #f8f9fa;
    display: grid;              /* nice grid layout instead of long column */
    grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
    gap: 10px;
  }

  /* prettier thin scrollbar (optional) */
  #timeSlots::-webkit-scrollbar{ width: 8px; }
  #timeSlots::-webkit-scrollbar-thumb{ background:#bcd; border-radius: 8px; }
  #timeSlots::-webkit-scrollbar-track{ background: #eef3f6; }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="dashboard.php">
                <i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?>
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item"><a class="nav-link" href="dashboard.php"><i class="fas fa-home me-1"></i>Home</a></li>
                    <li class="nav-item"><a class="nav-link" href="doctors.php"><i class="fas fa-user-md me-1"></i>Find Doctors</a></li>
                    <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>My Appointments</a></li>
                    <li class="nav-item"><a class="nav-link" href="medical_history.php"><i class="fas fa-history me-1"></i>Medical History</a></li>
                </ul>
                <ul class="navbar-nav">
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($_SESSION['patient_name']); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>My Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <!-- Booking Header -->
    <div class="booking-header">
        <div class="container">
            <div class="booking-info">
                <h1 class="display-5 fw-bold mb-4">
                    <i class="fas fa-calendar-plus me-3"></i>Book Appointment
                </h1>
                
                <div class="doctor-summary">
                    <div class="row align-items-center">
                        <div class="col-md-8">
                            <h4 class="mb-2"><i class="fas fa-user-md me-2"></i> <?php echo htmlspecialchars($doctor['name']); ?></h4>
                            <p class="mb-1"><i class="fas fa-stethoscope me-2"></i><?php echo htmlspecialchars($doctor['specialization']); ?></p>
                            <p class="mb-0"><i class="fas fa-phone me-2"></i><?php echo htmlspecialchars($doctor['contact']); ?></p>
                        </div>
                        <div class="col-md-4 text-md-end">
                            <div class="mb-2"><i class="fas fa-calendar-alt me-2"></i><?php echo htmlspecialchars($working_days_display); ?></div>
                            <div>
                                <i class="fas fa-clock me-2"></i>
                                <?php if (!empty($availability_schedule)): ?>
                                    <?php foreach ($availability_schedule as $day => $sch): ?>
                                        <span class="schedule-chip">
                                            <?php echo htmlspecialchars($day); ?>:
                                            <?php echo date('g:i A', strtotime($sch['start_time'])); ?> - <?php echo date('g:i A', strtotime($sch['end_time'])); ?>
                                        </span>
                                    <?php endforeach; ?>
                                <?php else: ?>
                                    Not available
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div><!-- /doctor-summary -->
            </div>
        </div>
    </div>

    <div class="container mt-4">
        <div class="row justify-content-center">
            <div class="col-lg-8">
                <div class="card hospital-card">
                    <div class="card-body p-4">
                        <h4 class="card-title mb-4" style="color: var(--primary-color);">
                            <i class="fas fa-calendar-check me-2"></i>Schedule Your Appointment
                        </h4>

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

                        <?php if ($success_message): ?>
                            <div class="alert alert-success">
                                <i class="fas fa-check-circle me-2"></i>
                                <?php echo htmlspecialchars($success_message); ?>
                                <div class="mt-3">
                                    <a href="appointments.php" class="btn btn-primary">
                                        <i class="fas fa-list me-2"></i>View My Appointments
                                    </a>
                                </div>
                            </div>
                        <?php else: ?>
                            <form method="POST" action="" id="bookingForm">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
                                <!-- we submit 24h HH:MM into this hidden input -->
                                <input type="hidden" name="appointment_time" id="selectedTime" value="<?php echo htmlspecialchars($_POST['appointment_time'] ?? ''); ?>">
                                
                                <div class="row">
                                    <div class="col-md-6 mb-4">
                                        <label for="appointment_date" class="form-label">
                                            <i class="fas fa-calendar medical-icon"></i>Preferred Date
                                        </label>
                                        <input type="date" class="form-control" id="appointment_date" name="appointment_date" 
                                               min="<?php echo date('Y-m-d'); ?>" 
                                               max="<?php echo date('Y-m-d', strtotime('+3 months')); ?>"
                                               value="<?php echo htmlspecialchars($_POST['appointment_date'] ?? ''); ?>" required>
                                        <small class="text-muted">Available days: <?php echo htmlspecialchars($working_days_display); ?></small>
                                    </div>
                                    
                                    <div class="col-md-6 mb-4">
                                        <label class="form-label">
                                            <i class="fas fa-clock medical-icon"></i>Available Time Slots
                                        </label>
                                        <div id="timeSlots" class="border rounded p-3" style="min-height: 120px; background: #f8f9fa;">
                                            <p class="text-muted text-center mb-0">Please select a date first to see available time slots</p>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="reason" class="form-label">
                                        <i class="fas fa-notes-medical medical-icon"></i>Reason for Appointment
                                    </label>
                                    <textarea class="form-control" id="reason" name="reason" rows="4" 
                                              placeholder="Please describe your symptoms or reason for consultation..." required><?php echo htmlspecialchars($_POST['reason'] ?? ''); ?></textarea>
                                </div>
                                
                                <div class="booking-summary" id="bookingSummary" style="display: none;">
                                    <h5 class="mb-3" style="color: var(--primary-color);">
                                        <i class="fas fa-clipboard-check me-2"></i>Appointment Summary
                                    </h5>
                                    
                                    <div class="summary-item">
                                        <span class="summary-label">Doctor:</span>
                                        <span class="summary-value"> <?php echo htmlspecialchars($doctor['name']); ?></span>
                                    </div>
                                    
                                    <div class="summary-item">
                                        <span class="summary-label">Specialization:</span>
                                        <span class="summary-value"><?php echo htmlspecialchars($doctor['specialization']); ?></span>
                                    </div>
                                    
                                    <div class="summary-item">
                                        <span class="summary-label">Date:</span>
                                        <span class="summary-value" id="summaryDate">-</span>
                                    </div>
                                    
                                    <div class="summary-item">
                                        <span class="summary-label">Time:</span>
                                        <span class="summary-value" id="summaryTime">-</span>
                                    </div>
                                </div>
                                
                                <div class="d-flex gap-3 mt-4">
                                    <button type="submit" class="btn btn-primary btn-lg" id="bookButton" disabled>
                                        <i class="fas fa-calendar-check me-2"></i>Book Appointment
                                    </button>
                                    <a href="doctor_profile.php?id=<?php echo $doctor['id']; ?>" class="btn d-inline-flex align-items-center btn-secondary">
                                        <i class="fas fa-arrow-left me-2"></i>Back to Doctor Profile
                                    </a>
                                </div>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // All slots are 24h "HH:MM" strings keyed by weekday
        const allTimeSlots = <?php echo json_encode($all_time_slots); ?>;
        const workingDays  = <?php echo json_encode($working_days_array); ?>;

        function toWeekday(dateStr) {
            const d = new Date(dateStr + 'T00:00:00'); // avoid TZ surprises
            return d.toLocaleDateString('en-US', { weekday: 'long' });
        }

        function toAmPm(hm) { // "HH:MM" -> "h:mm AM/PM"
            const [H, m] = hm.split(':').map(Number);
            let h = H % 12; if (h === 0) h = 12;
            const ampm = H < 12 ? 'AM' : 'PM';
            return `${h}:${String(m).padStart(2,'0')} ${ampm}`;
        }

        function nowLocalHm() { // returns "HH:MM" local
            const d = new Date();
            return `${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`;
        }

        function renderSlots(selectedDate) {
            const selectedDay = toWeekday(selectedDate);
            const timeSlotsContainer = document.getElementById('timeSlots');
            const todaysHm = nowLocalHm();
            const todayStr = new Date().toISOString().slice(0,10);

            if (!workingDays.includes(selectedDay)) {
                timeSlotsContainer.innerHTML = '<p class="text-danger text-center mb-0">Doctor is not available on ' + selectedDay + 's</p>';
                document.getElementById('selectedTime').value = '';
                document.getElementById('summaryTime').textContent = '-';
                updateSummary();
                return;
            }

            const dayTimeSlots = (allTimeSlots[selectedDay] || []).filter(hm => {
                // If booking for today, hide past slots
                if (selectedDate === todayStr) {
                    return hm >= todaysHm;
                }
                return true;
            });

            if (dayTimeSlots.length === 0) {
                timeSlotsContainer.innerHTML = '<p class="text-muted text-center mb-0">No available slots for the selected date.</p>';
                document.getElementById('selectedTime').value = '';
                document.getElementById('summaryTime').textContent = '-';
                updateSummary();
                return;
            }

            let slotsHtml = '';
            dayTimeSlots.forEach(hm => {
                slotsHtml += `<span class="time-slot" data-time="${hm}" title="${toAmPm(hm)}">${toAmPm(hm)}</span>`;
            });
            timeSlotsContainer.innerHTML = slotsHtml;

            document.querySelectorAll('.time-slot').forEach(slot => {
                slot.addEventListener('click', function() {
                    document.querySelectorAll('.time-slot').forEach(s => s.classList.remove('selected'));
                    this.classList.add('selected');

                    const hm24 = this.dataset.time;
                    document.getElementById('selectedTime').value = hm24; // submit as 24h HH:MM
                    document.getElementById('summaryTime').textContent = toAmPm(hm24);

                    updateSummary();
                });
            });
        }

        document.getElementById('appointment_date').addEventListener('change', function() {
            const selectedDate = this.value;
            renderSlots(selectedDate);

            // Update date in summary
            const d = new Date(selectedDate + 'T00:00:00');
            document.getElementById('summaryDate').textContent = d.toLocaleDateString('en-US', {
                weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
            });

            updateSummary();
        });

        function updateSummary() {
            const date = document.getElementById('appointment_date').value;
            const time = document.getElementById('selectedTime').value;
            const summary = document.getElementById('bookingSummary');
            const bookButton = document.getElementById('bookButton');
            if (date && time) {
                summary.style.display = 'block';
                bookButton.disabled = false;
            } else {
                summary.style.display = 'none';
                bookButton.disabled = true;
            }
        }

        // Initialize if form had values (e.g., after validation errors)
        (function init() {
            const dateInput = document.getElementById('appointment_date');
            if (dateInput.value) {
                renderSlots(dateInput.value);
                const initialTime = document.getElementById('selectedTime').value;
                if (initialTime) {
                    const btn = document.querySelector(`[data-time="${initialTime}"]`);
                    if (btn) {
                        btn.classList.add('selected');
                        document.getElementById('summaryTime').textContent = toAmPm(initialTime);
                    }
                }
                const d = new Date(dateInput.value + 'T00:00:00');
                document.getElementById('summaryDate').textContent = d.toLocaleDateString('en-US', {
                    weekday: 'long', year: 'numeric', month: 'long', day: 'numeric'
                });
                updateSummary();
            }
        })();
    </script>
</body>
</html>
