<?php
require_once 'config/config.php';
?>
<?php
if (session_status() === PHP_SESSION_NONE) { session_start(); }
if (!isset($is_patient)) {
    $is_patient = isset($_SESSION['patient']) || isset($_SESSION['patient_id']);
}
if (!isset($current_patient)) {
    $current_patient = isset($_SESSION['patient']) && is_array($_SESSION['patient']) ? $_SESSION['patient'] : ['name' => 'Guest'];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Medical Health Packages - <?php echo APP_NAME; ?></title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" crossorigin="anonymous">
<style>
:root{
  --primary-color: #0b2e4e;
  --secondary-color: #0aa4a8;
  --accent-color: #ff7a59;
  --text-color: #1f2937;
  --background-color: #f5f7fb;
}
body{background:var(--background-color);color:var(--text-color)}

.hero-pack{background: linear-gradient(135deg, rgba(11,46,78,.92), rgba(10,164,168,.92)), url('https://images.unsplash.com/photo-1582719478250-c89cae4dc85b?q=80&w=1200&auto=format&fit=crop'); background-size:cover; background-position:center; color:#fff; border-bottom-left-radius:24px; border-bottom-right-radius:24px;}
.hero-pack h1{font-weight:800; letter-spacing:.3px}

.package-card{border:1px solid #e5e9f0; border-radius:16px; background:#fff; box-shadow:0 10px 28px rgba(0,0,0,.06); overflow:hidden; height:100%}
.package-card .header{padding:16px 16px 0 16px}
.package-card .price{font-size:1.75rem;font-weight:800;color:var(--primary-color)}
.package-card .body{padding:16px}
.package-card ul{margin:0;padding-left:1.2rem}
.package-card li{margin:.35rem 0}
.package-card .cta{padding:16px; border-top:1px dashed #e5e9f0; background:#fafcff}

.badge-pop{background:var(--accent-color)}
.footer-bar{background:linear-gradient(135deg, #0b2e4e, #0aa4a8); color:#fff}
.footer-bar a{color:#fff;text-decoration:none}

/* footer background override */
.footer-bar{background:linear-gradient(135deg,#0b2e4e,#0a8f8f)!important;}
</style>
<style>
:root{
            --primary-color: <?php echo COLOR_PRIMARY; ?>;
            --secondary-color: <?php echo COLOR_SECONDARY; ?>;
            --accent-color: <?php echo COLOR_ACCENT; ?>;
            --background-color: <?php echo COLOR_BACKGROUND; ?>;
            --text-color: <?php echo COLOR_TEXT; ?>;
        }
        body{background:var(--background-color);color:var(--text-color);font-family:'Segoe UI', Tahoma, Geneva, Verdana, sans-serif}
        .navbar{background:linear-gradient(135deg,var(--primary-color),#00796b)!important;box-shadow:0 2px 10px rgba(0,0,0,.1)}
        .navbar-brand{font-weight:700;font-size:1.5rem}
        .navbar-nav .nav-link{color:#fff!important;font-weight:500;margin:0 10px;transition:.3s}
        .navbar-nav .nav-link:hover{color:var(--secondary-color)!important;transform:translateY(-2px)}

        .card-lite{background:#fff;border:none;border-radius:16px;box-shadow:0 6px 20px rgba(0,0,0,.08)}
        .section-title{color:var(--primary-color)}
        .stat-card{border-radius:16px;color:#fff;padding:22px;text-align:center;box-shadow:0 6px 20px rgba(0,0,0,.08)}
        .stat-primary{background:linear-gradient(135deg,var(--primary-color),#00796b)}
        .stat-secondary{background:linear-gradient(135deg,var(--secondary-color),#689f38)}
        .stat-accent{background:linear-gradient(135deg,var(--accent-color),#e91e63)}
        .stat-info{background:linear-gradient(135deg,#2196f3,#1976d2)}
        .stat-number{font-size:2.2rem;font-weight:800}
        .stat-label{opacity:.95;margin-top:6px}

        .appointment-item{border-left:4px solid var(--primary-color);background:#fff;border-radius:10px;padding:1rem;margin-bottom:1rem;box-shadow:0 2px 10px rgba(0,0,0,.05)}
        .quick-btn{display:block;width:100%;border-radius:10px;padding:10px 14px;border:1px solid #e5e9f0;background:#fff;text-align:left}
        .quick-btn:hover{background:#f7fbfb;border-color:var(--primary-color)}
        .quick-btn .icon{width:28px;height:28px;display:inline-grid;place-items:center;border-radius:50%;margin-right:8px;background:rgba(0,0,0,.06)}

        .announce-card{background:#fff;border-radius:14px;border:none;box-shadow:0 6px 18px rgba(0,0,0,.07)}
        .announce-header{background:linear-gradient(90deg,var(--primary-color),var(--accent-color));color:#fff;border-radius:14px 14px 0 0;padding:14px 16px}
        .content-block{padding:16px}
        @media (max-width: 575.98px){
            .stat-number{font-size:1.8rem}
        }
        .hero {background:linear-gradient(135deg,var(--primary-color),var(--accent-color)); color:#fff; border-radius:16px}
    
/* ==== Enhanced styles for Quick Actions & Plan Your Visit ==== */
.qa-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.qa-card{position:relative;display:flex;align-items:center;gap:12px;padding:14px;border:1px solid #e5e9f0;border-radius:14px;background:#fff;box-shadow:0 6px 18px rgba(0,0,0,.06);text-decoration:none;color:inherit;transition:transform .15s ease, box-shadow .2s ease, border-color .2s ease}
.qa-card .icon-wrap{width:40px;height:40px;display:grid;place-items:center;border-radius:12px;background:linear-gradient(135deg,var(--accent-color),#ff6b6b);color:#fff;flex:0 0 40px}
.qa-card:hover{transform:translateY(-2px);box-shadow:0 10px 24px rgba(0,0,0,.10);border-color:#d9dee7}
.qa-card .label{font-weight:600;letter-spacing:.2px}

.visit-steps{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.visit-step{position:relative;border-radius:16px;padding:16px;border:1px dashed #dce2ec;background:linear-gradient(180deg,#ffffff, #fafcff);box-shadow:0 6px 18px rgba(0,0,0,.05);transition:transform .15s ease, box-shadow .2s ease}
.visit-step:hover{transform:translateY(-2px);box-shadow:0 10px 24px rgba(0,0,0,.10)}
.visit-step .step-badge{position:absolute;top:-10px;left:-10px;background:var(--primary-color);color:#fff;border-radius:999px;padding:6px 10px;font-size:.75rem;box-shadow:0 8px 18px rgba(0,0,0,.12)}
.visit-step .title{font-weight:700;margin-bottom:6px}
.visit-step .desc{font-size:.9rem;color:#6b7280}
.visit-cta{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
.visit-cta .btn{border-radius:999px;padding:.45rem .85rem}
/* Responsive tweaks */
@media (max-width: 992px){ .visit-steps{grid-template-columns:repeat(2,minmax(0,1fr))} }
@media (max-width: 576px){ .qa-grid{grid-template-columns:1fr} .visit-steps{grid-template-columns:1fr} }
/* ============================================================= */


/* ==== Hospital info enhancements ==== */
.emergency-strip{background:linear-gradient(90deg,var(--accent-color),#ff8a65);color:#fff;border-radius:12px;padding:10px 14px;display:flex;align-items:center;gap:10px;box-shadow:0 8px 18px rgba(0,0,0,.12)}
.emergency-strip .badge{background:rgba(255,255,255,.2);backdrop-filter:blur(2px);}

.feature-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
.feature-card{border-radius:16px;padding:16px;border:1px solid #e5e9f0;background:linear-gradient(180deg,#ffffff,#fafcff);box-shadow:0 6px 18px rgba(0,0,0,.06)}
.feature-card .icon{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:linear-gradient(135deg,var(--secondary-color),#4caf50);color:#fff;margin-bottom:10px}
.feature-card h6{margin:0 0 6px 0;font-weight:700}
.feature-card p{margin:0;color:#6b7280;font-size:.95rem}

.insurance-badges{display:flex;flex-wrap:wrap;gap:8px}
.insurance-badge{border:1px dashed #dce2ec;border-radius:999px;padding:.35rem .7rem;font-weight:600;background:#fff}

.testimonial-card{border-left:4px solid var(--secondary-color);border-radius:14px;background:#fff;padding:14px;box-shadow:0 6px 18px rgba(0,0,0,.05)}
.testimonial-card .who{font-weight:700}

.accordion-button{font-weight:600}
/* Responsive */
@media (max-width: 992px){ .feature-grid{grid-template-columns:repeat(2,minmax(0,1fr))} }
@media (max-width: 576px){ .feature-grid{grid-template-columns:1fr} }
/* ==================================== */


/* --- Features block styles imported from index --- */
            color: var(--primary-color);
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(255, 255, 255, 0.3);
        }
        
        .features-section {
            padding: 5rem 0;
            background: white;
        .feature-card {
            border-radius: 20px;
            padding: 2.5rem;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            border: none;
            transition: all 0.3s ease;
            height: 100%;
        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
        .feature-icon {
            font-size: 3.5rem;
            margin-bottom: 1.5rem;
        .feature-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: var(--text-color);
        .feature-description {
            color: #6c757d;
            line-height: 1.6;
        .stats-section {
            background: var(--background-color);
            padding: 4rem 0;
        .stat-item {
            padding: 2rem;
        .stat-number {
            font-size: 3rem;
            margin-bottom: 0.5rem;


/* Footer styles */
.footer-bar{background:linear-gradient(135deg,var(--primary-color),#0aa4a8);color:#fff;border-top-left-radius:16px;border-top-right-radius:16px;box-shadow:0 -6px 18px rgba(0,0,0,.08)}
.footer-bar a{color:#fff;text-decoration:none}
.footer-bar .btn{border-radius:999px;border-color:rgba(255,255,255,.6)}
.footer-bar .btn:hover{background:rgba(255,255,255,.12)}
.footer-contact{line-height:1.6}



/* Footer redesign */
.footer-bar{background:linear-gradient(135deg,var(--primary-color),#0aa4a8);color:#fff;border-top-left-radius:16px;border-top-right-radius:16px;box-shadow:0 -6px 18px rgba(0,0,0,.08)}
.footer-bar a{color:#fff;text-decoration:none}
.footer-bar .btn{border-radius:999px;border-color:rgba(255,255,255,.6)}
.footer-bar .btn:hover{background:rgba(255,255,255,.12)}
.footer-contacts .contact-card{background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.2);border-radius:14px;padding:12px;box-shadow:0 6px 18px rgba(0,0,0,.08)}
.footer-contacts .contact-card .icon{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;background:rgba(255,255,255,.2);margin-bottom:8px}
.footer-contacts .contact-card .label{font-weight:700;letter-spacing:.2px}
.footer-contacts .contact-card .value{opacity:.95}
.footer-contacts .emergency{border-color:rgba(255,0,0,.4);background:rgba(255,0,0,.08)}


/* footer background override */
.footer-bar{background:linear-gradient(135deg,#0b2e4e,#0a8f8f)!important;}
</style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark">
    <div class="container">
        <a class="navbar-brand" href="dashboard.php"><i class="fas fa-hospital-alt me-2"></i><?php echo APP_NAME; ?></a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#nav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="nav">
            <ul class="navbar-nav me-auto">
                <li class="nav-item"><a class="nav-link active" href="dashboard.php"><i class="fas fa-home me-1"></i><?php echo $is_patient ? 'Home' : 'Welcome'; ?></a></li>
                <li class="nav-item"><a class="nav-link" href="doctors.php"><i class="fas fa-user-md me-1"></i>Find Doctors</a></li>
                <?php if ($is_patient): ?>
                    <li class="nav-item"><a class="nav-link" href="appointments.php"><i class="fas fa-calendar-check me-1"></i>My Appointments</a></li>
                    <li class="nav-item"><a class="nav-link" href="medical_history.php"><i class="fas fa-history me-1"></i>Medical History</a></li>
                    <li class="nav-item"><a class="nav-link" href="feedback.php"><i class="fas fa-comment-medical me-1"></i>Give Feedback</a></li>
                <?php endif; ?>
            </ul>

            <ul class="navbar-nav">
                <?php if ($is_patient): ?>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i><?php echo htmlspecialchars($current_patient['name']); ?>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="profile.php"><i class="fas fa-user me-2"></i>My Profile</a></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="logout.php"><i class="fas fa-sign-out-alt me-2"></i>Logout</a></li>
                        </ul>
                    </li>
                <?php else: ?>
                    <li class="nav-item"><a class="nav-link" href="login.php"><i class="fas fa-sign-in-alt me-1"></i>Login</a></li>
                    <li class="nav-item"><a class="nav-link" href="register.php"><i class="fas fa-user-plus me-1"></i>Register</a></li>
                <?php endif; ?>
            </ul>
        </div>
    </div>
</nav>

<header class="hero-pack py-5 mb-4">
  <div class="container py-3">
    <div class="row align-items-center">
      <div class="col-lg-7">
        <span class="badge bg-light text-dark mb-2"><i class="fas fa-heart-pulse me-1 text-danger"></i> Preventive Care</span>
        <h1 class="display-6 mb-2">Medical Health Packages</h1>
        <p class="lead mb-0">Curated checkups for every age and need—save with bundled diagnostics and specialist consults.</p>
      </div>
    </div>
  </div>
</header>

<main class="container mb-5">
  <div class="row g-4">

    <div class="col-md-6 col-lg-4">
      <div class="package-card">
        <div class="header d-flex justify-content-between align-items-center">
          <h5 class="mb-0">General Wellness</h5>
          <span class="badge rounded-pill bg-secondary">Popular</span>
        </div>
        <div class="body">
          <div class="price mb-2">$99</div>
          <ul class="small">
            <li>Physician consultation</li>
            <li>Complete blood count (CBC)</li>
            <li>Fasting blood sugar</li>
            <li>Lipid profile</li>
            <li>Urinalysis</li>
          </ul>
        </div>
        <div class="cta">
          <a href="appointments.php" class="btn btn-primary w-100"><i class="fas fa-calendar-plus me-1"></i>Book Package</a>
        </div>
      </div>
    </div>

    <div class="col-md-6 col-lg-4">
      <div class="package-card">
        <div class="header d-flex justify-content-between align-items-center">
          <h5 class="mb-0">Cardiac Screening</h5>
          <span class="badge rounded-pill bg-danger">Heart</span>
        </div>
        <div class="body">
          <div class="price mb-2">$199</div>
          <ul class="small">
            <li>Cardiologist consult</li>
            <li>ECG & Chest X‑ray</li>
            <li>Lipid profile & HbA1C</li>
            <li>TSH & Electrolytes</li>
            <li>Diet counseling</li>
          </ul>
        </div>
        <div class="cta">
          <a href="appointments.php" class="btn btn-primary w-100"><i class="fas fa-heartbeat me-1"></i>Book Package</a>
        </div>
      </div>
    </div>

    <div class="col-md-6 col-lg-4">
      <div class="package-card">
        <div class="header d-flex justify-content-between align-items-center">
          <h5 class="mb-0">Diabetes Care</h5>
          <span class="badge rounded-pill bg-warning text-dark">Metabolic</span>
        </div>
        <div class="body">
          <div class="price mb-2">$149</div>
          <ul class="small">
            <li>Endocrinologist consult</li>
            <li>Fasting/PP blood sugar</li>
            <li>HbA1C & Microalbumin</li>
            <li>Kidney & liver panel</li>
            <li>Diet & lifestyle plan</li>
          </ul>
        </div>
        <div class="cta">
          <a href="appointments.php" class="btn btn-primary w-100"><i class="fas fa-syringe me-1"></i>Book Package</a>
        </div>
      </div>
    </div>

    <div class="col-md-6 col-lg-4">
      <div class="package-card">
        <div class="header d-flex justify-content-between align-items-center">
          <h5 class="mb-0">Women’s Health</h5>
          <span class="badge rounded-pill bg-pink" style="background:#ff69b4">Women</span>
        </div>
        <div class="body">
          <div class="price mb-2">$179</div>
          <ul class="small">
            <li>Gynecologist consult</li>
            <li>Pelvic exam & PAP test</li>
            <li>Breast exam</li>
            <li>Thyroid profile</li>
            <li>Vitamin D & B12</li>
          </ul>
        </div>
        <div class="cta">
          <a href="appointments.php" class="btn btn-primary w-100"><i class="fas fa-venus me-1"></i>Book Package</a>
        </div>
      </div>
    </div>

    <div class="col-md-6 col-lg-4">
      <div class="package-card">
        <div class="header d-flex justify-content-between align-items-center">
          <h5 class="mb-0">Senior Wellness</h5>
          <span class="badge rounded-pill bg-success">Senior</span>
        </div>
        <div class="body">
          <div class="price mb-2">$159</div>
          <ul class="small">
            <li>Physician + dental + eye screen</li>
            <li>Bone density & Vit D</li>
            <li>ECG</li>
            <li>Kidney/Liver panel</li>
            <li>Fall risk counseling</li>
          </ul>
        </div>
        <div class="cta">
          <a href="appointments.php" class="btn btn-primary w-100"><i class="fas fa-user-clock me-1"></i>Book Package</a>
        </div>
      </div>
    </div>

    <div class="col-md-6 col-lg-4">
      <div class="package-card">
        <div class="header d-flex justify-content-between align-items-center">
          <h5 class="mb-0">Executive Checkup</h5>
          <span class="badge rounded-pill bg-info text-dark">Premium</span>
        </div>
        <div class="body">
          <div class="price mb-2">$299</div>
          <ul class="small">
            <li>Physician & Cardiologist</li>
            <li>Full blood work + Thyroid</li>
            <li>MRI/CT as indicated</li>
            <li>Diet & fitness coaching</li>
            <li>Priority scheduling</li>
          </ul>
        </div>
        <div class="cta">
          <a href="appointments.php" class="btn btn-primary w-100"><i class="fas fa-stethoscope me-1"></i>Book Package</a>
        </div>
      </div>
    </div>

  </div>
</main>

<footer class="footer-bar mt-5">
    <div class="container py-5">
        <div class="row g-4 align-items-start">
            <div class="col-lg-4">
                <div class="d-flex align-items-center gap-2 mb-2">
                    <i class="fas fa-hospital-symbol"></i>
                    <strong class="fs-5"><?php echo APP_NAME; ?></strong>
                </div>
                <p class="mb-3 opacity-75">Delivering quality healthcare with compassion and excellence.</p>
                <div class="footer-social d-flex gap-2">
    <a href="https://facebook.com/YourHospital" class="btn btn-sm btn-outline-light" aria-label="Facebook"><i class="fab fa-facebook-f"></i></a>
    <a href="https://twitter.com/YourHospital" class="btn btn-sm btn-outline-light" aria-label="Twitter"><i class="fab fa-twitter"></i></a>
    <a href="https://instagram.com/YourHospital" class="btn btn-sm btn-outline-light" aria-label="Instagram"><i class="fab fa-instagram"></i></a>
    <a href="https://www.linkedin.com/company/YourHospital" class="btn btn-sm btn-outline-light" aria-label="LinkedIn"><i class="fab fa-linkedin-in"></i></a>
    <a href="https://youtube.com/@YourHospital" class="btn btn-sm btn-outline-light" aria-label="YouTube"><i class="fab fa-youtube"></i></a>
</div>
            </div>
            <div class="col-lg-8">
                <div class="row g-3 footer-contacts">
                    <?php
                    $addr = $phone = $email = $emergency = '';
                    if (!empty($cms['contact_info'])) {
                        $raw = strip_tags($cms['contact_info']);
                        if (preg_match('/Address\s*:\s*(.+?)(?:Phone|Email|Emergency|$)/is', $raw, $m)) $addr = trim($m[1]);
                        if (preg_match('/Phone\s*:\s*([^\n\r]+)/i', $raw, $m)) $phone = trim($m[1]);
                        if (preg_match('/Email\s*:\s*([^\n\r]+)/i', $raw, $m)) $email = trim($m[1]);
                        if (preg_match('/Emergency\s*:\s*([^\n\r]+)/i', $raw, $m)) $emergency = trim($m[1]);
                    }
                    if (empty($addr)) $addr = '1234 Medical Center Dr, Healthcare City, HC';
                    if (empty($phone)) $phone = '(555) 123-4567';
                    if (empty($email)) $email = 'info@hospital.com';
                    if (empty($emergency)) $emergency = '(555) 911-HELP';
                    ?>
                    <div class="col-md-6 col-xl-3">
                        <div class="contact-card">
                            <div class="icon"><i class="fas fa-map-marker-alt"></i></div>
                            <div class="label">Address</div>
                            <div class="value"><?php echo htmlspecialchars($addr); ?></div>
                        </div>
                    </div>
                    <div class="col-md-6 col-xl-3">
                        <div class="contact-card">
                            <div class="icon"><i class="fas fa-phone-alt"></i></div>
                            <div class="label">Phone</div>
                            <div class="value"><a href="tel:<?php echo preg_replace('/[^0-9+]/','',$phone); ?>"><?php echo htmlspecialchars($phone); ?></a></div>
                        </div>
                    </div>
                    <div class="col-md-6 col-xl-3">
                        <div class="contact-card">
                            <div class="icon"><i class="fas fa-envelope"></i></div>
                            <div class="label">Email</div>
                            <div class="value"><a href="mailto:<?php echo htmlspecialchars($email); ?>"><?php echo htmlspecialchars($email); ?></a></div>
                        </div>
                    </div>
                    <div class="col-md-6 col-xl-3">
                        <div class="contact-card emergency">
                            <div class="icon"><i class="fas fa-ambulance"></i></div>
                            <div class="label">Emergency</div>
                            <div class="value"><a href="tel:<?php echo preg_replace('/[^0-9+]/','',$emergency); ?>"><?php echo htmlspecialchars($emergency); ?></a></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <hr class="border-light my-4 opacity-25">
        <div class="d-flex flex-wrap justify-content-between align-items-center small opacity-75">
            <span>&copy; <?php echo date('Y'); ?> <?php echo APP_NAME; ?>. All rights reserved.</span>
            <span>Powered by <?php echo APP_NAME; ?> Patient Portal</span>
        </div>
    </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
