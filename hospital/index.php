<?php
require_once 'config/config.php';

// Check if user is already logged in
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to <?php echo APP_NAME; ?></title>
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
        
        body {
            background-color: var(--background-color);
            color: var(--text-color);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .hero-section {
            background: linear-gradient(135deg, var(--primary-color), #00796b);
            color: white;
            min-height: 100vh;
            display: flex;
            align-items: center;
            position: relative;
            overflow: hidden;
        }
        
        .hero-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('https://images.unsplash.com/photo-1538108149393-fbbd81895907?ixlib=rb-4.0.3&auto=format&fit=crop&w=1200&q=80') center/cover;
            opacity: 0.1;
        }
        
        .hero-content {
            position: relative;
            z-index: 1;
        }
        
        .hospital-logo {
            font-size: 4rem;
            margin-bottom: 1rem;
            color: var(--secondary-color);
        }
        
        .hero-title {
            font-size: 3.5rem;
            font-weight: 700;
            margin-bottom: 1.5rem;
            line-height: 1.2;
        }
        
        .hero-subtitle {
            font-size: 1.3rem;
            margin-bottom: 2rem;
            opacity: 0.9;
            line-height: 1.6;
        }
        
        .cta-buttons {
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }
        
        .btn-hero {
            padding: 1rem 2rem;
            font-size: 1.1rem;
            font-weight: 600;
            border-radius: 50px;
            text-decoration: none;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            min-width: 200px;
            justify-content: center;
        }
        
        .btn-hero-primary {
            background: var(--secondary-color);
            color: white;
            border: 2px solid var(--secondary-color);
        }
        
        .btn-hero-primary:hover {
            background: transparent;
            color: var(--secondary-color);
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(139, 195, 74, 0.3);
        }
        
        .btn-hero-secondary {
            background: transparent;
            color: white;
            border: 2px solid white;
        }
        
        .btn-hero-secondary:hover {
            background: white;
            color: var(--primary-color);
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(255, 255, 255, 0.3);
        }
        
        .features-section {
            padding: 5rem 0;
            background: white;
        }
        
        .feature-card {
            background: white;
            border-radius: 20px;
            padding: 2.5rem;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            border: none;
            transition: all 0.3s ease;
            height: 100%;
        }
        
        .feature-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
        }
        
        .feature-icon {
            font-size: 3.5rem;
            margin-bottom: 1.5rem;
            color: var(--primary-color);
        }
        
        .feature-title {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 1rem;
            color: var(--text-color);
        }
        
        .feature-description {
            color: #6c757d;
            line-height: 1.6;
        }
        
        .stats-section {
            background: var(--background-color);
            padding: 4rem 0;
        }
        
        .stat-item {
            text-align: center;
            padding: 2rem;
        }
        
        .stat-number {
            font-size: 3rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
        }
        
        .stat-label {
            font-size: 1.1rem;
            color: var(--text-color);
            font-weight: 500;
        }
        
        .footer {
            background: var(--text-color);
            color: white;
            padding: 2rem 0;
            text-align: center;
        }
        
        .floating-elements {
            position: absolute;
            width: 100%;
            height: 100%;
            overflow: hidden;
            pointer-events: none;
        }
        
        .floating-icon {
            position: absolute;
            color: rgba(255, 255, 255, 0.1);
            font-size: 2rem;
            animation: float 6s ease-in-out infinite;
        }
        
        .floating-icon:nth-child(1) {
            top: 20%;
            left: 10%;
            animation-delay: 0s;
        }
        
        .floating-icon:nth-child(2) {
            top: 60%;
            right: 15%;
            animation-delay: 2s;
        }
        
        .floating-icon:nth-child(3) {
            bottom: 30%;
            left: 20%;
            animation-delay: 4s;
        }
        
        .floating-icon:nth-child(4) {
            top: 40%;
            right: 30%;
            animation-delay: 1s;
        }
        
        @keyframes float {
            0%, 100% {
                transform: translateY(0px);
            }
            50% {
                transform: translateY(-20px);
            }
        }
        
        @media (max-width: 768px) {
            .hero-title {
                font-size: 2.5rem;
            }
            
            .hero-subtitle {
                font-size: 1.1rem;
            }
            
            .cta-buttons {
                flex-direction: column;
                align-items: center;
            }
            
            .btn-hero {
                width: 100%;
                max-width: 300px;
            }
        }
    </style>
</head>
<body>
    <!-- Hero Section -->
    <section class="hero-section">
        <div class="floating-elements">
            <i class="fas fa-heartbeat floating-icon"></i>
            <i class="fas fa-user-md floating-icon"></i>
            <i class="fas fa-hospital floating-icon"></i>
            <i class="fas fa-stethoscope floating-icon"></i>
        </div>
        
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-6">
                    <div class="hero-content">
                        <div class="hospital-logo">
                            <i class="fas fa-hospital-alt"></i>
                        </div>
                        <h1 class="hero-title">MedCare Hospital</h1>
                        <p class="hero-subtitle">
                            Your trusted healthcare partner providing comprehensive medical services 
                            with compassionate care. Book appointments, manage your health records, 
                            and connect with experienced doctors.
                        </p>
                        <div class="cta-buttons">
                            <a href="dashboard.php" class="btn-hero btn-hero-primary">
                                <i class="fas fa-user-plus me-2"></i>Get Started
                            </a>
                            <a href="login.php" class="btn-hero btn-hero-secondary">
                                <i class="fas fa-sign-in-alt me-2"></i>Patient Login
                            </a>
                        </div>
                    </div>
                </div>
                <div class="col-lg-6">
                    <div class="text-center">
                        <img src="https://images.unsplash.com/photo-1559757148-5c350d0d3c56?ixlib=rb-4.0.3&auto=format&fit=crop&w=600&q=80" 
                             alt="Healthcare Team" class="img-fluid rounded-3" style="max-height: 500px; object-fit: cover;">
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Features Section -->
    <section class="features-section">
        <div class="container">
            <div class="row text-center mb-5">
                <div class="col-12">
                    <h2 class="display-5 fw-bold mb-3" style="color: var(--primary-color);">
                        Why Choose Our Healthcare Platform?
                    </h2>
                    <p class="lead text-muted">
                        Experience modern healthcare management with our comprehensive patient portal
                    </p>
                </div>
            </div>
            
            <div class="row g-4">
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-calendar-check"></i>
                        </div>
                        <h4 class="feature-title">Easy Appointment Booking</h4>
                        <p class="feature-description">
                            Schedule appointments with your preferred doctors at your convenience. 
                            View available time slots and get instant confirmation.
                        </p>
                    </div>
                </div>
                
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon" style="color: var(--secondary-color);">
                            <i class="fas fa-user-md"></i>
                        </div>
                        <h4 class="feature-title">Expert Medical Team</h4>
                        <p class="feature-description">
                            Connect with experienced doctors across various specializations. 
                            Find the right healthcare professional for your needs.
                        </p>
                    </div>
                </div>
                
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon" style="color: var(--accent-color);">
                            <i class="fas fa-file-medical-alt"></i>
                        </div>
                        <h4 class="feature-title">Digital Health Records</h4>
                        <p class="feature-description">
                            Access your complete medical history, prescriptions, and treatment 
                            records anytime, anywhere. Keep track of your health journey.
                        </p>
                    </div>
                </div>
                
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <h4 class="feature-title">Secure & Private</h4>
                        <p class="feature-description">
                            Your health information is protected with industry-standard security 
                            measures. Complete privacy and confidentiality guaranteed.
                        </p>
                    </div>
                </div>
                
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon" style="color: var(--secondary-color);">
                            <i class="fas fa-clock"></i>
                        </div>
                        <h4 class="feature-title">24/7 Access</h4>
                        <p class="feature-description">
                            Manage your healthcare needs around the clock. Book appointments, 
                            view records, and communicate with your healthcare team anytime.
                        </p>
                    </div>
                </div>
                
                <div class="col-lg-4 col-md-6">
                    <div class="card feature-card">
                        <div class="feature-icon" style="color: var(--accent-color);">
                            <i class="fas fa-mobile-alt"></i>
                        </div>
                        <h4 class="feature-title">Mobile Friendly</h4>
                        <p class="feature-description">
                            Access all features from any device. Our responsive design ensures 
                            a seamless experience on desktop, tablet, and mobile.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Stats Section -->
    <section class="stats-section">
        <div class="container">
            <div class="row">
                <div class="col-lg-3 col-md-6">
                    <div class="stat-item">
                        <div class="stat-number">50+</div>
                        <div class="stat-label">Expert Doctors</div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="stat-item">
                        <div class="stat-number">15+</div>
                        <div class="stat-label">Medical Specializations</div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="stat-item">
                        <div class="stat-number">1000+</div>
                        <div class="stat-label">Happy Patients</div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="stat-item">
                        <div class="stat-number">24/7</div>
                        <div class="stat-label">Healthcare Support</div>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Call to Action -->
    <section class="py-5" style="background: linear-gradient(135deg, var(--primary-color), #00796b); color: white;">
        <div class="container text-center">
            <h2 class="display-6 fw-bold mb-3">Ready to Take Control of Your Health?</h2>
            <p class="lead mb-4">Join thousands of patients who trust us with their healthcare needs</p>
            <div class="d-flex justify-content-center gap-3 flex-wrap">
                <a href="register.php" class="btn btn-light btn-lg px-4">
                    <i class="fas fa-user-plus me-2"></i>Register Now
                </a>
                <a href="doctors.php" class="btn btn-outline-light btn-lg px-4">
                    <i class="fas fa-search me-2"></i>Find Doctors
                </a>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <div class="row">
                <div class="col-12">
                    <p class="mb-2">
                        <i class="fas fa-hospital-alt me-2"></i>
                        <strong><?php echo APP_NAME; ?></strong> - Your Trusted Healthcare Partner
                    </p>
                    <p class="mb-0 text-muted">
                        &copy; <?php echo date('Y'); ?> <?php echo APP_NAME; ?>. Providing quality healthcare services with compassion and excellence.
                    </p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>