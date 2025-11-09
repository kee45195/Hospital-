-- Admin Schema for Hospital Management System
-- This file contains all admin-related tables and sample data

-- Create admins table
DROP TABLE IF EXISTS admins;
CREATE TABLE admins (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(20),
    role ENUM('admin', 'superadmin') DEFAULT 'admin',
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create users table for unified user management
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    role ENUM('patient', 'doctor', 'receptionist', 'admin') NOT NULL,
    status ENUM('active', 'inactive') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_user_role (user_id, role),
    INDEX idx_status (status)
);

-- Create reports table
DROP TABLE IF EXISTS reports;
CREATE TABLE reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    type ENUM('appointments', 'users', 'feedback', 'custom') NOT NULL,
    title VARCHAR(200) NOT NULL,
    details TEXT,
    generated_by INT NOT NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (generated_by) REFERENCES admins(id) ON DELETE CASCADE
);

-- Create site_content table for content management
DROP TABLE IF EXISTS site_content;
CREATE TABLE site_content (
    id INT AUTO_INCREMENT PRIMARY KEY,
    section VARCHAR(100) NOT NULL UNIQUE,
    title VARCHAR(200),
    content TEXT,
    updated_by INT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES admins(id) ON DELETE SET NULL
);

-- Insert default admin accounts
INSERT INTO admins (name, email, password, phone, role) VALUES
('Admin One', 'admin@hospital.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', '9998887777', 'superadmin'),
('Hospital Admin', 'hospitaladmin@hospital.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', '9998887778', 'admin');

-- Note: Default password for both accounts is 'password' (hashed)
-- Login Credentials:
-- Email: admin@hospital.com, Password: password
-- Email: hospitaladmin@hospital.com, Password: password

-- Insert sample site content
INSERT INTO site_content (section, title, content, updated_by) VALUES
('about_us', 'About Our Hospital', 'We are a leading healthcare institution committed to providing exceptional medical care with compassion and excellence. Our team of dedicated professionals works tirelessly to ensure the best possible outcomes for our patients.', 1),
('contact_info', 'Contact Information', 'Address: 123 Medical Center Drive, Healthcare City, HC 12345\nPhone: (555) 123-4567\nEmail: info@hospital.com\nEmergency: (555) 911-HELP', 1),
('hospital_announcements', 'Hospital Announcements', 'Welcome to our new online appointment booking system! You can now schedule appointments with your preferred doctors at your convenience. For any assistance, please contact our reception desk.', 1),
('services', 'Our Services', 'We offer comprehensive healthcare services including Emergency Care, Cardiology, Neurology, Orthopedics, Pediatrics, Radiology, Laboratory Services, and Pharmacy. Our state-of-the-art facilities ensure the highest quality of care.', 1);

-- Insert admins into users table
INSERT INTO users (user_id, role, status)
SELECT id, 'admin', status FROM admins;

-- Create indexes for better performance
CREATE INDEX idx_admins_email ON admins(email);
CREATE INDEX idx_admins_status ON admins(status);
CREATE INDEX idx_reports_type ON reports(type);
CREATE INDEX idx_reports_generated_at ON reports(generated_at);
CREATE INDEX idx_site_content_section ON site_content(section);

-- Sample reports data
INSERT INTO reports (type, title, details, generated_by) VALUES
('appointments', 'Monthly Appointments Report', 'Total appointments for current month: 150\nConfirmed: 120\nPending: 20\nCancelled: 10', 1),
('users', 'User Statistics Report', 'Total Users: 200\nPatients: 150\nDoctors: 25\nReceptionists: 5\nAdmins: 2\nActive Users: 180\nInactive Users: 20', 1),
('feedback', 'Patient Feedback Summary', 'Average Rating: 4.5/5\nTotal Feedback: 85\nPositive: 70\nNeutral: 10\nNegative: 5', 1);

COMMIT;