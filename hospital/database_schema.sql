-- Hospital Management System Database Schema
-- Patient-side management + Departments/Specializations minimized to id+name

-- =========================================================
-- Create / select database
-- =========================================================
CREATE DATABASE IF NOT EXISTS hospital_management;
USE hospital_management;

-- =========================================================
-- Drop dependent views first (to avoid FK dependency errors)
-- =========================================================
DROP VIEW IF EXISTS appointment_details;
DROP VIEW IF EXISTS medical_history_details;

-- =========================================================
-- Drop tables in dependency-safe order
-- =========================================================
DROP TABLE IF EXISTS appointments;
DROP TABLE IF EXISTS medical_history;
DROP TABLE IF EXISTS patients;
DROP TABLE IF EXISTS departments;
DROP TABLE IF EXISTS specializations;
DROP TABLE IF EXISTS doctors;

-- =========================================================
-- Base tables
-- =========================================================

-- Table: patients
CREATE TABLE patients (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    gender ENUM('Male', 'Female', 'Other') NOT NULL,
    date_of_birth DATE NOT NULL,
    phone VARCHAR(15) NOT NULL,
    address TEXT NOT NULL,
    allergy TEXT NULL,
    -- Optional link to department
    department_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Table: doctors
CREATE TABLE doctors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    -- Backward-compatible free-text specialization (kept for legacy inserts)
    specialization VARCHAR(100) NOT NULL,
    contact VARCHAR(15) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    working_days VARCHAR(50) NOT NULL,   -- e.g., 'Mon-Fri' or 'Mon,Wed,Fri'
    working_hours VARCHAR(50) NOT NULL,  -- e.g., '09:00-17:00'
    profile_image VARCHAR(255) DEFAULT NULL,
    experience_years INT DEFAULT 0,
    qualification VARCHAR(255) DEFAULT NULL,
    -- New FKs
    department_id INT NULL,
    specialization_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Table: departments (ONLY id + name)
CREATE TABLE departments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Table: specializations (ONLY id + name)
CREATE TABLE specializations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- =========================================================
-- Add FKs after all referenced tables exist
-- =========================================================
ALTER TABLE patients
    ADD CONSTRAINT fk_patients_department
        FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE SET NULL;

ALTER TABLE doctors
    ADD CONSTRAINT fk_doctors_department
        FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE SET NULL,
    ADD CONSTRAINT fk_doctors_specialization
        FOREIGN KEY (specialization_id) REFERENCES specializations(id) ON DELETE SET NULL;

-- =========================================================
-- Transactional tables
-- =========================================================

-- Table: appointments
CREATE TABLE appointments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    appointment_date DATE NOT NULL,
    appointment_time TIME NOT NULL,
    status ENUM('Pending', 'Confirmed', 'Completed', 'Cancelled') DEFAULT 'Pending',
    notes TEXT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_appointments_patient
        FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    CONSTRAINT fk_appointments_doctor
        FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
);

-- Table: medical_history
CREATE TABLE medical_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    patient_id INT NOT NULL,
    doctor_id INT NOT NULL,
    diagnosis TEXT NOT NULL,
    prescription TEXT DEFAULT NULL,
    consultation_date DATE NOT NULL,
    symptoms TEXT DEFAULT NULL,
    treatment_notes TEXT DEFAULT NULL,
    follow_up_date DATE DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_medhist_patient
        FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    CONSTRAINT fk_medhist_doctor
        FOREIGN KEY (doctor_id) REFERENCES doctors(id) ON DELETE CASCADE
);

-- =========================================================
-- Indexes
-- =========================================================

-- Patients
CREATE INDEX idx_patient_email ON patients(email);
CREATE INDEX idx_patient_department ON patients(department_id);

-- Doctors
CREATE INDEX idx_doctor_specialization_text ON doctors(specialization);   -- legacy quick search
CREATE INDEX idx_doctor_specialization ON doctors(specialization_id);
CREATE INDEX idx_doctor_department ON doctors(department_id);

-- Appointments & Medical History
CREATE INDEX idx_appointment_date ON appointments(appointment_date);
CREATE INDEX idx_appointment_patient ON appointments(patient_id);
CREATE INDEX idx_appointment_doctor ON appointments(doctor_id);
CREATE INDEX idx_medical_history_patient ON medical_history(patient_id);
CREATE INDEX idx_medical_history_date ON medical_history(consultation_date);

-- =========================================================
-- Views (use specialization entity when available)
-- =========================================================

-- View: appointment_details
CREATE VIEW appointment_details AS
SELECT 
    a.id,
    a.appointment_date,
    a.appointment_time,
    a.status,
    a.notes,
    p.name AS patient_name,
    p.phone AS patient_phone,
    d.name AS doctor_name,
    COALESCE(s.name, d.specialization) AS specialization,
    d.contact AS doctor_contact
FROM appointments a
JOIN patients p ON a.patient_id = p.id
JOIN doctors d ON a.doctor_id = d.id
LEFT JOIN specializations s ON d.specialization_id = s.id;

-- View: medical_history_details
CREATE VIEW medical_history_details AS
SELECT 
    mh.id,
    mh.diagnosis,
    mh.prescription,
    mh.consultation_date,
    mh.symptoms,
    mh.treatment_notes,
    mh.follow_up_date,
    p.name AS patient_name,
    d.name AS doctor_name,
    COALESCE(s.name, d.specialization) AS specialization
FROM medical_history mh
JOIN patients p ON mh.patient_id = p.id
JOIN doctors d ON mh.doctor_id = d.id
LEFT JOIN specializations s ON d.specialization_id = s.id;
