CREATE DATABASE IF NOT EXISTS supplyguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE supplyguard;

SET FOREIGN_KEY_CHECKS=0;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS dependencies;
DROP TABLE IF EXISTS dependency_files;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS users;
SET FOREIGN_KEY_CHECKS=1;

-- Seven tables and the fields documented in Chapter Three.
CREATE TABLE users (
  user_id INT AUTO_INCREMENT PRIMARY KEY,
  full_name VARCHAR(100) NOT NULL,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role ENUM('admin','user') NOT NULL DEFAULT 'user',
  status ENUM('active','inactive') NOT NULL DEFAULT 'active',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE projects (
  project_id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(150) NOT NULL,
  description TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_projects_user FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
  INDEX idx_projects_user (user_id)
) ENGINE=InnoDB;

CREATE TABLE dependency_files (
  file_id INT AUTO_INCREMENT PRIMARY KEY,
  project_id INT NOT NULL,
  file_name VARCHAR(150) NOT NULL,
  file_type VARCHAR(50) NOT NULL,
  file_path VARCHAR(255) NOT NULL,
  uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_files_project FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
  INDEX idx_files_project (project_id)
) ENGINE=InnoDB;

CREATE TABLE dependencies (
  dependency_id INT AUTO_INCREMENT PRIMARY KEY,
  file_id INT NOT NULL,
  name VARCHAR(100) NOT NULL,
  version VARCHAR(50) NOT NULL,
  ecosystem VARCHAR(50) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_dependencies_file FOREIGN KEY (file_id) REFERENCES dependency_files(file_id) ON DELETE CASCADE,
  INDEX idx_dependencies_file (file_id)
) ENGINE=InnoDB;

-- One assessment row per dependency per scan operation. vulnerability_id links
-- the row to one known finding; additional findings create additional assessment rows.
CREATE TABLE scans (
  scan_id INT AUTO_INCREMENT PRIMARY KEY,
  project_id INT NOT NULL,
  dependency_id INT NULL,
  vulnerability_id INT NULL,
  status ENUM('vulnerable','no known vulnerability found') NOT NULL,
  scanned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_scans_project FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
  CONSTRAINT fk_scans_dependency FOREIGN KEY (dependency_id) REFERENCES dependencies(dependency_id) ON DELETE SET NULL,
  INDEX idx_scans_project (project_id),
  INDEX idx_scans_dependency (dependency_id)
) ENGINE=InnoDB;

CREATE TABLE vulnerabilities (
  vulnerability_id INT AUTO_INCREMENT PRIMARY KEY,
  osv_id VARCHAR(100) NOT NULL,
  cve_id VARCHAR(50) NULL,
  summary TEXT NOT NULL,
  severity VARCHAR(50) NOT NULL DEFAULT 'unclassified',
  reference_url VARCHAR(255) NULL,
  published_at DATETIME NULL,
  UNIQUE KEY uq_vulnerability_osv (osv_id)
) ENGINE=InnoDB;

ALTER TABLE scans
  ADD CONSTRAINT fk_scans_vulnerability
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(vulnerability_id) ON DELETE SET NULL;

CREATE TABLE reports (
  report_id INT AUTO_INCREMENT PRIMARY KEY,
  scan_id INT NOT NULL,
  report_title VARCHAR(150) NOT NULL,
  report_file VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_reports_scan FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE,
  INDEX idx_reports_scan (scan_id)
) ENGINE=InnoDB;

-- Create the first administrator after importing:
-- php -r "echo password_hash('ChangeThisAdmin!2026', PASSWORD_DEFAULT), PHP_EOL;"
-- INSERT INTO users(full_name,email,password,role,status)
-- VALUES ('System Administrator','admin@example.com','PASTE_HASH_HERE','admin','active');
