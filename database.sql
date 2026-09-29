CREATE DATABASE IF NOT EXISTS aneri_office CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE aneri_office;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  employee_id VARCHAR(50) NOT NULL UNIQUE,
  name VARCHAR(150) NOT NULL,
  department VARCHAR(100) NOT NULL,
  role ENUM('admin','employee') NOT NULL DEFAULT 'employee',
  password VARCHAR(255) NOT NULL,
  phone VARCHAR(15) NULL,
  email VARCHAR(100) NULL,
  address VARCHAR(255) NULL,
  gender VARCHAR(20) NULL,
  joining_date DATE NULL,
  salary DECIMAL(10,2) NULL,
  status VARCHAR(20) NULL DEFAULT 'Active',
  photo LONGTEXT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login TIMESTAMP NULL DEFAULT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS files (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  original_name VARCHAR(255) NOT NULL,
  stored_name VARCHAR(255) NOT NULL UNIQUE,
  uploaded_by INT NOT NULL,
  target_type ENUM('department','person') NOT NULL,
  target_value VARCHAR(100) NOT NULL,
  description TEXT NULL,
  upload_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  download_count INT UNSIGNED NOT NULL DEFAULT 0,
  CONSTRAINT fk_files_user FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_files_target (target_type, target_value),
  INDEX idx_files_uploader (uploaded_by)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS activities (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  activity_type VARCHAR(60) NOT NULL,
  description VARCHAR(500) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_activities_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_activity_user (user_id),
  INDEX idx_activity_date (created_at)
) ENGINE=InnoDB;

-- Safe migrations for an existing users table.
ALTER TABLE users ADD COLUMN IF NOT EXISTS photo LONGTEXT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP NULL DEFAULT NULL;
