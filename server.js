require("dotenv").config();

const express = require("express");
const session = require("express-session");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 5000);
const UPLOAD_DIR = path.join(__dirname, "uploads");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "aneri-change-this-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));
app.use(express.static(path.join(__dirname, "public")));

const pool = mysql.createPool({
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "aneri_office",
  // TiDB Cloud Serverless requires an encrypted TLS connection.
  ssl: {
    rejectUnauthorized: true
  },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Department aliases are normalized before comparison so values such as
// "BACK OFFICE", "Back Office", and "back office" are treated as the same.
const ROLE_DEPARTMENTS = {
  hr: ["hr", "human resources"],
  backoffice: ["back office", "backoffice"],
  tl: ["tl", "telecalling", "team leader", "team leader (tl)"],
  fos: ["fos", "field officer", "field officer sales"]
};

function normalizeDepartment(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ");
}

function departmentMatches(userDepartment, allowedDepartments) {
  const actual = normalizeDepartment(userDepartment);
  return allowedDepartments.some(item => normalizeDepartment(item) === actual);
}

const ROLE_NAMES = {
  admin: "Manager / Head",
  hr: "HR Department",
  backoffice: "Back Office",
  tl: "Team Leader (TL)",
  fos: "FOS",
  other: "Other Employee",
  person: "Specific Person"
};

const ROLE_PASSWORDS = {
  admin: process.env.ADMIN_PASSWORD || "admin123",
  hr: process.env.HR_ROLE_PASSWORD || "hr123",
  backoffice: process.env.BACKOFFICE_ROLE_PASSWORD || "backoffice123",
  tl: process.env.TL_ROLE_PASSWORD || "tl123",
  fos: process.env.FOS_ROLE_PASSWORD || "fos123",
  other: process.env.OTHER_EMPLOYEE_ROLE_PASSWORD || "employee123"
};

const allowedExt = new Set([
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".txt",
  ".jpg", ".jpeg", ".png", ".gif", ".zip"
]);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname).toLowerCase())
});

const upload = multer({
  storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowedExt.has(ext)) return cb(new Error("File type is not allowed."));
    cb(null, true);
  }
});

function auth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please login first." });
  next();
}

function adminOnly(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Please login first." });
  if (req.session.user.role !== "admin") return res.status(403).json({ error: "Manager / Head access required." });
  next();
}

function publicUser(user, loginRole) {
  return {
    id: user.id,
    employee_id: user.employee_id,
    name: user.name,
    department: user.department,
    role: user.role,
    login_role: loginRole,
    login_role_name: ROLE_NAMES[loginRole] || loginRole,
    photo: user.photo || null,
    last_login: user.last_login || null
  };
}

async function logActivity(userId, type, description) {
  try {
    await pool.query(
      "INSERT INTO activities(user_id, activity_type, description) VALUES(?,?,?)",
      [userId, type, description]
    );
  } catch (error) {
    console.error("Activity log error:", error.message);
  }
}

async function addColumnIfMissing(tableName, columnName, definition) {
  const [rows] = await pool.query(
    `SELECT COUNT(*) AS count FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=? AND COLUMN_NAME=?`,
    [process.env.DB_NAME || "aneri_office", tableName, columnName]
  );
  if (Number(rows[0].count) === 0) {
    await pool.query(`ALTER TABLE \`${tableName}\` ADD COLUMN \`${columnName}\` ${definition}`);
    console.log(`Added missing column: ${tableName}.${columnName}`);
  }
}

async function initDb() {
  const conn = await pool.getConnection();
  try {
    await conn.query(`CREATE TABLE IF NOT EXISTS users(
      id INT AUTO_INCREMENT PRIMARY KEY,
      employee_id VARCHAR(50) NOT NULL UNIQUE,
      name VARCHAR(150) NOT NULL,
      department VARCHAR(100) NOT NULL,
      role ENUM('admin','employee') NOT NULL DEFAULT 'employee',
      password VARCHAR(255) NOT NULL,
      photo LONGTEXT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      last_login TIMESTAMP NULL DEFAULT NULL
    ) ENGINE=InnoDB`);

    await conn.query(`CREATE TABLE IF NOT EXISTS files(
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      original_name VARCHAR(255) NOT NULL,
      stored_name VARCHAR(255) NOT NULL UNIQUE,
      uploaded_by INT NOT NULL,
      target_type ENUM('department','person') NOT NULL,
      target_value VARCHAR(100) NOT NULL,
      description TEXT NULL,
      upload_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      download_count INT UNSIGNED NOT NULL DEFAULT 0,
      CONSTRAINT fk_files_user FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_files_target(target_type,target_value),
      INDEX idx_files_uploader(uploaded_by)
    ) ENGINE=InnoDB`);

    await conn.query(`CREATE TABLE IF NOT EXISTS activities(
      id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      activity_type VARCHAR(60) NOT NULL,
      description VARCHAR(500) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      CONSTRAINT fk_activities_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      INDEX idx_activity_user(user_id),
      INDEX idx_activity_date(created_at)
    ) ENGINE=InnoDB`);

    await conn.query(`ALTER TABLE users MODIFY COLUMN password VARCHAR(255) NOT NULL`);
    await addColumnIfMissing("users", "photo", "LONGTEXT NULL");
    await addColumnIfMissing("users", "created_at", "TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP");
    await addColumnIfMissing("users", "last_login", "TIMESTAMP NULL DEFAULT NULL");

    const [adminRows] = await conn.query("SELECT id FROM users WHERE employee_id='ADMIN001' LIMIT 1");
    if (!adminRows.length) {
      const hash = await bcrypt.hash(ROLE_PASSWORDS.admin, 12);
      await conn.query(
        "INSERT INTO users(employee_id,name,department,role,password) VALUES(?,?,?,?,?)",
        ["ADMIN001", "System Administrator", "Management", "admin", hash]
      );
      console.log("Default Manager / Head account created: ADMIN001");
    }
  } finally {
    conn.release();
  }
}

app.get("/", (req, res) => {
  const rootFile = path.join(__dirname, "file.html");
  const publicFile = path.join(__dirname, "public", "dashboard.html");
  if (fs.existsSync(rootFile)) return res.sendFile(rootFile);
  return res.sendFile(publicFile);
});

app.post("/api/login", async (req, res) => {
  try {
    const employeeId = String(req.body.employee_id || "").trim();
    const password = String(req.body.password || "");
    const loginRole = String(req.body.role || "").trim();

    if (!employeeId || !password || !loginRole) {
      return res.status(400).json({ error: "Employee ID, password and login role are required." });
    }

    const validRoles = Object.keys(ROLE_NAMES);
    if (!validRoles.includes(loginRole)) {
      return res.status(400).json({ error: "Invalid login role." });
    }

    const [rows] = await pool.query("SELECT * FROM users WHERE employee_id=? LIMIT 1", [employeeId]);
    if (!rows.length) return res.status(401).json({ error: "Invalid Employee ID or password." });

    const user = rows[0];

    if (loginRole === "admin") {
      if (user.role !== "admin") {
        return res.status(403).json({ error: "This account is not a Manager / Head account." });
      }
      if (password !== ROLE_PASSWORDS.admin) {
        return res.status(401).json({ error: "Invalid Manager / Head password." });
      }
    } else if (loginRole === "person") {
      if (user.role === "admin") {
        return res.status(403).json({ error: "Manager / Head must use the Manager / Head login." });
      }
      if (password !== user.employee_id) {
        return res.status(401).json({ error: "For Specific Person login, the password is the Employee ID." });
      }
    } else {
      if (user.role === "admin") {
        return res.status(403).json({ error: "Please select Manager / Head for this account." });
      }
      if (loginRole === "other") {
        if (password !== ROLE_PASSWORDS.other) {
          return res.status(401).json({ error: "Invalid Other Employee password." });
        }
      } else {
        const allowedDepartments = ROLE_DEPARTMENTS[loginRole] || [];
        const matchesDepartment = departmentMatches(user.department, allowedDepartments);
        if (!matchesDepartment) {
          return res.status(403).json({
            error: `This account belongs to ${user.department}. Select the matching login role.`
          });
        }
        if (password !== ROLE_PASSWORDS[loginRole]) {
          return res.status(401).json({ error: `Invalid ${ROLE_NAMES[loginRole]} password.` });
        }
      }
    }

    await pool.query("UPDATE users SET last_login=NOW() WHERE id=?", [user.id]);
    const [freshRows] = await pool.query("SELECT * FROM users WHERE id=? LIMIT 1", [user.id]);
    const freshUser = freshRows[0] || user;
    req.session.user = publicUser(freshUser, loginRole);

    await logActivity(user.id, "login", `${ROLE_NAMES[loginRole]} login for ${user.employee_id}`);
    res.json({ success: true, user: req.session.user });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/api/logout", auth, async (req, res) => {
  const id = req.session.user.id;
  await logActivity(id, "logout", "User logged out");
  req.session.destroy(() => res.json({ success: true }));
});

app.get("/api/me", auth, (req, res) => res.json({ success: true, user: req.session.user }));

app.get("/api/dashboard", auth, async (req, res) => {
  try {
    const u = req.session.user;
    if (u.role === "admin") {
      const [[employeeCount]] = await pool.query("SELECT COUNT(*) AS count FROM users WHERE role='employee'");
      const [[fileCount]] = await pool.query("SELECT COUNT(*) AS count FROM files");
      const [departments] = await pool.query(`
        SELECT u.department,
               COUNT(DISTINCT u.id) AS employee_count,
               COUNT(DISTINCT f.id) AS file_count
        FROM users u
        LEFT JOIN files f ON f.target_type='department' AND f.target_value=u.department
        GROUP BY u.department
        ORDER BY u.department
      `);
      return res.json({
        total_employees: Number(employeeCount.count),
        total_files: Number(fileCount.count),
        departments
      });
    }

    const [[fileCount]] = await pool.query(`
      SELECT COUNT(*) AS count FROM files f
      WHERE f.uploaded_by=?
         OR (f.target_type='department' AND f.target_value=?)
         OR (f.target_type='person' AND f.target_value=?)
    `, [u.id, u.department, u.employee_id]);

    const [[departmentEmployees]] = await pool.query(
      "SELECT COUNT(*) AS count FROM users WHERE role='employee' AND department=?",
      [u.department]
    );

    res.json({
      total_employees: Number(departmentEmployees.count),
      total_files: Number(fileCount.count),
      departments: [{ department: u.department, employee_count: Number(departmentEmployees.count), file_count: Number(fileCount.count) }]
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    res.status(500).json({ error: "Dashboard load failed." });
  }
});

app.get("/api/employees", adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, employee_id, name, department, role, phone, email, address, gender, joining_date, salary, status, photo, created_at, last_login
      FROM users ORDER BY id DESC
    `);
    res.json({ success: true, employees: rows });
  } catch (error) {
    console.error("GET /api/employees error:", error);
    res.status(500).json({ success: false, error: error.message, employees: [] });
  }
});

app.post("/api/employees", adminOnly, async (req, res) => {
  try {
    const { employee_id, name, department, password, role } = req.body;
    const employeeId = String(employee_id || "").trim();
    const employeeName = String(name || "").trim();
    const employeeDepartment = String(department || "").trim();
    if (!employeeId || !employeeName || !employeeDepartment) {
      return res.status(400).json({ error: "Employee ID, name and department are required." });
    }

    const finalPassword = String(password || employeeId);
    const hash = await bcrypt.hash(finalPassword, 12);
    const [result] = await pool.query(
      "INSERT INTO users(employee_id,name,department,role,password) VALUES(?,?,?,?,?)",
      [employeeId, employeeName, employeeDepartment, role === "admin" ? "admin" : "employee", hash]
    );

    await logActivity(req.session.user.id, "employee_created", `Created employee ${employeeId}`);
    res.json({ success: true, id: result.insertId, message: "Employee added successfully." });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Employee ID already exists." });
    console.error("POST /api/employees error:", error);
    res.status(500).json({ error: "Could not create employee." });
  }
});

app.delete("/api/employees/:id", adminOnly, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (id === Number(req.session.user.id)) return res.status(400).json({ error: "You cannot delete your own account." });
    const [result] = await pool.query("DELETE FROM users WHERE id=? AND role<>'admin'", [id]);
    if (!result.affectedRows) return res.status(404).json({ error: "Employee not found or protected." });
    await logActivity(req.session.user.id, "employee_deleted", `Deleted employee ${id}`);
    res.json({ success: true });
  } catch (error) {
    console.error("DELETE /api/employees error:", error);
    res.status(500).json({ error: "Could not delete employee." });
  }
});

app.get("/api/employees/dropdown", auth, async (req, res) => {
  const [rows] = await pool.query("SELECT employee_id,name,department FROM users WHERE role='employee' ORDER BY name");
  res.json({ users: rows });
});

app.get("/api/monitoring", adminOnly, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT u.id,u.employee_id,u.name,u.department,
        COALESCE((SELECT COUNT(*) FROM files f WHERE f.uploaded_by=u.id),0) AS files_uploaded,
        COALESCE((SELECT SUM(f.download_count) FROM files f WHERE f.uploaded_by=u.id),0) AS total_downloads,
        (SELECT MAX(a.created_at) FROM activities a WHERE a.user_id=u.id) AS last_activity
      FROM users u ORDER BY u.name
    `);
    const [activities] = await pool.query(`
      SELECT a.id,a.activity_type,a.description,a.created_at,u.name,u.employee_id,u.department
      FROM activities a JOIN users u ON u.id=a.user_id
      ORDER BY a.created_at DESC LIMIT 100
    `);
    res.json({ rows, activities });
  } catch (error) {
    console.error("Monitoring error:", error);
    res.status(500).json({ error: "Monitoring load failed." });
  }
});

app.post("/api/profile/photo", auth, async (req, res) => {
  try {
    const { photo } = req.body;
    if (typeof photo !== "string" || !/^data:image\/(png|jpeg|jpg|gif);base64,/i.test(photo)) {
      return res.status(400).json({ error: "Invalid image data." });
    }
    if (Buffer.byteLength(photo, "utf8") > 3 * 1024 * 1024) {
      return res.status(400).json({ error: "Photo is too large." });
    }
    await pool.query("UPDATE users SET photo=? WHERE id=?", [photo, req.session.user.id]);
    req.session.user.photo = photo;
    res.json({ success: true });
  } catch (error) {
    console.error("Profile photo error:", error);
    res.status(500).json({ error: "Could not update profile photo." });
  }
});

app.get("/api/files", auth, async (req, res) => {
  try {
    const u = req.session.user;
    let sql = `
      SELECT f.*, sender.name AS uploader_name, sender.employee_id AS uploader_eid,
             target.name AS target_person_name
      FROM files f
      JOIN users sender ON sender.id=f.uploaded_by
      LEFT JOIN users target ON f.target_type='person' AND target.employee_id=f.target_value
    `;
    const args = [];

    if (u.role !== "admin") {
      sql += ` WHERE f.uploaded_by=?
          OR (f.target_type='department' AND f.target_value=?)
          OR (f.target_type='person' AND f.target_value=?)`;
      args.push(u.id, u.department, u.employee_id);
    }

    sql += " ORDER BY f.upload_date DESC";
    const [rows] = await pool.query(sql, args);
    res.json({ success: true, files: rows });
  } catch (error) {
    console.error("GET /api/files error:", error);
    res.status(500).json({ success: false, error: "Could not load files." });
  }
});

app.post("/api/files", auth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Please select a file." });

  try {
    const targetType = String(req.body.target_type || "").trim();
    const targetValue = String(req.body.target_value || "").trim();
    const description = String(req.body.description || "").trim();

    if (!["department", "person"].includes(targetType) || !targetValue) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: "Please select a valid recipient." });
    }

    if (targetType === "person") {
      const [users] = await pool.query("SELECT id,name,department FROM users WHERE employee_id=? AND role='employee' LIMIT 1", [targetValue]);
      if (!users.length) {
        fs.unlinkSync(req.file.path);
        return res.status(404).json({ error: "Target employee was not found." });
      }
    }

    const [result] = await pool.query(`
      INSERT INTO files(original_name,stored_name,uploaded_by,target_type,target_value,description)
      VALUES(?,?,?,?,?,?)
    `, [req.file.originalname, req.file.filename, req.session.user.id, targetType, targetValue, description || null]);

    const recipient = targetType === "person" ? `employee ${targetValue}` : `department ${targetValue}`;
    await logActivity(req.session.user.id, "file_upload", `Sent ${req.file.originalname} to ${recipient}`);

    res.json({ success: true, id: result.insertId, message: "File uploaded and sent successfully." });
  } catch (error) {
    if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    console.error("POST /api/files error:", error);
    res.status(500).json({ error: "File upload failed." });
  }
});

async function getFileForUser(fileId, user) {
  const [rows] = await pool.query("SELECT * FROM files WHERE id=? LIMIT 1", [fileId]);
  if (!rows.length) return null;

  const file = rows[0];
  if (user.role === "admin") return file;
  if (Number(file.uploaded_by) === Number(user.id)) return file;
  if (file.target_type === "department" && file.target_value === user.department) return file;
  if (file.target_type === "person" && file.target_value === user.employee_id) return file;
  return null;
}

app.get("/api/files/:id/download", auth, async (req, res) => {
  try {
    const file = await getFileForUser(Number(req.params.id), req.session.user);
    if (!file) return res.status(403).json({ error: "You do not have permission to access this file." });

    const fullPath = path.join(UPLOAD_DIR, file.stored_name);
    if (!fs.existsSync(fullPath)) return res.status(404).json({ error: "File is missing from server storage." });

    await pool.query("UPDATE files SET download_count=download_count+1 WHERE id=?", [file.id]);
    await logActivity(req.session.user.id, "file_download", `Downloaded ${file.original_name}`);
    res.download(fullPath, file.original_name);
  } catch (error) {
    console.error("Download error:", error);
    res.status(500).json({ error: "Download failed." });
  }
});

app.delete("/api/files/:id", auth, async (req, res) => {
  try {
    const file = await getFileForUser(Number(req.params.id), req.session.user);
    if (!file) return res.status(403).json({ error: "You do not have permission to delete this file." });
    if (req.session.user.role !== "admin" && Number(file.uploaded_by) !== Number(req.session.user.id)) {
      return res.status(403).json({ error: "Only the sender or Manager / Head can delete this file." });
    }

    const fullPath = path.join(UPLOAD_DIR, file.stored_name);
    if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
    await pool.query("DELETE FROM files WHERE id=?", [file.id]);
    await logActivity(req.session.user.id, "file_deleted", `Deleted ${file.original_name}`);
    res.json({ success: true });
  } catch (error) {
    console.error("Delete file error:", error);
    res.status(500).json({ error: "Delete failed." });
  }
});

function aiReply(message) {
  const m = String(message || "").toLowerCase();
  if (m.includes("upload")) return "Open Upload Files, choose a department or a specific person, select the file, and press Upload & Send.";
  if (m.includes("download")) return "Open My Files or All Files and press Download. Server-side permissions are checked automatically.";
  if (m.includes("password") || m.includes("login")) return "Use the correct login role, Employee ID, and role password. Specific Person login uses the Employee ID as the password.";
  if (m.includes("employee")) return "Manager / Head can view employees and create new employee accounts. New employees use their Employee ID as the initial Specific Person password.";
  if (m.includes("monitor")) return "Monitoring shows employee activity, uploads, downloads, sender details, and timestamps.";
  if (m.includes("file")) return "Files can be sent to an entire department or to one specific employee. Recipient access is enforced by the server.";
  if (m.includes("help") || m.includes("hello") || m.includes("hi")) return "Hello! I am the Aneri AI Assistant. I can help with login, employees, files, upload, download, permissions, and monitoring.";
  return "I can help with login, employee management, file sharing, permissions, downloads, and monitoring.";
}

app.post("/api/ai-chat", auth, (req, res) => res.json({ reply: aiReply(req.body.message) }));

app.post("/api/ai-suggest", auth, (req, res) => {
  const text = `${req.body.filename || ""} ${req.body.description || ""}`.toLowerCase();
  const map = [
    ["HR", ["salary", "payroll", "leave", "joining", "resume", "recruit", "hr"]],
    ["Finance", ["invoice", "payment", "account", "finance", "bill", "expense"]],
    ["Back Office", ["back office", "data entry", "report", "document"]],
    ["Telecalling", ["call", "telecalling", "telecaller", "lead"]],
    ["FOS", ["fos", "field", "visit", "collection"]],
    ["Management", ["management", "director", "manager", "admin"]]
  ];

  let targetValue = "";
  let score = 0;
  for (const [department, words] of map) {
    const currentScore = words.filter(word => text.includes(word)).length;
    if (currentScore > score) {
      score = currentScore;
      targetValue = department;
    }
  }
  res.json({ target_value: targetValue, confidence: score ? "High" : "Low" });
});

app.get("/api/ai-insights", auth, async (req, res) => {
  try {
    if (req.session.user.role === "admin") {
      const [[files]] = await pool.query("SELECT COUNT(*) AS count FROM files");
      const [[employees]] = await pool.query("SELECT COUNT(*) AS count FROM users WHERE role='employee'");
      return res.json({
        insights: [
          `System currently has ${files.count} files.`,
          `There are ${employees.count} employee accounts.`,
          "Monitoring records sender, recipient, upload time, download activity, and login activity."
        ]
      });
    }

    const [[files]] = await pool.query(`
      SELECT COUNT(*) AS count FROM files
      WHERE uploaded_by=? OR (target_type='department' AND target_value=?) OR (target_type='person' AND target_value=?)
    `, [req.session.user.id, req.session.user.department, req.session.user.employee_id]);

    res.json({
      insights: [
        `Your account can access ${files.count} file records.`,
        `Your department is ${req.session.user.department}.`,
        "File access is restricted by sender, department recipient, or specific-person recipient." 
      ]
    });
  } catch (error) {
    console.error("AI insights error:", error);
    res.status(500).json({ error: "Could not load insights." });
  }
});

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError && error.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({ error: "File is too large. Maximum size is 50MB." });
  }
  if (error) console.error(error);
  res.status(500).json({ error: error.message || "Server error." });
});

initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log("========================================");
      console.log("       ANERI FILE SHARING SYSTEM");
      console.log("========================================");
      console.log(`Server: http://127.0.0.1:${PORT}`);
      console.log("Authentication: ENABLED");
      console.log("Role-based access: ENABLED");
      console.log("Person/Department file sharing: ENABLED");
      console.log("MySQL database: CONNECTED");
      console.log("========================================");
    });
  })
  .catch(error => {
    console.error("Database startup failed:", error);
    process.exit(1);
  });