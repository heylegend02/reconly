const fs = require("fs");
const path = require("path");
const initSqlJs = require("sql.js");
const bcrypt = require("bcryptjs");

const dataDir = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : path.join(__dirname, "data");
const dbPath = process.env.DATABASE_PATH
  ? path.resolve(process.env.DATABASE_PATH)
  : path.join(dataDir, "osint.db");

let sqlPromise = null;
let database = null;

function ensureDataDir() {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
}

async function getSqlRuntime() {
  if (!sqlPromise) {
    sqlPromise = initSqlJs({
      locateFile: (file) => path.join(__dirname, "node_modules", "sql.js", "dist", file),
    });
  }

  return sqlPromise;
}

async function ensureDb() {
  if (database) {
    return database;
  }

  ensureDataDir();

  const SQL = await getSqlRuntime();
  if (fs.existsSync(dbPath)) {
    database = new SQL.Database(fs.readFileSync(dbPath));
  } else {
    database = new SQL.Database();
  }

  database.run("PRAGMA foreign_keys = ON;");
  return database;
}

function persistDb() {
  if (!database) {
    return;
  }

  ensureDataDir();
  fs.writeFileSync(dbPath, Buffer.from(database.export()));
}

function queryRowsSync(db, sql, params = []) {
  const statement = db.prepare(sql, params);
  try {
    const rows = [];
    while (statement.step()) {
      rows.push(statement.getAsObject());
    }
    return rows;
  } finally {
    statement.free();
  }
}

async function run(sql, params = []) {
  const db = await ensureDb();

  try {
    db.run(sql, params);
    const [meta] = queryRowsSync(
      db,
      "SELECT last_insert_rowid() AS id, changes() AS changes"
    );
    persistDb();
    return meta || { id: 0, changes: 0 };
  } catch (error) {
    console.error("DB RUN ERROR:", error.message);
    throw error;
  }
}

async function get(sql, params = []) {
  const rows = await all(sql, params);
  return rows[0] || null;
}

async function all(sql, params = []) {
  const db = await ensureDb();

  try {
    return queryRowsSync(db, sql, params);
  } catch (error) {
    console.error("DB QUERY ERROR:", error.message);
    throw error;
  }
}

async function initDb() {
  console.log("Initializing database...");

  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'blue',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS activity_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      target TEXT,
      status TEXT NOT NULL,
      details TEXT,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS monitored_assets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      domain TEXT NOT NULL UNIQUE,
      baseline_json TEXT NOT NULL,
      last_checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS alerts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      asset_domain TEXT,
      alert_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      message TEXT NOT NULL,
      source TEXT,
      data_json TEXT,
      status TEXT NOT NULL DEFAULT 'OPEN',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const adminUsername = process.env.ADMIN_USERNAME || "admin";
  const adminEmail = process.env.ADMIN_EMAIL || "admin@osint.local";
  const adminPassword = process.env.ADMIN_PASSWORD || "admin@123";
  const adminHash = await bcrypt.hash(adminPassword, 12);

  const existingAdmin = await get(
    "SELECT id FROM users WHERE username = ? OR email = ?",
    [adminUsername, adminEmail]
  );

  if (!existingAdmin) {
    console.log("Creating admin user...");
    await run(
      "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'admin')",
      [adminUsername, adminEmail, adminHash]
    );
  } else {
    console.log("Admin exists; syncing credentials from environment...");
    await run(
      "UPDATE users SET username = ?, email = ?, password_hash = ?, role = 'admin' WHERE id = ?",
      [adminUsername, adminEmail, adminHash, existingAdmin.id]
    );
  }

  console.log(`Database ready at ${dbPath}`);
}

function findUserByUsernameOrEmail(identifier) {
  return get(
    `SELECT id, username, email, password_hash, role, created_at
     FROM users
     WHERE username = ? OR email = ?`,
    [identifier, identifier]
  );
}

function findUserById(userId) {
  return get(
    `SELECT id, username, email, password_hash, role, created_at
     FROM users
     WHERE id = ?`,
    [userId]
  );
}

function listUsers() {
  return all(
    `SELECT id, username, email, password_hash, role, created_at
     FROM users
     ORDER BY id ASC`
  );
}

async function createUser({ username, email, password, role }) {
  const passwordHash = await bcrypt.hash(password, 12);
  return run(
    "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
    [username, email, passwordHash, role]
  );
}

async function updateUserById(userId, { username, email, role, newPassword }) {
  const assignments = ["username = ?", "email = ?", "role = ?"];
  const params = [username, email, role];

  if (newPassword) {
    const passwordHash = await bcrypt.hash(newPassword, 12);
    assignments.push("password_hash = ?");
    params.push(passwordHash);
  }

  params.push(userId);

  return run(
    `UPDATE users
     SET ${assignments.join(", ")}
     WHERE id = ?`,
    params
  );
}

function deleteUserById(userId) {
  return run("DELETE FROM users WHERE id = ?", [userId]);
}

function logActivity({ userId, action, target, status, details }) {
  return run(
    `INSERT INTO activity_logs (user_id, action, target, status, details)
     VALUES (?, ?, ?, ?, ?)`,
    [userId || null, action, target || null, status, details || null]
  );
}

function fetchActivityLogs(limit = 200) {
  return all(
    `SELECT l.*, u.username, u.role
     FROM activity_logs l
     LEFT JOIN users u ON u.id = l.user_id
     ORDER BY l.id DESC
     LIMIT ?`,
    [limit]
  );
}

function fetchActivityLogsByUserId(userId, limit = 200) {
  return all(
    `SELECT l.*, u.username, u.role
     FROM activity_logs l
     LEFT JOIN users u ON u.id = l.user_id
     WHERE l.user_id = ?
     ORDER BY l.id DESC
     LIMIT ?`,
    [userId, limit]
  );
}

function deleteActivityLogById(logId) {
  return run("DELETE FROM activity_logs WHERE id = ?", [logId]);
}

function clearActivityLogs() {
  return run("DELETE FROM activity_logs");
}

function getMonitoredAsset(domain) {
  return get(
    `SELECT id, domain, baseline_json, last_checked_at, created_by
     FROM monitored_assets
     WHERE domain = ?`,
    [domain]
  );
}

function upsertMonitoredAsset(domain, baselineJson, createdBy) {
  return run(
    `INSERT INTO monitored_assets (domain, baseline_json, created_by)
     VALUES (?, ?, ?)
     ON CONFLICT(domain) DO UPDATE SET
       baseline_json = excluded.baseline_json,
       last_checked_at = CURRENT_TIMESTAMP,
       created_by = COALESCE(monitored_assets.created_by, excluded.created_by)`,
    [domain, baselineJson, createdBy || null]
  );
}

function createAlert({ assetDomain, alertType, severity, message, source, dataJson, status }) {
  return run(
    `INSERT INTO alerts (asset_domain, alert_type, severity, message, source, data_json, status)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      assetDomain || null,
      alertType,
      severity,
      message,
      source || null,
      dataJson ? JSON.stringify(dataJson) : null,
      status || "OPEN",
    ]
  );
}

function listOpenAlerts(limit = 200) {
  return all(
    `SELECT id, asset_domain, alert_type, severity, message, source, data_json, status, created_at
     FROM alerts
     WHERE status = 'OPEN'
     ORDER BY id DESC
     LIMIT ?`,
    [limit]
  );
}

function closeAlert(alertId) {
  return run("UPDATE alerts SET status = 'CLOSED' WHERE id = ?", [alertId]);
}

async function countDashboardStats() {
  try {
    const [users, logs, alerts, assets] = await Promise.all([
      get("SELECT COUNT(*) AS total FROM users"),
      get("SELECT COUNT(*) AS total FROM activity_logs"),
      get("SELECT COUNT(*) AS total FROM alerts WHERE status = 'OPEN'"),
      get("SELECT COUNT(*) AS total FROM monitored_assets"),
    ]);

    return {
      users: users?.total || 0,
      logs: logs?.total || 0,
      openAlerts: alerts?.total || 0,
      monitoredAssets: assets?.total || 0,
    };
  } catch (error) {
    console.error("Stats query failed:", error.message);
    return {
      users: 0,
      logs: 0,
      openAlerts: 0,
      monitoredAssets: 0,
    };
  }
}

module.exports = {
  dbPath,
  run,
  get,
  all,
  initDb,
  createUser,
  updateUserById,
  findUserByUsernameOrEmail,
  findUserById,
  listUsers,
  deleteUserById,
  logActivity,
  fetchActivityLogs,
  fetchActivityLogsByUserId,
  deleteActivityLogById,
  clearActivityLogs,
  getMonitoredAsset,
  upsertMonitoredAsset,
  createAlert,
  listOpenAlerts,
  closeAlert,
  countDashboardStats,
};
