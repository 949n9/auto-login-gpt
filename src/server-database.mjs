import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

export const JOB_ARTIFACT_FILENAMES = Object.freeze([
  "login-checkpoint.json",
  "sub2api-import-oauth.json",
  "totp-setup-result.json",
  "password-add-result.json",
]);
const JOB_META_FILENAME = "job-meta.json";
const MONITOR_FILENAME = "sub2api-monitor.json";
const SAFE_JOB_ID = /^[a-zA-Z0-9_-]{1,128}$/;
const SETTINGS_SECTIONS = new Set(["proxyLibrary", "sms", "mail", "sub2api"]);

// Every business payload is authenticated and encrypted. IDs remain queryable;
// passwords, proxy credentials, API keys, cookies, tokens and logs do not.
export function createServerDatabase(options = {}) {
  const outputRoot = path.resolve(options.outputRoot || process.env.ONBOARDING_OUTPUT_ROOT || ".");
  const databasePath = path.resolve(options.databasePath || path.join(outputRoot, "tosub2.sqlite3"));
  const keyPath = path.join(path.dirname(databasePath), ".tosub2-database-key");
  const mustExist = options.mustExist === true;
  if (mustExist && (!fs.existsSync(databasePath) || !fs.existsSync(keyPath))) {
    throw new Error("服务器数据库或加密密钥不存在，已停止写入");
  }
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });
  let key;
  try {
    key = fs.readFileSync(keyPath);
  } catch (error) {
    if (error.code !== "ENOENT" || fs.existsSync(databasePath)) {
      throw new Error("服务器数据库加密密钥无法读取，已保留现有数据");
    }
    const descriptor = fs.openSync(keyPath, "wx", 0o600);
    try {
      key = crypto.randomBytes(32);
      fs.writeFileSync(descriptor, key);
      fs.fsyncSync(descriptor);
    } finally { fs.closeSync(descriptor); }
  }
  if (key.length !== 32) throw new Error("服务器数据库加密密钥格式错误，已保留现有数据");
  fs.chmodSync(keyPath, 0o600);
  const database = new DatabaseSync(databasePath);
  fs.chmodSync(databasePath, 0o600);
  database.exec("PRAGMA busy_timeout=10000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
  database.exec(`
    CREATE TABLE IF NOT EXISTS records (
      kind TEXT NOT NULL, id TEXT NOT NULL, payload BLOB NOT NULL,
      updated_at TEXT NOT NULL, PRIMARY KEY (kind,id)
    );
    CREATE TABLE IF NOT EXISTS settings (
      section TEXT PRIMARY KEY, revision INTEGER NOT NULL, payload BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS deleted_jobs (id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS migrations (name TEXT PRIMARY KEY);
  `);
  const selectRecord = database.prepare("SELECT payload FROM records WHERE kind=? AND id=?");
  const upsertRecord = database.prepare("INSERT INTO records(kind,id,payload,updated_at) VALUES(?,?,?,?) ON CONFLICT(kind,id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at");
  const deleteRecord = database.prepare("DELETE FROM records WHERE kind=? AND id=?");
  const isDeleted = database.prepare("SELECT 1 FROM deleted_jobs WHERE id=?");
  const selectSetting = database.prepare("SELECT revision,payload FROM settings WHERE section=?");
  const upsertSetting = database.prepare("INSERT INTO settings(section,revision,payload) VALUES(?,?,?) ON CONFLICT(section) DO UPDATE SET revision=excluded.revision,payload=excluded.payload");

  function encrypt(value, context) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    cipher.setAAD(Buffer.from(context));
    const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), "utf8"), cipher.final()]);
    return Buffer.concat([Buffer.from([1]), iv, cipher.getAuthTag(), encrypted]);
  }
  function decrypt(payload, context) {
    try {
      const bytes = Buffer.from(payload);
      if (bytes[0] !== 1 || bytes.length < 30) throw new Error();
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, bytes.subarray(1, 13));
      decipher.setAAD(Buffer.from(context));
      decipher.setAuthTag(bytes.subarray(13, 29));
      return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(29)), decipher.final()]).toString("utf8"));
    } catch {
      throw new Error("服务器数据库内容无法解密，已停止恢复并保留数据");
    }
  }
  function get(kind, id) {
    const row = selectRecord.get(kind, id);
    return row ? decrypt(row.payload, `${kind}:${id}`) : null;
  }
  function put(kind, id, value) {
    upsertRecord.run(kind, id, encrypt(value, `${kind}:${id}`), new Date().toISOString());
  }
  function transaction(operation) {
    database.exec("BEGIN IMMEDIATE");
    try { const result = operation(); database.exec("COMMIT"); return result; }
    catch (error) { database.exec("ROLLBACK"); throw error; }
  }
  function assertJobId(id) {
    if (typeof id !== "string" || !SAFE_JOB_ID.test(id)) throw new Error("任务数据标识无效");
  }
  function artifactLocation(filePath) {
    const relative = path.relative(outputRoot, path.resolve(filePath));
    const parts = relative.split(path.sep);
    if (parts.length !== 2 || !SAFE_JOB_ID.test(parts[0]) || !JOB_ARTIFACT_FILENAMES.includes(parts[1])) return null;
    return { jobId: parts[0], filename: parts[1], id: `${parts[0]}/${parts[1]}` };
  }
  function readJsonFile(filePath) {
    try { return JSON.parse(fs.readFileSync(filePath, "utf8")); }
    catch (error) { if (error.code === "ENOENT") return null; throw new Error("现有任务数据文件无法读取，已停止迁移并保留原文件"); }
  }
  function writeWorkingJson(filePath, value) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const temporaryPath = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
      fs.writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
      fs.renameSync(temporaryPath, filePath);
      fs.chmodSync(filePath, 0o600);
    } finally { fs.rmSync(temporaryPath, { force: true }); }
  }
  function settingsSnapshot() {
    const settings = {};
    const revisions = {};
    for (const row of database.prepare("SELECT section,revision,payload FROM settings").all()) {
      if (!SETTINGS_SECTIONS.has(row.section)) continue;
      settings[row.section] = decrypt(row.payload, `settings:${row.section}`);
      revisions[row.section] = row.revision;
    }
    return { settings, revisions };
  }

  return {
    databasePath, outputRoot, keyPath,
    close() { database.close(); key.fill(0); },
    transaction,
    recordIds: (kind) => database.prepare("SELECT id FROM records WHERE kind=? ORDER BY id").all(kind).map((row) => row.id),
    get, put, remove: (kind, id) => deleteRecord.run(kind, id),
    getSettings: settingsSnapshot,
    putSetting(section, value, expectedRevision) {
      if (!SETTINGS_SECTIONS.has(section)) throw new Error("配置类型无效");
      return transaction(() => {
        const current = selectSetting.get(section);
        const revision = current?.revision || 0;
        if (revision !== expectedRevision) return { conflict: true, ...settingsSnapshot() };
        upsertSetting.run(section, revision + 1, encrypt(value, `settings:${section}`));
        return { conflict: false, ...settingsSnapshot() };
      });
    },
    migrateSettings(values) {
      return transaction(() => {
        for (const [section, value] of Object.entries(values)) {
          if (!SETTINGS_SECTIONS.has(section)) throw new Error("配置类型无效");
          if (!selectSetting.get(section)) upsertSetting.run(section, 1, encrypt(value, `settings:${section}`));
        }
        return settingsSnapshot();
      });
    },
    saveCredentials(email, value) { put("credentials", String(email).trim().toLowerCase(), value); },
    loadCredentials(email) { return get("credentials", String(email).trim().toLowerCase()) || {}; },
    deleteCredentials(email) { deleteRecord.run("credentials", String(email).trim().toLowerCase()); },
    saveJob(id, metadata) {
      assertJobId(id);
      if (isDeleted.get(id)) return false;
      put("job", id, metadata);
      return true;
    },
    getJob(id) { return get("job", id); },
    saveLogs(id, logs) {
      assertJobId(id);
      if (!isDeleted.get(id)) put("job-logs", id, logs);
    },
    jobIds() { return database.prepare("SELECT id FROM records WHERE kind='job'").all().map((row) => row.id); },
    deleteJob(id) {
      assertJobId(id);
      transaction(() => {
        database.prepare("INSERT OR IGNORE INTO deleted_jobs(id) VALUES(?)").run(id);
        deleteRecord.run("job", id);
        deleteRecord.run("job-logs", id);
        deleteRecord.run("account-history", id);
        for (const filename of JOB_ARTIFACT_FILENAMES) deleteRecord.run("artifact", `${id}/${filename}`);
      });
    },
    artifactLocation,
    saveArtifact(filePath, value) {
      const location = artifactLocation(filePath);
      if (!location) return false;
      return transaction(() => {
        if (isDeleted.get(location.jobId)) return false;
        put("artifact", location.id, value);
        return true;
      });
    },
    readArtifact(filePath) {
      const location = artifactLocation(filePath);
      return location ? get("artifact", location.id) : null;
    },
    removeArtifact(filePath) {
      const location = artifactLocation(filePath);
      if (location) deleteRecord.run("artifact", location.id);
    },
    migrateLegacy() {
      if (database.prepare("SELECT 1 FROM migrations WHERE name='legacy-files-v1'").get()) return;
      transaction(() => {
        for (const entry of fs.readdirSync(outputRoot, { withFileTypes: true })) {
          if (!entry.isDirectory() || !SAFE_JOB_ID.test(entry.name)) continue;
          const directory = path.join(outputRoot, entry.name);
          const metadata = readJsonFile(path.join(directory, JOB_META_FILENAME));
          let recoveredMetadata = metadata;
          for (const filename of JOB_ARTIFACT_FILENAMES) {
            const value = readJsonFile(path.join(directory, filename));
            if (value === null) continue;
            put("artifact", `${entry.name}/${filename}`, value);
            if (!recoveredMetadata && filename === "sub2api-import-oauth.json") {
              const account = value?.accounts?.[0];
              const email = account?.credentials?.email || account?.extra?.email || account?.name;
              if (email) recoveredMetadata = { version: 1, email };
            }
            if (!recoveredMetadata && filename === "login-checkpoint.json" && value?.email) recoveredMetadata = { version: 1, email: value.email };
          }
          if (recoveredMetadata) put("job", entry.name, recoveredMetadata);
        }
        const monitor = readJsonFile(path.join(outputRoot, MONITOR_FILENAME));
        if (monitor !== null) put("runtime", "sub2api-monitor", monitor);
        database.prepare("INSERT INTO migrations(name) VALUES('legacy-files-v1')").run();
      });
    },
    restoreWorkspace() {
      // Validate all encrypted records before touching any recoverable work copy.
      const restoredJobs = database.prepare("SELECT id,payload FROM records WHERE kind='job'").all().map((row) => {
        assertJobId(row.id);
        return { id: row.id, value: decrypt(row.payload, `job:${row.id}`) };
      });
      const restoredArtifacts = database.prepare("SELECT id,payload FROM records WHERE kind='artifact'").all().map((row) => {
        const target = path.join(outputRoot, row.id);
        if (!artifactLocation(target)) throw new Error("数据库工作文件路径无效");
        return { target, value: decrypt(row.payload, `artifact:${row.id}`) };
      });
      for (const row of database.prepare("SELECT kind,id,payload FROM records WHERE kind NOT IN ('job','artifact')").all()) {
        decrypt(row.payload, `${row.kind}:${row.id}`);
      }
      settingsSnapshot();
      const monitor = get("runtime", "sub2api-monitor");
      // Old cache files never recreate deleted database records.
      for (const entry of fs.readdirSync(outputRoot, { withFileTypes: true })) {
        if (!entry.isDirectory() || !SAFE_JOB_ID.test(entry.name)) continue;
        for (const filename of [JOB_META_FILENAME, ...JOB_ARTIFACT_FILENAMES]) {
          fs.rmSync(path.join(outputRoot, entry.name, filename), { force: true });
        }
      }
      for (const row of restoredJobs) {
        writeWorkingJson(path.join(outputRoot, row.id, JOB_META_FILENAME), row.value);
      }
      for (const row of restoredArtifacts) {
        writeWorkingJson(row.target, row.value);
      }
      if (monitor) writeWorkingJson(path.join(outputRoot, MONITOR_FILENAME), monitor);
      else fs.rmSync(path.join(outputRoot, MONITOR_FILENAME), { force: true });
    },
  };
}
