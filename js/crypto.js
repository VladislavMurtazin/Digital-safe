const KDF_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const MIN_PASSWORD_LENGTH = 12;
const STORAGE_KEYS = {
  salt: "vault_salt",
  data: "vault_data",
  settings: "vault_settings",
  lockout: "vault_lockout",
};
const FAILURE_LIMIT = 5;
const DAY_MS = 24 * 60 * 60 * 1000;
const IMPORT_ERROR = "Неверный пароль или файл поврежден";
const BACKUP_FILE_LIMIT = 1_000_000;

/**
 * Ошибка криптооперации, которую можно показать в интерфейсе.
 * Внутренние детали Web Crypto в сообщение не попадают.
 */
export class VaultCryptoError extends Error {
  constructor(message) {
    super(message);
    this.name = "VaultCryptoError";
  }
}

/**
 * Создаёт соль KDF один раз на сейф. Это не секрет и не IV.
 * @returns {Uint8Array}
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_BYTES));
}

/**
 * Выводит неэкспортируемый ключ AES-256-GCM из мастер-пароля.
 * Пароль нормализуется в NFKC, чтобы одинаковый на вид текст
 * давал одни и те же байты на разных ОС.
 * @param {string} password
 * @param {Uint8Array} salt 16 байт из generateSalt()
 * @param {number} [iterations]
 * @returns {Promise<CryptoKey>}
 */
export async function deriveKey(password, salt, iterations = KDF_ITERATIONS) {
  if (typeof password !== "string" || password.normalize("NFKC") === "") {
    throw new VaultCryptoError("Введите мастер-пароль");
  }
  if (password.normalize("NFKC").length < MIN_PASSWORD_LENGTH) {
    throw new VaultCryptoError("Мастер-пароль должен быть не короче 12 символов");
  }
  if (!(salt instanceof Uint8Array) || salt.byteLength !== SALT_BYTES) {
    throw new VaultCryptoError("Соль сейфа повреждена");
  }
  if (!Number.isInteger(iterations) || iterations < 100_000 || iterations > 10_000_000) {
    throw new VaultCryptoError("Параметры сейфа повреждены");
  }

  const normalized = password.normalize("NFKC");
  const passwordBytes = new TextEncoder().encode(normalized);
  const baseKey = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Шифрует текст. Новый IV на каждый вызов. Соль сюда не входит:
 * она принадлежит заголовку сейфа и не меняется при сохранении.
 * @param {string} plaintext
 * @param {CryptoKey} key
 * @returns {Promise<{ iv: string, ciphertext: string }>}
 */
export async function encryptData(plaintext, key) {
  if (typeof plaintext !== "string") {
    throw new VaultCryptoError("Нечего шифровать");
  }

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    return {
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
    };
  } catch {
    throw new VaultCryptoError("Не удалось зашифровать данные");
  }
}

/**
 * Расшифровывает объект { iv, ciphertext } в base64.
 * OperationError означает неверный ключ или подмену шифротекста.
 * @param {{ iv: string, ciphertext: string }} encryptedObj
 * @param {CryptoKey} key
 * @returns {Promise<string>}
 */
export async function decryptData(encryptedObj, key) {
  try {
    const iv = base64ToBytes(encryptedObj.iv);
    const ciphertext = base64ToBytes(encryptedObj.ciphertext);
    if (iv.byteLength !== IV_BYTES || ciphertext.byteLength < 16) {
      throw new VaultCryptoError("Данные сейфа повреждены");
    }
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    if (error instanceof VaultCryptoError) {
      throw error;
    }
    throw new VaultCryptoError("Неверный пароль");
  }
}

/**
 * Проверяет ядро без записи на диск и без вывода секретов.
 * Три вывода ключа занимают несколько секунд из-за 600 000 итераций.
 * @returns {Promise<void>}
 */
export async function runCryptoSelfTest() {
  const salt = generateSalt();
  const nfdPassword = "\u0435\u0308-vault-check";
  const nfcPassword = "\u0451-vault-check";
  const plaintext = "тест 🔐";

  const keyFromNfd = await deriveKey(nfdPassword, salt);
  const keyFromNfc = await deriveKey(nfcPassword, salt);
  const encrypted = await encryptData(plaintext, keyFromNfd);
  const decrypted = await decryptData(encrypted, keyFromNfc);
  if (decrypted !== plaintext) {
    throw new VaultCryptoError("Проверка шифрования не пройдена");
  }

  const again = await encryptData(plaintext, keyFromNfc);
  if (again.iv === encrypted.iv) {
    throw new VaultCryptoError("IV повторился");
  }

  const wrongKey = await deriveKey("другой-пароль-12", salt);
  try {
    await decryptData(encrypted, wrongKey);
    throw new VaultCryptoError("Чужой ключ открыл сейф");
  } catch (error) {
    if (!(error instanceof VaultCryptoError)) {
      throw new VaultCryptoError("Проверка отказа не пройдена");
    }
    if (error.message === "Чужой ключ открыл сейф") {
      throw error;
    }
  }
}

/**
 * Открывает существующий сейф или создаёт новый пустой.
 * Ключ остаётся только в window.currentKey.
 * @param {string} password
 * @returns {Promise<{ created: boolean }>}
 */
export async function unlockVault(password) {
  const stored = readStoredVault();
  if (!stored) {
    const salt = generateSalt();
    const key = await deriveKey(password, salt);
    const encrypted = await encryptData("", key);
    writeStoredVault({
      saltB64: bytesToBase64(salt),
      iterations: KDF_ITERATIONS,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
    });
    holdSession(key, "");
    clearLockout();
    return { created: true };
  }

  assertVaultOpen();
  try {
    const key = await deriveKey(password, stored.salt, stored.iterations);
    const plaintext = await decryptData(stored, key);
    clearLockout();
    holdSession(key, plaintext);
    return { created: false };
  } catch (error) {
    if (error instanceof VaultCryptoError && error.message === "Неверный пароль") {
      throw new VaultCryptoError(recordFailedAttempt());
    }
    throw error;
  }
}

/**
 * Шифрует заметку текущим ключом и перезаписывает vault_data.
 * Соль не меняется. IV создаётся заново.
 * @param {string} plaintext
 * @returns {Promise<void>}
 */
export async function saveToVault(plaintext) {
  const key = window.currentKey;
  const meta = openMeta;
  if (!key || !meta) {
    throw new VaultCryptoError("Сейф заблокирован");
  }
  if (typeof plaintext !== "string" || plaintext.trim() === "") {
    const error = new VaultCryptoError("Заметка пустая. Сохранять нечего.");
    error.warning = true;
    throw error;
  }

  const encrypted = await encryptData(plaintext, key);
  if (window.currentKey !== key || openMeta !== meta) {
    throw new VaultCryptoError("Сейф заблокирован");
  }
  writeStoredVault({
    saltB64: meta.saltB64,
    iterations: meta.iterations,
    iv: encrypted.iv,
    ciphertext: encrypted.ciphertext,
  });
  savedPlaintext = plaintext;
}

/**
 * Сбрасывает ключ из памяти и возвращает на экран входа.
 * Шифротекст в localStorage не удаляется.
 * @param {{ force?: boolean }} [options]
 * @returns {boolean} false, если выход отменён из-за несохранённого текста
 */
export function lockVault(options = {}) {
  if (busy) {
    return false;
  }
  if (!window.currentKey) {
    showLogin();
    return true;
  }
  if (!options.force && isDirty()) {
    const leave = window.confirm("Есть несохраненные изменения. Выйти без сохранения?");
    if (!leave) {
      return false;
    }
  }

  forgetSession();
  showLogin();
  return true;
}

let openMeta = null;
let savedPlaintext = "";
let busy = false;
let saveNoticeTimer = 0;

function holdSession(key, plaintext) {
  window.currentKey = key;
  const stored = readStoredVault();
  openMeta = stored
    ? { saltB64: bytesToBase64(stored.salt), iterations: stored.iterations }
    : null;
  savedPlaintext = plaintext;
}

function readStoredVault() {
  const saltB64 = localStorage.getItem(STORAGE_KEYS.salt);
  const rawData = localStorage.getItem(STORAGE_KEYS.data);
  if (!saltB64 && !rawData) {
    return null;
  }
  if (!saltB64 || !rawData) {
    throw new VaultCryptoError("Данные сейфа повреждены");
  }

  let parsed;
  try {
    parsed = JSON.parse(rawData);
  } catch {
    throw new VaultCryptoError("Данные сейфа повреждены");
  }
  if (!parsed || typeof parsed.iv !== "string" || typeof parsed.ciphertext !== "string") {
    throw new VaultCryptoError("Данные сейфа повреждены");
  }

  const iterations = parsed.kdf == null
    ? KDF_ITERATIONS
    : parsed.kdf.iterations;

  return {
    salt: base64ToBytes(saltB64),
    iterations,
    iv: parsed.iv,
    ciphertext: parsed.ciphertext,
  };
}

function writeStoredVault({ saltB64, iterations, iv, ciphertext }) {
  const envelope = {
    version: 1,
    kdf: {
      algo: "PBKDF2",
      hash: "SHA-256",
      iterations,
    },
    iv,
    ciphertext,
  };
  try {
    localStorage.setItem(STORAGE_KEYS.salt, saltB64);
    localStorage.setItem(STORAGE_KEYS.data, JSON.stringify(envelope));
    if (localStorage.getItem(STORAGE_KEYS.settings) === null) {
      localStorage.setItem(STORAGE_KEYS.settings, "{}");
    }
  } catch {
    throw new VaultCryptoError("Не удалось сохранить");
  }
}

function readSettings() {
  const raw = localStorage.getItem(STORAGE_KEYS.settings);
  if (!raw) {
    return {};
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    return parsed;
  } catch {
    return {};
  }
}

function plainSettings(value) {
  if (value == null) {
    return {};
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new VaultCryptoError(IMPORT_ERROR);
  }
  const settings = {};
  for (const key of Object.keys(value)) {
    settings[key] = value[key];
  }
  return settings;
}

function parseBackup(value) {
  let backup = value;
  if (typeof value === "string") {
    try {
      backup = JSON.parse(value);
    } catch {
      throw new VaultCryptoError(IMPORT_ERROR);
    }
  }
  if (!backup || typeof backup !== "object" || Array.isArray(backup)) {
    throw new VaultCryptoError(IMPORT_ERROR);
  }
  if (backup.version !== 1) {
    throw new VaultCryptoError(IMPORT_ERROR);
  }
  if (!backup.kdf || backup.kdf.algo !== "PBKDF2" || backup.kdf.hash !== "SHA-256") {
    throw new VaultCryptoError(IMPORT_ERROR);
  }
  if (typeof backup.salt !== "string" || !backup.data) {
    throw new VaultCryptoError(IMPORT_ERROR);
  }
  if (typeof backup.data.iv !== "string" || typeof backup.data.ciphertext !== "string") {
    throw new VaultCryptoError(IMPORT_ERROR);
  }

  return {
    salt: backup.salt,
    iterations: backup.kdf.iterations,
    iv: backup.data.iv,
    ciphertext: backup.data.ciphertext,
    settings: plainSettings(backup.settings),
  };
}

function backupFilename(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `digital-safe-backup-${year}-${month}-${day}.json`;
}

function downloadBackup(filename, json) {
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}

/**
 * Скачивает зашифрованный сейф. Блокировка устройства в файл не входит:
 * это счётчик конкретного браузера, а не часть сейфа.
 */
export function exportVault() {
  const stored = readStoredVault();
  if (!stored) {
    throw new VaultCryptoError("Сейф ещё не создан");
  }
  const backup = {
    version: 1,
    kdf: {
      algo: "PBKDF2",
      hash: "SHA-256",
      iterations: stored.iterations,
    },
    salt: bytesToBase64(stored.salt),
    data: {
      iv: stored.iv,
      ciphertext: stored.ciphertext,
    },
    settings: readSettings(),
  };
  downloadBackup(backupFilename(), JSON.stringify(backup, null, 2));
}

function restoreStoredKey(key, value) {
  if (value === null) {
    localStorage.removeItem(key);
    return;
  }
  localStorage.setItem(key, value);
}

function commitImportedVault(parsed) {
  const previous = {
    salt: localStorage.getItem(STORAGE_KEYS.salt),
    data: localStorage.getItem(STORAGE_KEYS.data),
    settings: localStorage.getItem(STORAGE_KEYS.settings),
    lockout: localStorage.getItem(STORAGE_KEYS.lockout),
  };
  try {
    writeStoredVault({
      saltB64: parsed.salt,
      iterations: parsed.iterations,
      iv: parsed.iv,
      ciphertext: parsed.ciphertext,
    });
    localStorage.setItem(STORAGE_KEYS.settings, JSON.stringify(parsed.settings));
    localStorage.removeItem(STORAGE_KEYS.lockout);
  } catch (error) {
    restoreStoredKey(STORAGE_KEYS.salt, previous.salt);
    restoreStoredKey(STORAGE_KEYS.data, previous.data);
    restoreStoredKey(STORAGE_KEYS.settings, previous.settings);
    restoreStoredKey(STORAGE_KEYS.lockout, previous.lockout);
    if (error instanceof VaultCryptoError) {
      throw error;
    }
    throw new VaultCryptoError("Не удалось сохранить");
  }
}

/**
 * Проверяет файл паролем и только потом заменяет локальный сейф.
 * Неверный пароль не меняет localStorage и не считается попыткой входа.
 * @param {object | string} backup
 * @param {string} password
 * @returns {Promise<string>} расшифрованная заметка
 */
export async function importVault(backup, password) {
  const parsed = parseBackup(backup);
  let key;
  try {
    const salt = base64ToBytes(parsed.salt);
    key = await deriveKey(password, salt, parsed.iterations);
  } catch (error) {
    if (error instanceof VaultCryptoError && (
      error.message === "Введите мастер-пароль"
      || error.message === "Мастер-пароль должен быть не короче 12 символов"
    )) {
      throw error;
    }
    throw new VaultCryptoError(IMPORT_ERROR);
  }

  let plaintext;
  try {
    plaintext = await decryptData({
      iv: parsed.iv,
      ciphertext: parsed.ciphertext,
    }, key);
  } catch {
    throw new VaultCryptoError(IMPORT_ERROR);
  }

  commitImportedVault(parsed);
  holdSession(key, plaintext);
  return plaintext;
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      resolve(typeof reader.result === "string" ? reader.result : "");
    };
    reader.onerror = () => {
      reject(new VaultCryptoError(IMPORT_ERROR));
    };
    reader.readAsText(file);
  });
}

function emptyLockout() {
  return { failures: 0, tier: 0, lockedUntil: null };
}

function readLockout() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.lockout);
    if (!raw) {
      return emptyLockout();
    }
    const parsed = JSON.parse(raw);
    const failures = Number.isInteger(parsed.failures)
      ? Math.min(Math.max(parsed.failures, 0), FAILURE_LIMIT)
      : 0;
    const tier = Number.isInteger(parsed.tier)
      ? Math.min(Math.max(parsed.tier, 0), 2)
      : 0;
    const lockedUntil = Number.isFinite(parsed.lockedUntil) ? parsed.lockedUntil : null;
    return { failures, tier, lockedUntil };
  } catch {
    return emptyLockout();
  }
}

function writeLockout(state) {
  localStorage.setItem(STORAGE_KEYS.lockout, JSON.stringify(state));
}

function clearLockout() {
  localStorage.removeItem(STORAGE_KEYS.lockout);
}

function vaultExists() {
  return Boolean(
    localStorage.getItem(STORAGE_KEYS.salt)
    && localStorage.getItem(STORAGE_KEYS.data)
  );
}

function settleLockout(now = Date.now()) {
  const state = readLockout();
  if (state.lockedUntil && now >= state.lockedUntil) {
    const open = { failures: 0, tier: state.tier, lockedUntil: null };
    writeLockout(open);
    return open;
  }
  return state;
}

function formatAttemptMoment(timestamp) {
  return new Intl.DateTimeFormat("ru-RU", {
    day: "numeric",
    month: "long",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(timestamp));
}

function attemptsLeftText(count) {
  if (count === 1) {
    return "Осталась 1 попытка";
  }
  if (count > 1 && count < 5) {
    return `Осталось ${count} попытки`;
  }
  return `Осталось ${count} попыток`;
}

function lockoutText(state) {
  const lengthLabel = state.tier <= 1 ? "1 сутки" : "3 суток";
  return `Ввод заблокирован на ${lengthLabel}. Следующая попытка: ${formatAttemptMoment(state.lockedUntil)}.`;
}

function assertVaultOpen() {
  if (!vaultExists()) {
    return;
  }
  const state = settleLockout();
  if (state.lockedUntil && Date.now() < state.lockedUntil) {
    throw new VaultCryptoError(lockoutText(state));
  }
}

function recordFailedAttempt() {
  const state = settleLockout();
  const failures = state.failures + 1;
  if (failures < FAILURE_LIMIT) {
    writeLockout({ ...state, failures, lockedUntil: null });
    return `Неверный пароль. ${attemptsLeftText(FAILURE_LIMIT - failures)}.`;
  }

  const lockedUntil = Date.now() + (state.tier === 0 ? DAY_MS : 3 * DAY_MS);
  const next = {
    failures: 0,
    tier: Math.min(state.tier + 1, 2),
    lockedUntil,
  };
  writeLockout(next);
  return `Неверный пароль. ${lockoutText(next)}`;
}

function forgetSession() {
  window.currentKey = null;
  openMeta = null;
  savedPlaintext = "";
  const note = document.querySelector("#note");
  if (note) {
    note.value = "";
  }
  const recoveryKey = document.querySelector("#dms-key-output");
  const recoveryResult = document.querySelector("#dms-result");
  const recoveryPanel = document.querySelector("#dms-panel");
  if (recoveryKey) {
    recoveryKey.value = "";
  }
  if (recoveryResult) {
    recoveryResult.textContent = "";
    recoveryResult.className = "result";
  }
  if (recoveryPanel) {
    recoveryPanel.open = false;
  }
}

function showLogin() {
  const login = document.querySelector("#login-screen");
  const vault = document.querySelector("#vault-screen");
  const unlockResult = document.querySelector("#unlock-result");
  const passwordInput = document.querySelector("#master-password");
  if (!login || !vault || !passwordInput) {
    return;
  }
  forgetSession();
  login.hidden = false;
  vault.hidden = true;
  if (unlockResult) {
    unlockResult.textContent = "";
    unlockResult.className = "result";
  }
  passwordInput.value = "";
  setPasswordVisible(false);
  passwordInput.focus();
}

function setPasswordVisible(visible, inputSelector = "#master-password", toggleSelector = "#toggle-password") {
  const passwordInput = document.querySelector(inputSelector);
  const toggle = document.querySelector(toggleSelector);
  if (!passwordInput || !toggle) {
    return;
  }
  const value = passwordInput.value;
  const caret = passwordInput.selectionStart;
  passwordInput.type = visible ? "text" : "password";
  passwordInput.value = value;
  if (document.activeElement === passwordInput && caret !== null) {
    passwordInput.setSelectionRange(caret, caret);
  }
  toggle.classList.toggle("is-on", visible);
  toggle.setAttribute("aria-pressed", visible ? "true" : "false");
  toggle.setAttribute("aria-label", visible ? "Скрыть пароль" : "Показать пароль");
}

function isDirty() {
  const note = document.querySelector("#note");
  return Boolean(note) && note.value !== savedPlaintext;
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    const chunk = bytes.subarray(offset, offset + chunkSize);
    binary += String.fromCharCode.apply(null, chunk);
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new VaultCryptoError("Данные сейфа повреждены");
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new VaultCryptoError("Данные сейфа повреждены");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

export function boot() {
  window.currentKey = null;
  const secure = window.isSecureContext && Boolean(crypto.subtle);
  const status = document.querySelector("#context-status");
  const passwordInput = document.querySelector("#master-password");
  const unlockButton = document.querySelector("#unlock-button");
  const unlockSpinner = document.querySelector("#unlock-spinner");
  const unlockResult = document.querySelector("#unlock-result");
  const selfTestButton = document.querySelector("#self-test");
  const selfTestSpinner = document.querySelector("#self-test-spinner");
  const selfTestResult = document.querySelector("#self-test-result");
  const note = document.querySelector("#note");
  const saveButton = document.querySelector("#save-button");
  const exportButton = document.querySelector("#export-button");
  const lockButton = document.querySelector("#lock-button");
  const vaultSpinner = document.querySelector("#vault-spinner");
  const vaultResult = document.querySelector("#vault-result");
  const loginImportButton = document.querySelector("#login-import-button");
  const vaultImportButton = document.querySelector("#vault-import-button");
  const importFile = document.querySelector("#import-file");
  const importDialog = document.querySelector("#import-dialog");
  const importPassword = document.querySelector("#import-password");
  const importToggle = document.querySelector("#toggle-import-password");
  const importConfirm = document.querySelector("#import-confirm");
  const importCancel = document.querySelector("#import-cancel");
  const importSpinner = document.querySelector("#import-spinner");
  const importResult = document.querySelector("#import-result");
  let pendingBackup = null;

  if (secure) {
    status.textContent = "Контекст безопасный. Web Crypto доступен, ключ останется только в этой вкладке.";
    status.className = "status status-ok";
  } else {
    status.textContent = "Web Crypto здесь недоступен. Запустите локальный сервер и откройте http://localhost:8000, а не файл с диска.";
    status.className = "status status-bad";
    unlockButton.disabled = true;
    selfTestButton.disabled = true;
    loginImportButton.disabled = true;
    exportButton.disabled = true;
    vaultImportButton.disabled = true;
  }

  const passwordToggle = document.querySelector("#toggle-password");
  passwordInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      onUnlock();
    }
  });
  passwordToggle.addEventListener("click", () => {
    setPasswordVisible(passwordInput.type === "password");
    passwordInput.focus();
  });
  unlockButton.addEventListener("click", onUnlock);
  saveButton.addEventListener("click", onSave);
  exportButton.addEventListener("click", onExport);
  loginImportButton.addEventListener("click", onImportClick);
  vaultImportButton.addEventListener("click", onImportClick);
  importFile.addEventListener("change", onImportFile);
  importConfirm.addEventListener("click", onImportConfirm);
  importCancel.addEventListener("click", () => {
    if (!busy && importDialog.open) {
      importDialog.close();
    }
  });
  importDialog.addEventListener("close", () => {
    pendingBackup = null;
    importPassword.value = "";
    setPasswordVisible(false, "#import-password", "#toggle-import-password");
    importResult.textContent = "";
    importResult.className = "result";
  });
  importDialog.addEventListener("cancel", (event) => {
    if (busy) {
      event.preventDefault();
    }
  });
  importPassword.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      onImportConfirm();
    }
  });
  importToggle.addEventListener("click", () => {
    setPasswordVisible(importPassword.type === "password", "#import-password", "#toggle-import-password");
    importPassword.focus();
  });
  lockButton.addEventListener("click", () => {
    lockVault();
  });
  selfTestButton.addEventListener("click", onSelfTest);
  let lockoutTimer = 0;
  refreshLockoutNotice();

  document.addEventListener("keydown", (event) => {
    const onboardingDialog = document.querySelector("#onboarding-dialog");
    const onboardingOpen = Boolean(onboardingDialog && onboardingDialog.open);
    if (event.key === "Escape" && (importDialog.open || onboardingOpen)) {
      return;
    }
    if (event.key === "Escape" && window.currentKey) {
      event.preventDefault();
      lockVault();
      return;
    }
    const saveShortcut = (event.ctrlKey || event.metaKey)
      && (event.code === "KeyS" || event.key.toLowerCase() === "s");
    if (saveShortcut) {
      event.preventDefault();
      if (window.currentKey && !importDialog.open && !onboardingOpen) {
        onSave();
      }
    }
  });

  window.addEventListener("beforeunload", (event) => {
    if (window.currentKey && isDirty()) {
      event.preventDefault();
      event.returnValue = "";
    }
  });

  function entryLocked() {
    if (window.currentKey || !vaultExists()) {
      return false;
    }
    const state = settleLockout();
    return Boolean(state.lockedUntil) && Date.now() < state.lockedUntil;
  }

  function refreshLockoutNotice() {
    window.clearTimeout(lockoutTimer);
    const locked = entryLocked();
    passwordInput.disabled = locked;
    if (!busy) {
      unlockButton.disabled = locked || !secure;
      loginImportButton.disabled = locked || !secure;
    }
    if (!locked) {
      if (unlockResult.textContent.startsWith("Ввод заблокирован")) {
        unlockResult.textContent = "";
        unlockResult.className = "result";
      }
      return;
    }
    const state = readLockout();
    unlockResult.textContent = lockoutText(state);
    unlockResult.className = "result result-bad";
    const wait = Math.min(state.lockedUntil - Date.now(), 60_000);
    lockoutTimer = window.setTimeout(refreshLockoutNotice, wait + 250);
  }

  function setBusy(next) {
    busy = next;
    const locked = entryLocked();
    unlockButton.disabled = next || locked || !secure;
    loginImportButton.disabled = next || locked || !secure;
    selfTestButton.disabled = next || !secure;
    saveButton.disabled = next;
    exportButton.disabled = next;
    vaultImportButton.disabled = next;
    lockButton.disabled = next;
    importConfirm.disabled = next;
    importCancel.disabled = next;
    unlockSpinner.hidden = true;
    vaultSpinner.hidden = true;
    selfTestSpinner.hidden = true;
    importSpinner.hidden = true;
  }

  function showVault(plaintext) {
    passwordInput.value = "";
    setPasswordVisible(false);
    document.querySelector("#login-screen").hidden = true;
    document.querySelector("#vault-screen").hidden = false;
    note.value = plaintext;
    vaultResult.textContent = "";
    vaultResult.className = "result";
    note.focus();
  }

  function showImportProblem(message) {
    const target = document.querySelector("#vault-screen").hidden ? unlockResult : vaultResult;
    target.textContent = message;
    target.className = "result result-bad";
  }

  function onExport() {
    if (busy || !window.currentKey) {
      return;
    }
    if (isDirty()) {
      const proceed = window.confirm("Есть несохранённые изменения. В файл попадёт последняя сохранённая копия. Продолжить?");
      if (!proceed) {
        return;
      }
    }
    try {
      exportVault();
      vaultResult.textContent = "Файл резервной копии скачан";
      vaultResult.className = "result result-ok";
    } catch (error) {
      vaultResult.textContent = error instanceof VaultCryptoError
        ? error.message
        : "Не удалось экспортировать";
      vaultResult.className = "result result-bad";
    }
  }

  function onImportClick() {
    if (busy || !secure || importDialog.open) {
      return;
    }
    if (entryLocked()) {
      refreshLockoutNotice();
      return;
    }
    importFile.value = "";
    importFile.click();
  }

  async function onImportFile() {
    const file = importFile.files && importFile.files[0];
    importFile.value = "";
    if (!file || busy) {
      return;
    }
    if (file.size > BACKUP_FILE_LIMIT) {
      showImportProblem(IMPORT_ERROR);
      return;
    }
    try {
      const text = await readFileAsText(file);
      const parsed = JSON.parse(text);
      parseBackup(parsed);
      pendingBackup = parsed;
    } catch (error) {
      pendingBackup = null;
      showImportProblem(error instanceof VaultCryptoError ? error.message : IMPORT_ERROR);
      return;
    }
    const proceed = window.confirm("Это действие перезапишет текущий локальный сейф. Продолжить?");
    if (!proceed) {
      pendingBackup = null;
      return;
    }
    importResult.textContent = "";
    importResult.className = "result";
    importPassword.value = "";
    setPasswordVisible(false, "#import-password", "#toggle-import-password");
    importDialog.showModal();
    importPassword.focus();
  }

  async function onImportConfirm() {
    if (busy || !pendingBackup || !importDialog.open) {
      return;
    }
    const backup = pendingBackup;
    const password = importPassword.value;
    setBusy(true);
    importSpinner.hidden = false;
    importResult.textContent = "";
    importResult.className = "result";
    try {
      const plaintext = await importVault(backup, password);
      document.dispatchEvent(new CustomEvent("vault-imported"));
      if (importDialog.open) {
        importDialog.close();
      }
      showVault(plaintext);
      vaultResult.textContent = "Сейф успешно восстановлен";
      vaultResult.className = "result result-ok";
    } catch (error) {
      importResult.textContent = error instanceof VaultCryptoError
        ? error.message
        : IMPORT_ERROR;
      importResult.className = "result result-bad";
    } finally {
      setBusy(false);
      if (!importDialog.open) {
        refreshLockoutNotice();
      }
    }
  }

  async function onUnlock() {
    if (busy || !secure) {
      return;
    }
    const password = passwordInput.value;
    setBusy(true);
    unlockSpinner.hidden = false;
    unlockResult.textContent = "";
    unlockResult.className = "result";
    let opened = false;
    let created = false;
    try {
      const result = await unlockVault(password);
      created = result.created;
      opened = true;
    } catch (error) {
      unlockResult.textContent = error instanceof VaultCryptoError
        ? error.message
        : "Неверный пароль";
      unlockResult.className = "result result-bad";
    } finally {
      setBusy(false);
    }
    if (!opened) {
      refreshLockoutNotice();
      return;
    }
    const onboardingPending = localStorage.getItem("onboardingPending") === "1";
    if ((created || onboardingPending) && localStorage.getItem("hasSeenOnboarding") !== "1") {
      localStorage.setItem("onboardingPending", "1");
      passwordInput.value = "";
      const openAfterOnboarding = () => {
        document.removeEventListener("onboarding-accepted", openAfterOnboarding);
        showVault(savedPlaintext);
        vaultResult.textContent = created ? "Новый сейф создан" : "Сейф открыт";
        vaultResult.className = "result result-ok";
      };
      document.addEventListener("onboarding-accepted", openAfterOnboarding);
      document.dispatchEvent(new CustomEvent("vault-created"));
      return;
    }
    showVault(savedPlaintext);
    if (created) {
      vaultResult.textContent = "Новый сейф создан";
      vaultResult.className = "result result-ok";
    }
  }

  async function onSave() {
    if (busy || !window.currentKey) {
      return;
    }
    const plaintext = note.value;
    window.clearTimeout(saveNoticeTimer);
    if (plaintext.trim() === "") {
      try {
        await saveToVault(plaintext);
      } catch (error) {
        vaultResult.textContent = error instanceof VaultCryptoError
          ? error.message
          : "Заметка пустая. Сохранять нечего.";
        vaultResult.className = "result result-warn";
      }
      return;
    }
    setBusy(true);
    vaultSpinner.hidden = false;
    window.clearTimeout(saveNoticeTimer);
    try {
      await saveToVault(plaintext);
      vaultResult.textContent = "Сохранено";
      vaultResult.className = "result result-ok";
      saveNoticeTimer = window.setTimeout(() => {
        if (vaultResult.textContent === "Сохранено") {
          vaultResult.textContent = "";
        }
      }, 2000);
    } catch (error) {
      vaultResult.textContent = error instanceof VaultCryptoError
        ? error.message
        : "Не удалось сохранить";
      vaultResult.className = "result result-bad";
    } finally {
      setBusy(false);
    }
  }

  async function onSelfTest() {
    if (busy || !secure) {
      return;
    }
    setBusy(true);
    selfTestSpinner.hidden = false;
    selfTestResult.textContent = "";
    selfTestResult.className = "result";
    try {
      await runCryptoSelfTest();
      selfTestResult.textContent = "Проверка пройдена: NFKC, шифрование и отказ при чужом ключе работают.";
      selfTestResult.className = "result result-ok";
    } catch {
      selfTestResult.textContent = "Проверка не пройдена.";
      selfTestResult.className = "result result-bad";
    } finally {
      setBusy(false);
    }
  }
}

