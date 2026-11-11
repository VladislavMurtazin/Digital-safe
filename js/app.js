import { boot } from "./crypto.js";
import "./site.js";

const ONBOARDING_KEY = "hasSeenOnboarding";

wireOnboarding();
boot();
wireDeadManSwitch();

function wireOnboarding() {
  const dialog = document.querySelector("#onboarding-dialog");
  const accept = document.querySelector("#onboarding-accept");
  if (!dialog || !accept) {
    return;
  }

  dialog.addEventListener("cancel", (event) => {
    event.preventDefault();
  });

  document.addEventListener("vault-created", () => {
    if (localStorage.getItem(ONBOARDING_KEY) === "1") {
      document.dispatchEvent(new CustomEvent("onboarding-accepted"));
      return;
    }
    accept.disabled = true;
    let left = 3;
    accept.textContent = `Я понял, открыть сейф (${left})`;
    const timer = window.setInterval(() => {
      left -= 1;
      if (left > 0) {
        accept.textContent = `Я понял, открыть сейф (${left})`;
        return;
      }
      window.clearInterval(timer);
      accept.disabled = false;
      accept.textContent = "Я понял, открыть сейф";
      accept.focus();
    }, 1000);
    if (!dialog.open) {
      dialog.showModal();
    }
  });

  accept.addEventListener("click", () => {
    if (accept.disabled) {
      return;
    }
    localStorage.setItem(ONBOARDING_KEY, "1");
    localStorage.removeItem("onboardingPending");
    if (dialog.open) {
      dialog.close();
    }
    document.dispatchEvent(new CustomEvent("onboarding-accepted"));
  });
}

const SETTINGS_KEY = "vault_settings";

function readSettings() {
  try {
    const parsed = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    return parsed;
  } catch {
    return {};
  }
}

function formatRecoveryKey(bytes) {
  const groups = [];
  for (let offset = 0; offset < bytes.length; offset += 4) {
    const group = [...bytes.subarray(offset, offset + 4)]
      .map((value) => value.toString(16).padStart(2, "0"))
      .join("");
    groups.push(group);
  }
  return groups.join("-");
}

function wireDeadManSwitch() {
  const days = document.querySelector("#dms-days");
  const save = document.querySelector("#dms-save");
  const generate = document.querySelector("#dms-generate");
  const copy = document.querySelector("#dms-copy");
  const output = document.querySelector("#dms-key-output");
  const result = document.querySelector("#dms-result");
  if (!days || !save || !generate || !copy || !output || !result) {
    return;
  }

  function applyStoredTimer() {
    const stored = readSettings();
    days.value = Number.isInteger(stored.timerDays) ? String(stored.timerDays) : "30";
  }

  applyStoredTimer();
  document.addEventListener("vault-imported", () => {
    applyStoredTimer();
    output.value = "";
    result.textContent = "";
    result.className = "result";
  });

  save.addEventListener("click", () => {
    const value = Number(days.value);
    if (!Number.isInteger(value) || value < 1 || value > 365) {
      result.textContent = "Интервал — целое число от 1 до 365.";
      result.className = "result result-bad";
      return;
    }
    if (!localStorage.getItem("vault_salt")) {
      result.textContent = "Сначала откройте сейф.";
      result.className = "result result-bad";
      return;
    }
    const next = readSettings();
    next.timerDays = value;
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
    result.textContent = "Интервал записан только на этом устройстве. Сервер его не получает.";
    result.className = "result result-ok";
  });

  generate.addEventListener("click", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    output.value = formatRecoveryKey(bytes);
    result.textContent = "Ключ показан только здесь и никуда не отправлен. Он ещё не открывает сейф: таймер и сервер не подключены.";
    result.className = "result result-warn";
    output.focus();
    output.select();
  });

  copy.addEventListener("click", async () => {
    if (!output.value) {
      result.textContent = "Сначала сгенерируйте ключ.";
      result.className = "result result-warn";
      return;
    }
    try {
      await navigator.clipboard.writeText(output.value);
      result.textContent = "Ключ скопирован. Передайте его офлайн и очистите буфер обмена.";
      result.className = "result result-ok";
    } catch {
      output.focus();
      output.select();
      result.textContent = "Скопируйте ключ из поля вручную.";
      result.className = "result result-warn";
    }
  });
}
