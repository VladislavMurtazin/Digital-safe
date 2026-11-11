const SUPPORT_EMAIL = "vlad.murtazin@internet.ru";

function setupNav() {
  const toggle = document.querySelector(".nav-toggle");
  const nav = document.querySelector("#site-nav");
  if (!toggle || !nav) {
    return;
  }
  toggle.addEventListener("click", () => {
    const open = nav.classList.toggle("is-open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  });
  nav.addEventListener("click", (event) => {
    const link = event.target instanceof Element ? event.target.closest("a") : null;
    if (!link) {
      return;
    }
    window.setTimeout(() => {
      nav.classList.remove("is-open");
      toggle.setAttribute("aria-expanded", "false");
    }, 0);
  });
}

function setupEarlyAccess() {
  document.querySelectorAll("[data-early-access]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const status = form.querySelector(".form-note");
      const data = new FormData(form);
      const email = String(data.get("email") || "").trim();
      if (!email.includes("@") || email.startsWith("@") || email.endsWith("@")) {
        if (status) {
          status.textContent = "Введите email целиком.";
        }
        return;
      }
      if (SUPPORT_EMAIL.startsWith("[")) {
        if (status) {
          status.textContent = "Адрес поддержки ещё не задан. Замените SUPPORT_EMAIL в js/site.js, затем отправьте заявку снова.";
        }
        return;
      }
      const subject = encodeURIComponent("Ранний доступ к Digital Safe");
      const body = encodeURIComponent(`Прошу ранний доступ.\nEmail: ${email}`);
      if (status) {
        status.textContent = "Открываю почтовую программу с заявкой.";
      }
      window.location.href = `mailto:${SUPPORT_EMAIL}?subject=${subject}&body=${body}`;
    });
  });
}

setupNav();
setupEarlyAccess();
