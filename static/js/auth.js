(function () {
  const form = document.querySelector("form");
  if (!form) return;

  const msgBox = document.getElementById("authMsg");
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"
  }[c]));

  const show = (text, kind) => {
    const bg = kind === "ok" ? "#dcfce7" : kind === "warn" ? "#fef9c3" : "#ffe4e6";
    const fg = kind === "ok" ? "#166534" : kind === "warn" ? "#854d0e" : "#b91c1c";
    msgBox.innerHTML = `<div style="background:${bg}; color:${fg}; padding:10px; border-radius:6px;">${esc(text)}</div>`;
  };

  const isRegister = !!form.querySelector('input[name="name"]') && !!form.querySelector('select[name="role"]');
  const isLogin = !!form.querySelector('input[name="email"]') && !!form.querySelector('input[name="password"]') && !isRegister;

  const roleMap = (uiRole) => {
    const r = (uiRole || "").trim().toLowerCase();
    if (r === "admin") return "ADMIN";
    if (r === "doctor") return "DOCTOR";
    if (r === "patient") return "PATIENT";
    if (r === "lab assistant" || r === "labassistant") return "LAB";
    return "PATIENT";
  };

  async function setServerSession(token) {
    try {
      await fetch("/ui/session", {
        method: "POST",
        headers: {"Content-Type":"application/json"},
        body: JSON.stringify({ token })
      });
    } catch {}
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = (form.querySelector('input[name="email"]')?.value || "").trim();
    const password = form.querySelector('input[name="password"]')?.value || "";

    try {
      if (isRegister) {
        const name = (form.querySelector('input[name="name"]')?.value || "").trim();
        const uiRole = form.querySelector('select[name="role"]')?.value || "";
        const role = roleMap(uiRole);

        if (!name || !email || !password || !uiRole) return show("All fields are required.", "err");

        show("Password saved. Now place fingerprint to register...", "warn");
        const options = await Api.post("/auth/register/options", { email, full_name: name, role });

        const credential = await WebAuthn.createCredential(options.publicKey);

        await Api.post("/auth/register/verify", { email, password, full_name: name, role, credential });

        show("Registered. You can login now.", "ok");
        setTimeout(() => location.href = "/login", 700);
        return;
      }

      if (isLogin) {
        if (!email || !password) return show("Email and password required.", "err");

        show("Password verified. Now place fingerprint...", "warn");
        const options = await Api.post("/auth/login/options", { email, password });

        const credential = await WebAuthn.getAssertion(options.publicKey);

        const res = await Api.post("/auth/login/verify", { email, password, credential });

        localStorage.setItem("token", res.access_token);
        localStorage.setItem("role", res.role);

        await setServerSession(res.access_token);

        show("Login successful. Redirecting...", "ok");
        setTimeout(() => location.href = "/", 300);
        return;
      }

    } catch (err) {
      const message = err?.message || String(err);
      show(message, "err");
      const stage = isRegister ? "REG" : "AUTH";
      await Api.safePost("/auth/webauthn/fail", { email: email || null, stage, reason: message });
    }
  });
})();