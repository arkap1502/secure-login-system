/*
 * Live password strength feedback. This is UX sugar only -- the
 * authoritative policy check happens server-side in app/utils.py, and this
 * script deliberately mirrors those same rules so the two never disagree.
 */
(function () {
  const input = document.getElementById("password-input");
  if (!input) return;

  const segments = document.querySelectorAll("#strength-meter .strength-seg");
  const label = document.getElementById("strength-label");
  const checklist = document.getElementById("strength-checklist");

  const colors = ["#C1594A", "#C1594A", "#C89B3C", "#86A177", "#86A177"];
  const labels = ["Very weak", "Weak", "Fair", "Good", "Strong"];

  function evaluate(password) {
    const rules = {
      length: password.length >= 10,
      case: /[a-z]/.test(password) && /[A-Z]/.test(password),
      digit: /\d/.test(password),
      special: /[^\w\s]/.test(password),
    };

    if (checklist) {
      Object.entries(rules).forEach(([rule, met]) => {
        const item = checklist.querySelector(`[data-rule="${rule}"]`);
        if (item) item.classList.toggle("met", met);
      });
    }

    let score = 0;
    if (password.length >= 10) score++;
    if (password.length >= 14) score++;
    if (rules.case) score++;
    if (rules.digit) score++;
    if (rules.special) score++;
    score = Math.min(score, 4);

    segments.forEach((seg, i) => {
      seg.style.background = i <= score ? colors[score] : "var(--border)";
    });
    label.textContent = password.length === 0 ? "Password strength" : labels[score];
  }

  input.addEventListener("input", (e) => evaluate(e.target.value));
  evaluate(input.value || "");
})();
