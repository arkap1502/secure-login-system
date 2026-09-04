/*
 * Progressive enhancement only -- every behaviour here is optional sugar.
 * All real validation and security checks happen server-side.
 */
(function () {
  // OTP fields: digits only, auto-submit once 6 digits are entered.
  document.querySelectorAll(".otp-input").forEach((field) => {
    field.addEventListener("input", () => {
      field.value = field.value.replace(/\D/g, "").slice(0, 6);
      if (field.value.length === 6) {
        const form = field.closest("form");
        if (form) form.requestSubmit();
      }
    });
  });

  // Manual TOTP secret key: click to copy.
  const secretBox = document.querySelector(".secret-key");
  if (secretBox && navigator.clipboard) {
    secretBox.style.cursor = "pointer";
    secretBox.title = "Click to copy";
    secretBox.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(secretBox.textContent.trim());
        const original = secretBox.textContent;
        secretBox.textContent = "Copied to clipboard";
        setTimeout(() => { secretBox.textContent = original; }, 1200);
      } catch (err) {
        // Clipboard API unavailable or blocked -- fail silently, the key
        // is still selectable and copyable by hand.
      }
    });
  }
})();
