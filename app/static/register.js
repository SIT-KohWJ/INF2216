document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector("[data-register-form]");

  if (!form) {
    return;
  }

  const fullNameInput = form.querySelector("#full_name");
  const emailInput = form.querySelector("#email");
  const passwordInput = form.querySelector("#password");
  const confirmPasswordInput = form.querySelector("#confirm_password");

  const fieldMap = {
    full_name: fullNameInput,
    email: emailInput,
    password: passwordInput,
    confirm_password: confirmPasswordInput,
  };

  const setError = (fieldName, message) => {
    const input = fieldMap[fieldName];
    const errorElement = document.getElementById(`${fieldName}_error`);

    if (!input || !errorElement) {
      return;
    }

    input.setAttribute("aria-invalid", message ? "true" : "false");
    errorElement.textContent = message;
    errorElement.hidden = !message;
  };

  const validateFullName = () => {
    const value = fullNameInput.value.trim();

    if (!value) {
      return "Enter your full name.";
    }
    if (value.length < 2) {
      return "Full name must be at least 2 characters.";
    }
    return "";
  };

  const validateEmail = () => {
    const value = emailInput.value.trim();

    if (!value) {
      return "Enter your SIT email address.";
    }
    if (!emailInput.validity.valid) {
      return "Enter a valid email address.";
    }
    return "";
  };

  const validatePassword = () => {
    const value = passwordInput.value;

    if (!value) {
      return "Enter your password.";
    }
    if (value.length < 12) {
      return "Password must be at least 12 characters.";
    }
    return "";
  };

  const validateConfirmPassword = () => {
    const value = confirmPasswordInput.value;

    if (!value) {
      return "Confirm your password.";
    }
    if (value !== passwordInput.value) {
      return "Passwords do not match.";
    }
    return "";
  };

  const validators = {
    full_name: validateFullName,
    email: validateEmail,
    password: validatePassword,
    confirm_password: validateConfirmPassword,
  };

  const validateField = (fieldName) => {
    const message = validators[fieldName]();
    setError(fieldName, message);
    return !message;
  };

  Object.keys(fieldMap).forEach((fieldName) => {
    const input = fieldMap[fieldName];

    input.addEventListener("blur", () => validateField(fieldName));
    input.addEventListener("input", () => {
      validateField(fieldName);
      if (fieldName === "password" && confirmPasswordInput.value) {
        validateField("confirm_password");
      }
    });
  });

  form.addEventListener("submit", (event) => {
    const firstInvalid = Object.keys(fieldMap).find(
      (fieldName) => !validateField(fieldName),
    );

    if (firstInvalid) {
      event.preventDefault();
      fieldMap[firstInvalid].focus();
    }
  });
});
