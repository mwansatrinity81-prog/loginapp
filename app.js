// Registration
const registerForm = document.getElementById("registerForm");
const registerResult = document.getElementById("registerResult");

registerForm.addEventListener("submit", async function (event) {
  event.preventDefault();

  const username = document.getElementById("regUsername").value.trim();
  const password = document.getElementById("regPassword").value;

  registerResult.style.color = "red";

  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    registerResult.textContent = "Username must be 3 to 20 letters, numbers or underscores.";
    return;
  }
  if (password.length < 8) {
    registerResult.textContent = "Password must be at least 8 characters.";
    return;
  }

  try {
    const response = await fetch("/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username, password: password })
    });
    const data = await response.json();

    if (data.ok) {
      registerResult.style.color = "green";
      registerResult.textContent = "Account created! You can log in below.";
      registerForm.reset();
    } else {
      registerResult.textContent = data.error;
    }
  } catch (error) {
    registerResult.textContent = "Could not reach the server. Is it running?";
  }
});

// Login
const loginForm = document.getElementById("loginForm");
const loginResult = document.getElementById("loginResult");

loginForm.addEventListener("submit", async function (event) {
  event.preventDefault();

  const username = document.getElementById("loginUsername").value.trim();
  const password = document.getElementById("loginPassword").value;

  loginResult.style.color = "red";

  if (username === "" || password === "") {
    loginResult.textContent = "Please enter your username and password.";
    return;
  }

  try {
    const response = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username, password: password })
    });
    const data = await response.json();

    if (data.ok) {
      window.location.href = "/dashboard";
    } else {
      loginResult.textContent = data.error;
    }
  } catch (error) {
    loginResult.textContent = "Could not reach the server. Is it running?";
  }
});