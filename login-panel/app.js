const nameInput = document.getElementById("mail-input");
const passwordInput = document.getElementById("password-input");
const loginForm = document.getElementById("login-form");
const loginButton = document.getElementById("salam");
const loginMessage = document.getElementById("login-message");

let csrfToken = "";

async function getCsrf() {
    const res = await fetch("/api/csrf", {
        credentials: "same-origin"
    });
    const data = await res.json();
    csrfToken = data.csrfToken || "";
}

function showMsg(text) {
    loginMessage.textContent = text;
}

loginForm.addEventListener("submit", async function (event) {
    event.preventDefault();

    showMsg("");
    loginButton.disabled = true;

    try {
        if (!csrfToken) {
            await getCsrf();
        }

        const res = await fetch("/api/login", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": csrfToken
            },
            body: JSON.stringify({
                username: nameInput.value.trim(),
                password: passwordInput.value
            })
        });

        const data = await res.json();

        if (res.ok) {
            window.location.assign(data.next || "/dashboard");
            return;
        }

        if (res.status === 400) {
            await getCsrf();
        }

        showMsg(data.error || "LOGIN FAILED");
    } catch (err) {
        showMsg("SERVER ERROR");
    } finally {
        loginButton.disabled = false;
    }
});

getCsrf().catch(function () {
    showMsg("CSRF ERROR");
});
