const logoutBtn = document.getElementById("logout-btn");
let csrfToken = "";

async function getCsrf() {
    const res = await fetch("/api/csrf", {
        credentials: "same-origin"
    });
    const data = await res.json();
    csrfToken = data.csrfToken || "";
}

logoutBtn.addEventListener("click", async function () {
    logoutBtn.disabled = true;

    try {
        if (!csrfToken) {
            await getCsrf();
        }

        const res = await fetch("/api/logout", {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "X-CSRF-Token": csrfToken
            }
        });
        const data = await res.json();

        window.location.assign(data.next || "/");
    } catch (err) {
        logoutBtn.disabled = false;
    }
});

getCsrf().catch(function () {});
