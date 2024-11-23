document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("ddos-form");
    const resultContainer = document.getElementById("result");

    form.addEventListener("submit", function (event) {
        event.preventDefault();

        const target = document.getElementById("target").value;
        const method = document.getElementById("method").value;
        const requests = document.getElementById("requests").value;

        resultContainer.textContent = "Launching attack...";

        fetch('/start_ddos', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target, method, requests })
        })
        .then(response => response.json())
        .then(data => {
            resultContainer.textContent = data.output || "No output received.";
        })
        .catch(error => {
            console.error("Error:", error);
            resultContainer.textContent = "An error occurred while launching the attack.";
        });
    });
});
