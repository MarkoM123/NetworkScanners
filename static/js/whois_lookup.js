document.addEventListener("DOMContentLoaded", function () {
    const whoisForm = document.getElementById("whois-form");

    whoisForm.addEventListener("submit", function (event) {
        event.preventDefault(); // Sprečava osvežavanje stranice

        const target = document.getElementById("target").value.trim();
        const tool = document.getElementById("tool").value;

        if (!target || !tool) {
            alert("Please fill in all fields.");
            return;
        }

        // AJAX zahtev ka Flask backend-u
        fetch('/whois_lookup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                target: target,
                tool: tool,
            }),
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error("Network response was not ok.");
                }
                return response.json();
            })
            .then(data => {
                const resultContainer = document.getElementById("result");
                if (data.error) {
                    resultContainer.textContent = `Error: ${data.error}`;
                } else {
                    resultContainer.textContent = data.result;
                }
            })
            .catch(error => {
                console.error('Error during the request:', error);
                document.getElementById("result").textContent = "An error occurred.";
            });
    });
});
