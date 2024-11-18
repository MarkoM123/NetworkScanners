document.getElementById("scanButton").addEventListener("click", function (e) {
    e.preventDefault();

    const scanData = {
        target: document.getElementById("ip").value,
        options: {
            ping_scan: document.getElementById("ping_scan").checked,
            port_scan: document.getElementById("port_scan").checked,
            os_scan: document.getElementById("os_scan").checked,
            detect_service: document.getElementById("detect_service").checked,
            cve_detection: document.getElementById("cve_detection").checked,
            flood_detection: document.getElementById("flood_detection").checked,
            tcp_fin_scan: document.getElementById("tcp_fin_scan").checked,
        }
    };

    fetch('/nmap', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(scanData),
    })
        .then(response => {
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                alert("An error occurred.");
            }
        })
        .catch(error => {
            console.error("Error:", error);
            alert("An error occurred.");
        });
});
