document.addEventListener("DOMContentLoaded", function() {
    // Selektovanje svih dugmića koji imaju klasu 'tool-button'
    const toolButtons = document.querySelectorAll('.tool-button');

    toolButtons.forEach(function(button) {
        button.addEventListener("click", function(event) {
            // Sprečava učitavanje stranice samo ako je kliknuto na dugme 'DNS Enumeration'
            if (button.textContent.trim() === "DNS Enumeration") {
                event.preventDefault(); // Sprečava učitavanje stranice
                console.log("Pokreće se DNS Enumeration alat");

                // Pokretanje DNS Enumeration alata sa fetch metodom
                fetch('/dns_enum', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ target: "example.com" })
                })
                .then(response => response.json())
                .then(data => {
                    console.log("Rezultat DNS Enumeration:", data);
                    alert(data.message);
                })
                .catch(error => {
                    console.error("Greška pri izvršavanju DNS Enumeration:", error);
                    alert("Došlo je do greške pri izvršavanju DNS Enumeration.");
                });
                
            }
            // Ako nije DNS Enumeration, dopušta učitavanje stranice
            else {
                // Za ostale dugmice, dozvoljava učitavanje stranice
                console.log("Kliknuto dugme:", button.textContent.trim());
            }
        });
    });
});
