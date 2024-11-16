function startScan(event) {
    event.preventDefault();  // Sprečava formu da se pošalje na tradicionalan način

    const ipAddress = document.getElementById("ipAddress").value;
    const statusElement = document.getElementById("status");
    const outputElement = document.getElementById("scanOutput");

    console.log("IP Address entered: ", ipAddress);  // Ispisivanje unete IP adrese

    // Podesiti status na "Pokretanje skeniranja..."
    statusElement.textContent = "Starting scan...";
    outputElement.textContent = "";

    // Kreirajte telo za POST zahtev
    const data = {
        ipAddress: ipAddress
    };

    console.log("Sending data to server: ", data);  // Ispisivanje podataka koji se šalju serveru

    // Šaljemo POST zahtev sa JSON telom
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => {
        console.log("Response status: ", response.status);  // Ispisivanje HTTP status koda odgovora
        return response.json();  // Uzimamo odgovor u JSON formatu
    })
    .then(data => {
        console.log("Response data: ", data);  // Ispisivanje podataka koje smo dobili sa servera

        // Ako je sve u redu, prikazujemo rezultate
        if (data.result) {
            statusElement.textContent = "Scan Results:";
            outputElement.textContent = data.result;
        } else {
            statusElement.textContent = "Error:";
            outputElement.textContent = "No results found.";
        }
    })
    .catch(error => {
        // U slučaju greške prikazujemo status greške
        console.error("Error: ", error);  // Ispisivanje greške u konzolu
        statusElement.textContent = "Error:";
        outputElement.textContent = "Something went wrong. Please try again.";
    });
}

document.getElementById("scanForm").addEventListener("submit", startScan);
