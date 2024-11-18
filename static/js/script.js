// Skriva i otkriva alatke na klik
document.addEventListener("DOMContentLoaded", function() {
    const folderTitles = document.querySelectorAll(".folder-title");

    folderTitles.forEach(function(title) {
        title.addEventListener("click", function() {
            // Na osnovu ID-a foldera, prikazuj ili sakrij alatke
            const tools = title.nextElementSibling;

            // Toggle (prikazivanje/sakrivanje)
            if (tools.style.display === "none" || tools.style.display === "") {
                tools.style.display = "block";
            } else {
                tools.style.display = "none";
            }
        });
    });
});
