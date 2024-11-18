// Skripta za skrol efekat (promena pozadine pri skrolovanju)
window.onscroll = function() {
    if (window.scrollY > 50) {
        document.body.classList.add('scrolled');
    } else {
        document.body.classList.remove('scrolled');
    }
};

// Skripta za interaktivnost dugmadi i menija
document.addEventListener("DOMContentLoaded", function() {
    // Dodavanje efekta na dugmadi
    const toolButtons = document.querySelectorAll('.tool-button');
    toolButtons.forEach(button => {
        button.addEventListener('mouseover', function() {
            button.style.transform = 'scale(1.1)';
            button.style.boxShadow = '0 0 30px #00ff00';
        });
        button.addEventListener('mouseout', function() {
            button.style.transform = 'scale(1)';
            button.style.boxShadow = '0 0 15px #00ff00';
        });
    });
});
