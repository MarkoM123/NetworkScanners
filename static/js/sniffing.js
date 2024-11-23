document.addEventListener("DOMContentLoaded", function() {
    const buttons = document.querySelectorAll('.tool-button');
    const resultContainer = document.getElementById('result');

    buttons.forEach(button => {
        button.addEventListener('click', function() {
            const tool = button.getAttribute('data-tool');
            resultContainer.textContent = `Running ${tool}...`;

            fetch(`/run_tool`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ tool: tool })
            })
            .then(response => response.json())
            .then(data => {
                resultContainer.textContent = data.output || 'No output received.';
            })
            .catch(error => {
                console.error("Error:", error);
                resultContainer.textContent = "An error occurred while running the tool.";
            });
        });
    });
});
