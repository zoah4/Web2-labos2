document.getElementById("sql-form").addEventListener("submit", async function(event) {
    event.preventDefault(); 

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const isChecked = document.getElementById("vulnerability-toggle").checked; 
    const resultsDiv = document.getElementById("results");

    const isInputValid = /^[a-zA-Z0-9_-]+$/.test(username) && /^[a-zA-Z0-9_-]+$/.test(password);
    if (!isInputValid && !isChecked) {
        alert("Unijeli ste neispravan unos.");
        return;
    }

    try {
        const response = await fetch('/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ username, password, isChecked })
        });

        if (response.ok) {
            const data = await response.text();

            if (data.trim()) {
                resultsDiv.innerHTML = data;
                resultsDiv.style.display = 'block'; 
                resultsDiv.style.border = '1px solid #ddd';
                resultsDiv.style.backgroundColor = '#ecf0f1';
            } 
        } else {
            resultsDiv.innerHTML = "Greška u dohvaćanju podataka.";
            resultsDiv.style.display = 'block';
        }
    } catch (error) {
        console.error("Došlo je do greške:", error);
        resultsDiv.innerHTML = "Greška u dohvaćanju podataka.";
        resultsDiv.style.display = 'block';
    }
});


