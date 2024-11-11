const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg'); 
const cookieParser = require('cookie-parser');
const session = require('express-session');
const crypto = require('crypto');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('views')); 
app.use(session({ secret: 'y0urS3cr3tK3y', resave: false, saveUninitialized: true,
    cookie: { httpOnly: true, secure: false } })); 

const pool = new Pool({
    user: 'users_db_87rl_user',
    host: 'dpg-cson15hu0jms738mij2g-a.frankfurt-postgres.render.com',
    database: 'users_db_87rl',
    password: 'JkDWa76qHoUCJddWxYeFKvnnw4azztX4',
    port: 5432,
});

pool.query(`
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        oib TEXT,
        cardNumber TEXT
    );
`)
    .then(() => {
        console.log("Tablica 'users' uspješno kreirana.");

        const insertQuery = `
            INSERT INTO users (username, password, oib, cardNumber)
            VALUES 
            ($1, $2, $3, $4), 
            ($5, $6, $7, $8), 
            ($9, $10, $11, $12)
        `;
        
        const values = [
            "user1", "pass1", "12345678901", "1111-2222-3333-4444",
            "user2", "pass2", "23456789012", "5555-6666-7777-8888",
            "user3", "pass3", "34567890123", "9999-0000-1111-2222"
        ];

        return pool.query(insertQuery, values);
    })
    .then(() => {
        console.log("Podaci su uspješno uneseni u tablicu 'users'.");
    })
    .catch(err => {
        console.error("Greška:", err);
    });

let isChecked2 = false;

// SQL injection
app.post('/search', (req, res) => {
    const { username, password } = req.body;

    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "';";
    pool.query(query)
        .then(result => {
            if (result.rows.length > 0) {
                let response = '';
                result.rows.forEach((user, index) => {
                    response += `Korisnik ${index + 1}: OIB: ${user.oib}, Broj kartice: ${user.cardnumber}<br>`;
                });
                res.send(response);
            } else {
                res.send("Nema korisnika s tim podacima.");
            }
        })
        .catch(err => {
            console.error("Greška u upitu:", err);
            res.send("Greška u upitu.");
        });
});

// CSRF zaštita
app.post('/toggle-vulnerability', (req, res) => {
    isChecked2 = req.body.isChecked === true;
    res.sendStatus(200);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const loginQuery = `SELECT * FROM users WHERE username = $1 AND password = $2`;

    pool.query(loginQuery, [username, password])
        .then(result => {
            if (result.rows.length > 0) {
                const user = result.rows[0];  
                req.session.userId = user.id;
                res.redirect('/change-password'); 
            } else {
                res.redirect('/login.html?error=Neispravno korisničko ime ili lozinka.');
            }
        })
        .catch(err => {
            return res.status(500).send("Greška u sustavu.");
        });
});

app.get('/change-password', (req, res) => {
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }

    if (!req.session.csrfToken && !isChecked2) { 
        req.session.csrfToken = crypto.randomBytes(64).toString('hex');
    }

    const csrfToken = req.session.csrfToken || '';

    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Promjena lozinke</title>
            <link rel="stylesheet" href="style.css">
        </head>
        <body>
            <form id="passwordForm">
                <input type="hidden" name="csrfToken" value="${csrfToken}">
                <label for="password_new">Nova lozinka:</label>
                <input type="password" name="password_new" required>
                <label for="password_conf">Potvrda lozinke:</label>
                <input type="password" name="password_conf" required>
                <button type="submit">Promijeni lozinku</button>
            </form>

            <label>
                <input type="checkbox" id="vulnerabilityToggle">
                Omogući ranjivost (bez CSRF zaštite)
            </label>

            <script>
                document.getElementById("passwordForm").addEventListener("submit", async function(event) {
                    event.preventDefault();
                    const isChecked2 = document.getElementById('vulnerabilityToggle').checked;
                    
                    const response = await fetch('/toggle-vulnerability', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ isChecked: isChecked2 })
                    });

                    const form = document.getElementById('passwordForm');
                    const password_new = form.querySelector('input[name="password_new"]').value;
                    const password_conf = form.querySelector('input[name="password_conf"]').value;
                    const csrfToken = form.querySelector('input[name="csrfToken"]').value;

                    let passwordUpdateResponse;
                    
                    if(isChecked2) {
                        try {
                            passwordUpdateResponse = await fetch(\`/update-password?password_new=\${encodeURIComponent(password_new)}&password_conf=\${encodeURIComponent(password_conf)}\`, {
                                method: 'GET',
                            });
                        } catch (error) {
                            console.error("Error:", error);
                            alert("Došlo je do greške pri slanju zahtjeva.");
                            return;
                        }
                    } else {
                        passwordUpdateResponse = await fetch('/update-password', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ password_new, password_conf, csrfToken })
                        });
                    }
                    
                    if (passwordUpdateResponse.ok) {
                        alert('Lozinka uspješno promijenjena!');
                        setTimeout(function() {
                            window.location.href = "/malicious-image.html";
                        }, 2000);
                    } else {
                        const errorText = await passwordUpdateResponse.text();
                        alert(\`Greška pri promjeni lozinke: \${errorText}\`);
                    }
                });
            </script>
        </body>
        </html>
    `);
});

app.post('/update-password', (req, res) => {
    const { password_new, password_conf, csrfToken } = req.body;
    if (!req.session.userId) {
        return res.redirect('/login.html');
    }

    if (!isChecked2 && (!req.session.csrfToken || req.session.csrfToken !== csrfToken)) {
        return res.status(403).send("Neispravan CSRF token.");
    }

    if (password_new !== password_conf) {
        return res.status(400).send("Lozinke se ne podudaraju.");
    }

    const updateQuery = `UPDATE users SET password = $1 WHERE id = $2`;

    pool.query(updateQuery, [password_new, req.session.userId])
        .then(() => {
            res.status(200).send("Lozinka uspješno promijenjena!");
        })
        .catch(err => {
            console.error(err);
            res.status(500).send("Greška pri ažuriranju lozinke.");
        });
});

app.get('/update-password', (req, res) => {
    const { password_new, password_conf } = req.query;

    if (!req.session.userId) {
        return res.status(401).json({ message: 'Niste prijavljeni.' });
    }

    if (!isChecked2) {
        return res.status(403).json({ message: "Neispravan ili nedostaje CSRF token." });
    }

    if (password_new !== password_conf) {
        return res.status(400).json({ message: "Lozinke se ne podudaraju." });
    }

    const updateQuery = `UPDATE users SET password = $1 WHERE id = $2`;

    pool.query(updateQuery, [password_new, req.session.userId])
        .then(() => {
            res.status(200).json({ message: "Lozinka uspješno promijenjena!" });
        })
        .catch(err => {
            console.error(err);
            res.status(500).json({ message: "Greška pri ažuriranju lozinke." });
        });
});

app.post('/logout', (req, res) => {
    isChecked2 = false;
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).send("Greška pri odjavi.");
        }
        res.redirect('/login.html');
    });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
