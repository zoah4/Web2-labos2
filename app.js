const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require("sqlite3").verbose();
const cookieParser = require('cookie-parser');
const session = require('express-session');
const fs = require('fs');
const crypto = require('crypto');
const app = express();
const PORT = 3000;

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('views')); 
app.use(session({ secret: 'y0urS3cr3tK3y', resave: false, saveUninitialized: true,
    cookie: { httpOnly: true, secure: false } })); 

const DB_FILE_PATH = './users.db'; 

if (fs.existsSync(DB_FILE_PATH)) {
  fs.unlinkSync(DB_FILE_PATH);  
}

const db = new sqlite3.Database(DB_FILE_PATH);

db.serialize(() => {
  db.run(`CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    password TEXT,
    oib TEXT,
    cardNumber TEXT
  )`);

  const stmt = db.prepare("INSERT INTO users (username, password, oib, cardNumber) VALUES (?, ?, ?, ?)");
  stmt.run("user1", "pass1", "12345678901", "1111-2222-3333-4444");
  stmt.run("user2", "pass2", "23456789012", "5555-6666-7777-8888");
  stmt.run("user3", "pass3", "34567890123", "9999-0000-1111-2222");
  stmt.finalize();
});

let isChecked2 = false;

//sql injection
app.post('/search', (req, res) => {
    const { username, password } = req.body;
    const isChecked = req.body.isChecked === 'true'; 

    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.all(query, (err, rows) => {
        if (err) {
            res.send("Greška u upitu.");
        } else if (rows.length > 0) {
            const users = rows;
            let response = '';
            for (let i = 0; i < users.length; i++) {
                const user = users[i];
                response += `Korisnik ${i + 1}: OIB: ${user.oib}, Broj kartice: ${user.cardNumber}<br>`;  
            }
            res.send(response);
        } else {
            res.send("Nema korisnika s tim podacima (nezaštićeni unos).");
        }
    });
});

//csrf
app.post('/toggle-vulnerability', (req, res) => {
    isChecked2 = req.body.isChecked === true;
    res.sendStatus(200);
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, user) => {
        if (err) {
            return res.status(500).send("Greška u sustavu.");
        }

        if (user) {
            req.session.userId = user.id;
            res.redirect('/change-password'); 
        } else {
            res.redirect('/login.html?error=Neispravno korisničko ime ili lozinka.');
        }
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

                if (response.ok) {
                    alert(\`Stanje ranjivosti ažurirano: \${isChecked2 ? 'Ranjivo' : 'Zaštićeno'}\`);
                } else {
                    alert('Greška prilikom postavljanja stanja ranjivosti.');
                    return;
                }

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

    db.run("UPDATE users SET password = ? WHERE id = ?", [password_new, req.session.userId], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Greška pri ažuriranju lozinke.");
        }

        res.status(200).send("Lozinka uspješno promijenjena!" );
    });
});

app.get('/update-password', (req, res) => {
    const { password_new, password_conf } = req.query; 

    if (!req.session.userId) {
        return res.status(401).json({ message: 'Niste prijavljeni.' });
    }

    if (!isChecked2/* && (!req.session.csrfToken)*/) {
        return res.status(403).json({ message: "Neispravan ili nedostaje CSRF token." });
    }

    if (password_new !== password_conf) {
        return res.status(400).json({ message: "Lozinke se ne podudaraju." });
    }

    db.run("UPDATE users SET password = ? WHERE id = ?", [password_new, req.session.userId], (err) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: "Greška pri ažuriranju lozinke." });
        }
        res.status(200).json({ message: "Lozinka uspješno promijenjena!" });
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

//izmjeni http://localhost:${PORT} nakon deploya
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
