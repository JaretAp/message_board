const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./users.db');

db.all(`SELECT * FROM users`, [], (err, rows) => {
    if (err) {
        console.error("Error fetching data:", err.message);
    } else if (rows.length === 0) {
        console.log("No data found in users table.");
    } else {
        console.log("Data in users table:", rows);
    }
    db.close();
});
