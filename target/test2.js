const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();
app.use(express.json());

let db;

MongoClient.connect("mongodb://localhost:27017")
    .then(client => {
        db = client.db("test");
        console.log("Connected to DB");
    });

// -----------------------------
// MongoDB Injection
// -----------------------------
app.post('/login', async (req, res) => {
    const user = await db.collection('users').findOne(req.body);
    res.send(user ? "Logged in" : "Denied");
});

// -----------------------------
// Prototype Pollution
// -----------------------------
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post('/merge', (req, res) => {
    let obj = {};
    merge(obj, req.body);
    res.json(obj);
});

// -----------------------------
// eval Injection
// -----------------------------
app.get('/calc', (req, res) => {
    const expr = req.query.expr;

    try {
        let result = eval(expr);
        res.send(result.toString());
    } catch (e) {
        res.send(e.toString());
    }
});

// -----------------------------
// Command Injection
// -----------------------------
const { exec } = require('child_process');

app.get('/cmd', (req, res) => {
    const cmd = req.query.cmd;

    exec(cmd, (err, stdout, stderr) => {
        if (err) return res.send(err.toString());
        res.send(stdout);
    });
});

// -----------------------------
// Path Traversal
// -----------------------------
const fs = require('fs');

app.get('/read', (req, res) => {
    const file = req.query.file;

    try {
        let data = fs.readFileSync(file);
        res.send(data.toString());
    } catch (e) {
        res.send(e.toString());
    }
});

// -----------------------------
app.listen(3000, () => console.log("Server running"));
