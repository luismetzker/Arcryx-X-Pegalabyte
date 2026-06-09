const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// Banco SQLite
const db = new Database("database.db");

// Criar tabela
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
`).run();


// =========================
// HOME
// =========================
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});


// =========================
// REGISTER
// =========================
app.post("/register", async (req, res) => {

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: "Preencha todos os campos" });
    }

    try {
        const hash = await bcrypt.hash(password, 10);

        const stmt = db.prepare(`
            INSERT INTO users (username, email, password)
            VALUES (?, ?, ?)
        `);

        const result = stmt.run(username, email, hash);

        res.json({
            message: "Conta criada com sucesso!",
            userId: result.lastInsertRowid
        });

    } catch (err) {

        if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(400).json({ error: "Email já cadastrado" });
        }

        console.error(err);
        res.status(500).json({ error: "Erro no servidor" });
    }
});


// =========================
// LOGIN (CORRIGIDO)
// =========================
app.post("/login", async (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Preencha todos os campos" });
    }

    try {
        // 🔥 AGORA ACEITA EMAIL OU USERNAME
        const stmt = db.prepare(`
            SELECT * FROM users
            WHERE email = ? OR username = ?
        `);

        const user = stmt.get(email, email);

        if (!user) {
            return res.status(400).json({ error: "Usuário não encontrado" });
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(400).json({ error: "Senha incorreta" });
        }

        res.json({
            message: "Login realizado com sucesso!",
            user: {
                id: user.id,
                username: user.username,
                email: user.email
            }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro no servidor" });
    }
});


// =========================
// START SERVER
// =========================
app.listen(PORT, () => {
    console.log(`🔥 Servidor rodando na porta ${PORT}`);
});