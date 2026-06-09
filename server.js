const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 3000;

// =========================
// MIDDLEWARES
// =========================
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// =========================
// SQLITE DATABASE
// =========================
const db = new Database("database.db");

// =========================
// INIT DATABASE
// =========================
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_paid INTEGER DEFAULT 0,
    expires_at INTEGER
)
`).run();


// =========================
// HOME
// =========================
app.get("/", (req, res) => {
    res.sendFile(__dirname + "/public/index.html");
});


// =========================
// MAKE ADMIN (TEMP)
// =========================
app.get("/make-admin", (req, res) => {

    const email = req.query.email;

    if (!email) {
        return res.status(400).send("Passe ?email=seuemail");
    }

    const result = db.prepare(`
        UPDATE users
        SET is_admin = 1
        WHERE email = ?
    `).run(email);

    res.send(`Admin atualizado! Linhas afetadas: ${result.changes}`);
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

        const result = db.prepare(`
            INSERT INTO users (username, email, password)
            VALUES (?, ?, ?)
        `).run(username, email, hash);

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
// ADMIN - GRANT
// =========================
app.post("/admin/grant", (req, res) => {

    const { email, plan } = req.body;

    if (!email || !plan) {
        return res.status(400).json({ error: "Dados inválidos" });
    }

    let duration;

    if (plan === "monthly") {
        duration = 30 * 24 * 60 * 60 * 1000;
    } else if (plan === "yearly") {
        duration = 365 * 24 * 60 * 60 * 1000;
    } else {
        return res.status(400).json({ error: "Plano inválido" });
    }

    const expires_at = Date.now() + duration;

    db.prepare(`
        UPDATE users
        SET is_paid = 1,
            expires_at = ?
        WHERE email = ?
    `).run(expires_at, email);

    res.json({ message: "Usuário liberado!" });
});


// =========================
// ADMIN - REVOKE
// =========================
app.post("/admin/revoke", (req, res) => {

    const { email } = req.body;

    db.prepare(`
        UPDATE users
        SET is_paid = 0,
            expires_at = NULL
        WHERE email = ?
    `).run(email);

    res.json({ message: "Acesso removido!" });
});


// =========================
// LOGIN (CORRIGIDO - LÓGICA LIMPA)
// =========================
app.post("/login", async (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Preencha todos os campos" });
    }

    try {
        const user = db.prepare(`
            SELECT * FROM users
            WHERE email = ? OR username = ?
        `).get(email, email);

        if (!user) {
            return res.status(400).json({ error: "Usuário não encontrado" });
        }

        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(400).json({ error: "Senha incorreta" });
        }

        const now = Date.now();

        // =========================
        // EXPIRAÇÃO
        // =========================
        if (user.is_paid === 1 && user.expires_at && user.expires_at < now) {
            return res.status(403).json({ error: "Acesso expirado" });
        }

        // =========================
        // REDIRECT (ORDEM CORRETA)
        // =========================
        let redirect = "dashboard.html";

        const isActivePaid =
            user.is_paid === 1 &&
            (!user.expires_at || user.expires_at > now);

        if (Number(user.is_admin) === 1) {
            redirect = "admin.html";
        }
        else if (isActivePaid) {
            redirect = "trojan_panel.html";
        }

        res.json({
            message: "Login realizado com sucesso!",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                is_admin: Number(user.is_admin),
                is_paid: user.is_paid,
                expires_at: user.expires_at
            },
            redirect
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro no servidor" });
    }
});


// =========================
// DEBUG
// =========================
app.get("/debug-user", (req, res) => {

    const email = req.query.email;

    const user = db.prepare(`
        SELECT id, email, is_admin, is_paid, expires_at
        FROM users
        WHERE email = ?
    `).get(email);

    res.json(user);
});


// =========================
// START SERVER
// =========================
app.listen(PORT, () => {
    console.log(`🔥 Servidor rodando na porta ${PORT}`);
});