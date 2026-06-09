const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();

const PORT = process.env.PORT || 3000;

// =========================
// POSTGRESQL CONNECTION
// =========================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// =========================
// MIDDLEWARES
// =========================
app.use(cors());
app.use(express.json());
app.use(express.static("public"));


// =========================
// INIT DATABASE
// =========================
async function initDB() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);
}

initDB();


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

        const result = await pool.query(
            `INSERT INTO users (username, email, password)
             VALUES ($1, $2, $3)
             RETURNING id`,
            [username, email, hash]
        );

        res.json({
            message: "Conta criada com sucesso!",
            userId: result.rows[0].id
        });

    } catch (err) {

        if (err.code === "23505") {
            return res.status(400).json({ error: "Email já cadastrado" });
        }

        console.error(err);
        res.status(500).json({ error: "Erro no servidor" });
    }
});


// =========================
// LOGIN (EMAIL OU USERNAME)
// =========================
app.post("/login", async (req, res) => {

    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Preencha todos os campos" });
    }

    try {
        const result = await pool.query(
            `SELECT * FROM users
             WHERE email = $1 OR username = $1`,
            [email]
        );

        const user = result.rows[0];

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