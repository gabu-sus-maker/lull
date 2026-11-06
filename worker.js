// =====================================================================
// LULL server — accounts, cloud saves, and co-op rooms.
// One Worker + two kinds of Durable Object (SQLite, Free-plan compatible).
//   Accounts : one global instance. Users, sessions, saves, usage meter.
//   Room     : one instance per 4-letter room code. Owns a co-op game.
// Secrets live in the Cloudflare dashboard (ADMIN_KEY), never in the game.
// =====================================================================
import { DurableObject } from "cloudflare:workers";

const PROTO = 1;
const ITERS = 100000;                 // PBKDF2-SHA256; Workers cap is 100k
const SESSION_MS = 30 * 864e5;        // 30 days
const MAX_SESSIONS = 5;
const LOCK_AFTER = 5;                 // failed logins before a lock
const SAVE_MAX = 65536;               // bytes
const ROOM_MAX = 4;
const CODE_ABC = "BCDFGHJKLMNPQRSTVWXZ"; // no vowels: codes can't spell words
const RESET_ABC = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const RESERVED = new Set(["admin", "root", "system", "server", "lull", "mod", "moderator", "null", "undefined", "host"]);
const COMMON = new Set(["password", "password1", "password123", "passw0rd", "12345678", "123456789", "1234567890", "87654321", "00000000", "11111111", "aaaaaaaa",
  "qwertyui", "qwerty123", "qwertyuiop", "asdfghjk", "iloveyou", "football", "abc12345", "letmein1", "welcome1", "sunshine", "princess", "superman",
  "monkey12", "dragon12", "baseball", "trustno1", "minecraft", "fortnite", "arsenal1", "chelsea1", "liverpool", "lull1234", "roblox123"]);

const enc = new TextEncoder();
const SEC = { "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cache-control": "no-store" };
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json", ...SEC } });
const err = (msg, s = 400) => json({ error: msg }, s);
const now = () => Date.now();
const day = (t = now()) => new Date(t).toISOString().slice(0, 10);

function rnd(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }
function hex(buf) { return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join(""); }
function unhex(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; }
function b64u(buf) { let s = ""; for (const x of new Uint8Array(buf)) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function pickChars(abc, n) { const b = rnd(n * 2); let s = ""; for (let i = 0; i < n; i++) s += abc[((b[i * 2] << 8) | b[i * 2 + 1]) % abc.length]; return s; }
async function sha256(s) { return hex(await crypto.subtle.digest("SHA-256", enc.encode(s))); }
function safeEq(a, b) {
  const A = enc.encode(String(a)), B = enc.encode(String(b));
  if (A.length !== B.length) return false;
  if (crypto.subtle.timingSafeEqual) return crypto.subtle.timingSafeEqual(A, B);
  let r = 0; for (let i = 0; i < A.length; i++) r |= A[i] ^ B[i]; return r === 0;
}
async function pbkdf2(pw, saltHex, iters) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unhex(saltHex), iterations: iters }, k, 256));
}
function checkUsername(u) {
  if (typeof u !== "string") return "Pick a username.";
  u = u.trim().toLowerCase();
  if (!/^[a-z0-9_]{3,16}$/.test(u)) return "Usernames are 3–16 letters, numbers or _.";
  if (RESERVED.has(u)) return "That username is reserved.";
  return null;
}
function checkPassword(p, u) {
  if (typeof p !== "string" || p.length < 8) return "Passwords need at least 8 characters.";
  if (p.length > 128) return "That password is too long.";
  const l = p.toLowerCase();
  if (COMMON.has(l) || /^(.)\1+$/.test(p)) return "That password is too easy to guess.";
  if (u && l.includes(String(u).toLowerCase())) return "Don't put your username in your password.";
  return null;
}

// =====================================================================
// ACCOUNTS — single global Durable Object
// =====================================================================
export class Accounts extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.ip = new Map(); // ip -> {n,t} login attempts (memory only; resets if evicted)
    this.sql.exec(`CREATE TABLE IF NOT EXISTS users(u TEXT PRIMARY KEY, salt TEXT, hash TEXT, iters INTEGER, created INTEGER,
      fails INTEGER DEFAULT 0, lock_until INTEGER DEFAULT 0, reset_hash TEXT, reset_exp INTEGER DEFAULT 0)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS sessions(th TEXT PRIMARY KEY, u TEXT, exp INTEGER, created INTEGER)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS saves(u TEXT PRIMARY KEY, rev INTEGER, data TEXT, updated INTEGER)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS signups(ip TEXT, d TEXT, n INTEGER, PRIMARY KEY(ip, d))`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS usage(d TEXT PRIMARY KEY, msgs INTEGER DEFAULT 0, rooms INTEGER DEFAULT 0, players INTEGER DEFAULT 0)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS adminfail(ip TEXT PRIMARY KEY, n INTEGER, t INTEGER)`);
    this.sql.exec(`CREATE TABLE IF NOT EXISTS coop(u TEXT PRIMARY KEY, data TEXT, updated INTEGER)`);
  }
  one(q, ...a) { const r = this.sql.exec(q, ...a).toArray(); return r[0] || null; }

  ipTry(ip, limit = 30, windowMs = 600000) {
    const t = now(); let e = this.ip.get(ip);
    if (!e || t - e.t > windowMs) { e = { n: 0, t }; this.ip.set(ip, e); }
    e.n++; return e.n <= limit;
  }
  async newSession(u) {
    const token = b64u(rnd(32)), th = await sha256(token), t = now();
    this.sql.exec(`INSERT INTO sessions(th,u,exp,created) VALUES(?,?,?,?)`, th, u, t + SESSION_MS, t);
    const extra = this.sql.exec(`SELECT th FROM sessions WHERE u=? ORDER BY created DESC LIMIT -1 OFFSET ?`, u, MAX_SESSIONS).toArray();
    for (const r of extra) this.sql.exec(`DELETE FROM sessions WHERE th=?`, r.th);
    return token;
  }

  async register(u, p, ip, limit = 40) {
    const e1 = checkUsername(u); if (e1) return { error: e1 };
    u = u.trim().toLowerCase();
    const e2 = checkPassword(p, u); if (e2) return { error: e2 };
    if (this.one(`SELECT u FROM users WHERE u=?`, u)) return { error: "That username is taken." };
    const d = day(), row = this.one(`SELECT n FROM signups WHERE ip=? AND d=?`, ip, d);
    if (row && row.n >= limit) return { error: "Too many new accounts from this network today. Try tomorrow." };
    this.sql.exec(`INSERT INTO signups(ip,d,n) VALUES(?,?,1) ON CONFLICT(ip,d) DO UPDATE SET n=n+1`, ip, d);
    const salt = hex(rnd(16)), hash = await pbkdf2(p, salt, ITERS);
    this.sql.exec(`INSERT INTO users(u,salt,hash,iters,created) VALUES(?,?,?,?,?)`, u, salt, hash, ITERS, now());
    return { u, token: await this.newSession(u) };
  }

  async login(u, p, ip) {
    if (!this.ipTry(ip)) return { error: "Too many attempts from this network. Wait ten minutes." };
    if (typeof u !== "string" || typeof p !== "string" || p.length > 128) return { error: "Wrong username or password." };
    u = u.trim().toLowerCase();
    const r = this.one(`SELECT * FROM users WHERE u=?`, u);
    if (!r) { await pbkdf2(p, "00".repeat(16), ITERS); return { error: "Wrong username or password." }; } // same timing either way
    const t = now();
    if (r.lock_until > t) return { error: `Too many wrong tries. Wait ${Math.ceil((r.lock_until - t) / 60000)} min.` };
    const h = await pbkdf2(p, r.salt, r.iters);
    if (!safeEq(h, r.hash)) {
      const f = r.fails + 1, lock = f >= LOCK_AFTER ? t + Math.min(60000 * 2 ** (f - LOCK_AFTER), 3600000) : 0;
      this.sql.exec(`UPDATE users SET fails=?, lock_until=? WHERE u=?`, f, lock, u);
      return { error: "Wrong username or password." };
    }
    this.sql.exec(`UPDATE users SET fails=0, lock_until=0 WHERE u=?`, u);
    return { u, token: await this.newSession(u) };
  }

  async auth(token) {
    if (typeof token !== "string" || token.length < 20 || token.length > 100) return null;
    const th = await sha256(token), r = this.one(`SELECT u, exp FROM sessions WHERE th=?`, th);
    if (!r) return null;
    if (r.exp < now()) { this.sql.exec(`DELETE FROM sessions WHERE th=?`, th); return null; }
    return r.u;
  }
  async logout(token) { this.sql.exec(`DELETE FROM sessions WHERE th=?`, await sha256(String(token))); return { ok: true }; }

  getSave(u) { const r = this.one(`SELECT rev, data, updated FROM saves WHERE u=?`, u); return r ? { rev: r.rev, data: JSON.parse(r.data), updated: r.updated } : { rev: 0, data: null }; }
  putSave(u, data, baseRev, force) {
    const s = JSON.stringify(data);
    if (s.length > SAVE_MAX) return { error: "Save too large." };
    const cur = this.one(`SELECT rev FROM saves WHERE u=?`, u), rev = cur ? cur.rev : 0;
    if (!force && cur && baseRev !== rev) return { conflict: true, ...this.getSave(u) };
    this.sql.exec(`INSERT INTO saves(u,rev,data,updated) VALUES(?,?,?,?) ON CONFLICT(u) DO UPDATE SET rev=excluded.rev, data=excluded.data, updated=excluded.updated`, u, rev + 1, s, now());
    return { rev: rev + 1 };
  }

  async resetWithCode(u, code, p) {
    if (typeof u !== "string" || typeof code !== "string") return { error: "That code isn't valid." };
    u = u.trim().toLowerCase();
    const r = this.one(`SELECT * FROM users WHERE u=?`, u);
    const ok = r && r.reset_hash && r.reset_exp > now() && safeEq(await sha256(code.trim().toUpperCase()), r.reset_hash);
    if (!ok) return { error: "That code isn't valid." };
    const e = checkPassword(p, u); if (e) return { error: e };
    const salt = hex(rnd(16)), hash = await pbkdf2(p, salt, ITERS);
    this.sql.exec(`UPDATE users SET salt=?, hash=?, iters=?, fails=0, lock_until=0, reset_hash=NULL, reset_exp=0 WHERE u=?`, salt, hash, ITERS, u);
    this.sql.exec(`DELETE FROM sessions WHERE u=?`, u);
    return { u, token: await this.newSession(u) };
  }

  // ---- admin (the Worker checks the key first) ----
  adminGate(ip, ok) {
    const r = this.one(`SELECT n, t FROM adminfail WHERE ip=?`, ip), t = now();
    if (r && r.n >= 5 && t - r.t < 3600000) return { locked: true };
    if (!ok) { this.sql.exec(`INSERT INTO adminfail(ip,n,t) VALUES(?,1,?) ON CONFLICT(ip) DO UPDATE SET n=CASE WHEN ?-t>3600000 THEN 1 ELSE n+1 END, t=?`, ip, t, t, t); return { locked: false, bad: true }; }
    this.sql.exec(`DELETE FROM adminfail WHERE ip=?`, ip); return { locked: false };
  }
  async adminReset(u) {
    u = String(u || "").trim().toLowerCase();
    if (!this.one(`SELECT u FROM users WHERE u=?`, u)) return { error: "No such user: " + u };
    const code = pickChars(RESET_ABC, 8);
    this.sql.exec(`UPDATE users SET reset_hash=?, reset_exp=? WHERE u=?`, await sha256(code), now() + 864e5, u);
    return { u, code, expires: "24 hours" };
  }
  adminDelete(u) {
    u = String(u || "").trim().toLowerCase();
    if (!this.one(`SELECT u FROM users WHERE u=?`, u)) return { error: "No such user: " + u };
    this.sql.exec(`DELETE FROM users WHERE u=?`, u); this.sql.exec(`DELETE FROM sessions WHERE u=?`, u); this.sql.exec(`DELETE FROM saves WHERE u=?`, u);
    return { deleted: u };
  }
  adminUsers() {
    return this.sql.exec(`SELECT users.u AS u, users.created AS created, saves.updated AS saved FROM users LEFT JOIN saves ON saves.u=users.u ORDER BY users.created`).toArray();
  }
  addUsage(msgs, rooms, players) {
    this.sql.exec(`INSERT INTO usage(d,msgs,rooms,players) VALUES(?,?,?,?) ON CONFLICT(d) DO UPDATE SET msgs=msgs+excluded.msgs, rooms=rooms+excluded.rooms, players=players+excluded.players`, day(), msgs | 0, rooms | 0, players | 0);
    return { ok: true };
  }
  getCoop(u) { const r = this.one(`SELECT data, updated FROM coop WHERE u=?`, u); return r ? { data: JSON.parse(r.data), updated: r.updated } : null; }
  putCoop(u, data) { const s = JSON.stringify(data); if (s.length > 200000) return { error: "too big" };
    this.sql.exec(`INSERT INTO coop(u,data,updated) VALUES(?,?,?) ON CONFLICT(u) DO UPDATE SET data=excluded.data, updated=excluded.updated`, u, s, now()); return { ok: true }; }
  delCoop(u) { this.sql.exec(`DELETE FROM coop WHERE u=?`, u); return { ok: true }; }
  usage() { return this.sql.exec(`SELECT * FROM usage ORDER BY d DESC LIMIT 14`).toArray(); }
  today() { return this.one(`SELECT msgs FROM usage WHERE d=?`, day()) || { msgs: 0 }; }
}

// =====================================================================
// ROOM — one co-op game. WebSocket hibernation keeps idle rooms free.
// The server is the only place the whole truth lives; each client is sent
// only what that player could perceive.
// =====================================================================
const COLS = ["amber", "teal", "violet", "rose"];
const CHARS = ["rowan", "kofi", "nadia", "jun"];
const SAY_R = 170;          // px: say-aloud range
const GIVE_R = 48;          // px: hand-to-hand range
const REV_R = 40;           // px: revive range
// ---- story mode: the hidden truth lives only here ----
const CONSUMABLE = new Set(["water", "crisps", "beans", "choc", "bread", "pastry", "cordial", "peaches", "bar"]);
const NEAR_R = 140;         // px: close enough to feel the hum
const PRIME_R = 220;        // px: close enough to an infected player to see as they see
const HEAR_R = 170;         // px: overhearing a conversation

export class Room extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.st = null; this.loaded = false;
    this.pos = new Map();   // u -> {x,y,m,t}   (transient)
    this.bucket = new Map();// u -> {tok,t}      (rate limit)
    this.msgs = 0; this.flushAt = 0;
  }
  async load() { if (!this.loaded) { this.st = (await this.ctx.storage.get("st")) || null; this.loaded = true; } }
  async save() { await this.ctx.storage.put("st", this.st); }
  // live sockets only (a socket we've closed or that said goodbye is marked dead)
  socks(u) { return (u ? this.ctx.getWebSockets(u) : this.ctx.getWebSockets()).filter(s => { const a = s.deserializeAttachment(); return a && !a.dead; }); }
  kill(ws, code, why) { try { const a = ws.deserializeAttachment() || {}; ws.serializeAttachment({ ...a, dead: 1 }); } catch (e) { } try { ws.close(code, why); } catch (e) { } }
  online(u) { return this.socks(u).length > 0; }
  send(ws, o) { try { ws.send(JSON.stringify(o)); } catch (e) { } }
  to(u, o) { const s = JSON.stringify(o); for (const ws of this.socks(u)) { try { ws.send(s); } catch (e) { } } }
  all(o, except) { const s = JSON.stringify(o); for (const ws of this.socks()) { if (except && ws === except) continue; try { ws.send(s); } catch (e) { } } }
  others(u, o) { const s = JSON.stringify(o); for (const ws of this.socks()) { const a = ws.deserializeAttachment(); if (a && a.u === u) continue; try { ws.send(s); } catch (e) { } } }
  near(a, b, r) { const p = this.pos.get(a), q = this.pos.get(b); return !!(p && q && p.m === q.m && Math.hypot(p.x - q.x, p.y - q.y) <= r); }
  roomMsg() {
    const st = this.st;
    return { t: "room", code: st.code, host: st.host, phase: st.phase, proto: PROTO,
      roster: st.roster.map(r => ({ u: r.u, char: r.char, col: r.col, ready: r.ready, on: this.online(r.u) })) };
  }
  // ---- story helpers ----
  charOf(u) { const r = this.st.roster.find(x => x.u === u); return r ? r.char : null; }
  roleOf(u) { const p = this.st.party; return p && p.roles ? p.roles[this.charOf(u)] || "b" : "b"; }
  infected(u) { const r = this.roleOf(u); return r === "a" || r === "c"; }
  tellRole(u) { // each player is told only their own state, as an opaque code
    const p = this.st.party; if (!p || !p.roles || !p.breached) return;
    this.to(u, { t: "you", r: this.roleOf(u) });
    if (this.infected(u)) this.to(u, { t: "others", clean: this.st.roster.filter(r => r.u !== u && !this.infected(r.u)).map(r => r.u) });
  }
  perceive() { // who feels the hum, and which clean players are "primed" (near an infected one)
    const p = this.st.party; if (!p || !p.breached) return;
    this.perc = this.perc || new Map();
    for (const a of this.st.roster) {
      let hn = 0, pr = 0; const ia = this.infected(a.u);
      for (const b of this.st.roster) { if (a.u === b.u) continue; const ib = this.infected(b.u);
        if (ia !== ib && this.near(a.u, b.u, NEAR_R)) hn = 1;
        if (!ia && ib && this.near(a.u, b.u, PRIME_R)) pr = 1; }
      if (ia) pr = 1;
      const old = this.perc.get(a.u) || {};
      if (old.hn !== hn) this.to(a.u, { t: "hn", v: hn });
      if (old.pr !== pr) this.to(a.u, { t: "pr", v: pr });
      this.perc.set(a.u, { hn, pr });
    }
  }
  infect(u) { // low dose: from something an infected player gave them
    const p = this.st.party; if (!p || !p.breached || this.infected(u)) return;
    p.roles[this.charOf(u)] = "c"; p.passed = p.passed || {};
    for (const r of this.st.roster) this.tellRole(r.u);
  }
  resolveVote(id) {
    const v = this.st.party && this.st.party.votes && this.st.party.votes[id]; if (!v || v.done) return;
    const counts = v.opts.map(() => 0); for (const k in v.ballots) counts[v.ballots[k]]++;
    const max = Math.max(...counts), top = counts.map((c, i) => c === max ? i : -1).filter(i => i >= 0);
    const pick = top.length === 1 ? top[0] : (top.includes(v.ballots[v.by]) ? v.ballots[v.by] : top[0]); // tie: whoever called it decides
    v.done = 1; v.pick = pick; this.all({ t: "voted", id, pick, counts });
  }
  pickHost() {
    const st = this.st;
    if (st.host && this.online(st.host)) return false;
    const next = st.roster.find(r => this.online(r.u));
    const h = next ? next.u : null;
    if (h !== st.host) { st.host = h; return true; }
    return false;
  }

  async init(owner, code) {
    await this.load();
    if (this.st && this.st.live && this.socks().length > 0) return { ok: false };
    this.st = { code, owner, created: now(), live: true, roster: [], host: null, phase: "lobby", map: null, seed: 0, taken: {}, drops: [], nextPk: 1, ledger: [] };
    await this.save();
    return { ok: true };
  }

  async fetch(req) {
    await this.load();
    const u = req.headers.get("x-user");
    const st = this.st;
    if (!u || !st || !st.live) return new Response("No such room", { status: 404 });
    let me = st.roster.find(r => r.u === u);
    if (!me) {
      if (st.roster.length >= ROOM_MAX) return new Response("Room full", { status: 403 });
      const usedC = new Set(st.roster.map(r => r.col)), usedCh = new Set(st.roster.map(r => r.char));
      me = { u, col: COLS.find(c => !usedC.has(c)), char: CHARS.find(c => !usedCh.has(c)), ready: false, ch: 1, joined: now() };
      st.roster.push(me);
      if (st.phase === "lobby") me.ready = false;
    }
    for (const old of this.socks(u)) this.kill(old, 4000, "Opened somewhere else");
    await this.ctx.storage.deleteAlarm();
    const pair = new WebSocketPair(), server = pair[1];
    this.ctx.acceptWebSocket(server, [u]);
    server.serializeAttachment({ u });
    this.pickHost();
    await this.save();
    this.send(server, { t: "hello", you: u, proto: PROTO });
    this.all(this.roomMsg());
    if (st.phase === "play" && st.mode === "story") {
      this.send(server, { t: "start", mode: "story", ph: st.party.ph, pf: st.party.pf, seed: st.seed, resume: true, taken: st.taken, drops: st.drops, cst: st.party.cst[me.char] || null });
      this.tellRole(u);
      if (st.host && st.host !== u) this.to(st.host, { t: "need", u });
    } else if (st.phase === "play") {
      this.send(server, { t: "start", map: st.map, seed: st.seed, resume: true, taken: st.taken, drops: st.drops });
      if (st.host && st.host !== u) this.to(st.host, { t: "need", u });
    }
    return new Response(null, { status: 101, webSocket: pair[0], headers: { "Sec-WebSocket-Protocol": "lull" } });
  }

  allow(u) { // token bucket: 25 msg/s sustained, burst 50
    const t = now(); let b = this.bucket.get(u);
    if (!b) { b = { tok: 50, t }; this.bucket.set(u, b); }
    b.tok = Math.min(50, b.tok + (t - b.t) * 0.025); b.t = t;
    if (b.tok < 1) return false; b.tok--; return true;
  }
  meter(force) {
    if (!force) this.msgs++;
    if (this.msgs > 0 && (force || this.msgs >= 100 || now() > this.flushAt)) {
      const n = this.msgs; this.msgs = 0; this.flushAt = now() + 60000;
      const acc = this.env.ACCOUNTS.get(this.env.ACCOUNTS.idFromName("global"));
      acc.addUsage(n, 0, 0).catch(() => { });
    }
  }

  async webSocketMessage(ws, raw) {
    await this.load();
    this.meter();
    const a = ws.deserializeAttachment(); if (!a) return;
    const u = a.u, st = this.st; if (!st) return;
    if (typeof raw !== "string" || raw.length > 16384) return;
    if (!this.allow(u)) return;
    let m; try { m = JSON.parse(raw); } catch (e) { return; }
    const me = st.roster.find(r => r.u === u); if (!me) return;
    const isHost = st.host === u;
    switch (m.t) {
      case "ping": this.send(ws, { t: "pong", c: m.c }); break;
      case "char": {
        if (st.phase !== "lobby" || !CHARS.includes(m.char)) break;
        if (st.roster.some(r => r.u !== u && r.char === m.char)) break;
        me.char = m.char; me.ready = false; await this.save(); this.all(this.roomMsg()); break;
      }
      case "ready": if (st.phase === "lobby") { me.ready = !!m.r; await this.save(); this.all(this.roomMsg()); } break;
      case "start": {
        if (!isHost || st.phase !== "lobby") break;
        const on = st.roster.filter(r => this.online(r.u));
        if (!on.every(r => r.ready || r.u === u)) { this.send(ws, { t: "sys", msg: "Not everyone is ready." }); break; }
        st.roster = on; // people who left the lobby don't hold a slot
        st.phase = "play"; st.map = String(m.map || "nettest").slice(0, 32); st.seed = (Math.random() * 1e9) | 0; st.taken = {}; st.drops = []; st.ledger = [];
        st.mode = m.mode === "story" ? "story" : "test"; st.party = null;
        if (st.mode === "story") {
          if (!on.some(r => r.char === "rowan")) { st.phase = "lobby"; this.send(ws, { t: "sys", msg: "Someone has to be Rowan." }); break; }
          st.party = { ph: "c1_wake", pf: {}, roles: {}, votes: {}, taint: {}, cst: {}, breached: 0, day: "" };
          if (m.cont) { const acc0 = this.env.ACCOUNTS.get(this.env.ACCOUNTS.idFromName("global")); const c = await acc0.getCoop(u);
            if (c && c.data) { st.party = Object.assign(st.party, c.data); st.party.votes = {}; } }
          st.map = st.party.ph;
        }
        await this.save();
        const acc = this.env.ACCOUNTS.get(this.env.ACCOUNTS.idFromName("global"));
        acc.addUsage(0, 1, on.length).catch(() => { });
        this.all(this.roomMsg());
        if (st.mode === "story") { for (const r of on) this.to(r.u, { t: "start", mode: "story", ph: st.party.ph, pf: st.party.pf, seed: st.seed, cst: st.party.cst[r.char] || null, taken: {}, drops: [], cont: !!m.cont });
          for (const r of on) this.tellRole(r.u); }
        else this.all({ t: "start", map: st.map, seed: st.seed, taken: {}, drops: [] });
        break;
      }
      case "lobby": { // host returns everyone to the lobby
        if (!isHost) break;
        st.phase = "lobby"; st.roster.forEach(r => r.ready = false); await this.save();
        this.all(this.roomMsg()); this.all({ t: "lobby" }); break;
      }
      case "st": { // own player state
        const x = +m.x, y = +m.y; if (!isFinite(x) || !isFinite(y)) break;
        this.pos.set(u, { x, y, m: String(m.m || ""), t: now() });
        if (!isHost) delete m.h;  // only the host may carry the Hollowed
        m.u = u; delete m.t; this.others(u, { t: "ps", ...m });
        if (st.mode === "story") this.perceive();
        break;
      }
      case "ws": if (isHost) { m.t = "ws"; this.others(u, m); } break;                 // world snapshot (Hollowed)
      case "hx": if (isHost) { this.others(u, { t: "hx", id: m.id, lx: m.lx, ly: m.ly, x: m.x, y: m.y }); } break; // Hollowed lunge
      case "hh": if (st.host && !isHost) this.to(st.host, { t: "hh", id: m.id, dmg: +m.dmg || 0, fx: +m.fx || 0, fy: +m.fy || 0, kb: +m.kb || 0, by: u }); break;
      case "kill": if (isHost) this.all({ t: "kill", id: m.id, by: m.by }); break;
      case "pick": {
        const id = String(m.id);
        if (st.taken[id]) { this.send(ws, { t: "gone", id }); break; }
        st.taken[id] = u; st.drops = st.drops.filter(d => d.id !== id);
        if (st.party && st.party.taint && st.party.taint[id]) this.infect(u);
        await this.save(); this.all({ t: "got", id, by: u }); break;
      }
      case "spawn": { // a dropped item becomes a shared pickup
        const it = String(m.item || "").slice(0, 24), x = +m.x, y = +m.y;
        if (!it || !isFinite(x) || !isFinite(y) || st.drops.length > 200) break;
        const d = { id: "d" + (st.nextPk++), item: it, n: Math.max(1, Math.min(9, m.n | 0)), x, y };
        st.drops.push(d);
        if (st.party && st.party.breached && this.infected(u) && CONSUMABLE.has(it)) st.party.taint[d.id] = 1;
        await this.save(); this.all({ t: "pk+", ...d }); break;
      }
      case "give": {
        const to = String(m.to || ""), it = String(m.item || "").slice(0, 24);
        if (to === u || !st.roster.some(r => r.u === to) || !this.online(to) || !it) { this.send(ws, { t: "gave", ok: false, to, item: it }); break; }
        if (!this.near(u, to, GIVE_R)) { this.send(ws, { t: "gave", ok: false, to, item: it, far: true }); break; }
        st.ledger.push({ from: u, to, item: it, t: now() }); if (st.ledger.length > 500) st.ledger.shift();
        if (st.party && st.party.breached && this.infected(u) && !this.infected(to) && CONSUMABLE.has(it)) {
          const p = st.party; p.passed = p.passed || {}; p.passed[this.charOf(u)] = 1; this.infect(to); await this.save(); }
        this.to(to, { t: "gift", from: u, item: it });
        this.send(ws, { t: "gave", ok: true, to, item: it });
        break;
      }
      case "say": { // aloud: only people close enough hear it, and they see who said it
        const ph = m.ph | 0;
        for (const r of st.roster) if (r.u === u || this.near(u, r.u, SAY_R)) this.to(r.u, { t: "say", u, ph });
        break;
      }
      case "chan": { const c = m.ch | 0; if (c >= 1 && c <= 4) { me.ch = c; } break; }
      case "rad": case "clk": { // radio: no name, only a voice colour; quality falls with distance
        const ch = me.ch || 1, p = this.pos.get(u);
        for (const r of st.roster) {
          if (r.u === u || (r.ch || 1) !== ch) continue;
          const q2 = this.pos.get(r.u); let q = 1;
          if (p && q2) { const d = p.m === q2.m ? Math.hypot(p.x - q2.x, p.y - q2.y) : 2000; q = Math.max(.25, Math.min(1, 1 - (d - 300) / 1500)); }
          if (m.t === "rad") this.to(r.u, { t: "rad", col: me.col, ph: m.ph | 0, ch, q: +q.toFixed(2) });
          else this.to(r.u, { t: "clk", col: me.col, pat: Array.isArray(m.pat) ? m.pat.slice(0, 12).map(v => Math.max(0, Math.min(4000, v | 0))) : [], ch, q: +q.toFixed(2) });
        }
        break;
      }
      case "down": this.others(u, { t: "down", u }); break;
      case "up": this.others(u, { t: "up", u }); break;
      case "rev": { const to = String(m.to || ""); if (this.near(u, to, REV_R)) { this.to(to, { t: "revived", by: u }); this.others(to, { t: "up", u: to }); } break; }
      case "fx": this.others(u, { t: "fx", u, k: String(m.k || "").slice(0, 16) }); break; // cosmetic one-shots (torch click etc.)
      // ---------------- story mode ----------------
      case "pf": { // a shared story flag
        if (!st.party) break; const k = String(m.k || "").slice(0, 40); if (!k) break;
        const v = typeof m.v === "number" || typeof m.v === "string" || typeof m.v === "boolean" ? m.v : 1;
        if (Object.keys(st.party.pf).length > 600) break;
        st.party.pf[k] = v; await this.save(); this.others(u, { t: "pf", k, v, by: u }); break;
      }
      case "cph": { // move the whole party to a new scene (only once, whoever asks first)
        if (!st.party || String(m.from) !== st.party.ph) break;
        st.party.ph = String(m.ph || "").slice(0, 32); if (m.day) st.party.day = String(m.day).slice(0, 40);
        st.taken = {}; st.drops = []; await this.save();
        this.all({ t: "cph", ph: st.party.ph, card: Array.isArray(m.card) ? m.card.slice(0, 3).map(x => String(x).slice(0, 80)) : null, glitch: !!m.glitch });
        break;
      }
      case "breach": { // Day 2: one of them breathes it in. Nobody is told.
        if (!st.party || st.party.breached) break;
        const on = st.roster.filter(r => this.online(r.u)); if (!on.length) break;
        const pick = on[(crypto.getRandomValues(new Uint32Array(1))[0]) % on.length];
        st.party.roles = {}; for (const r of st.roster) st.party.roles[r.char] = "b";
        st.party.roles[pick.char] = "a"; st.party.breached = 1; st.party.carrier = pick.char;
        await this.save(); for (const r of st.roster) this.tellRole(r.u); this.perc = new Map(); this.perceive(); break;
      }
      case "vote": { // open a party vote
        if (!st.party) break; const id = String(m.id || "").slice(0, 32); if (!id) break;
        if (st.party.votes[id] && !st.party.votes[id].done) break;
        const opts = (Array.isArray(m.opts) ? m.opts : []).slice(0, 4).map(x => String(x).slice(0, 90)); if (opts.length < 2) break;
        st.party.votes[id] = { q: String(m.q || "").slice(0, 160), opts, by: u, ballots: {} };
        this.all({ t: "ballot", id, q: st.party.votes[id].q, opts, by: u });
        setTimeout(() => { this.resolveVote(id); }, 30000);
        break;
      }
      case "cast": {
        const v = st.party && st.party.votes[String(m.id)]; if (!v || v.done) break;
        const pk = m.pick | 0; if (pk < 0 || pk >= v.opts.length) break;
        v.ballots[u] = pk; this.all({ t: "cast", id: m.id, u });
        if (st.roster.filter(r => this.online(r.u)).every(r => v.ballots[r.u] !== undefined)) this.resolveVote(String(m.id));
        break;
      }
      case "pet": // Biscuit knows. Everyone nearby sees how he reacts.
        if (!st.party) break; this.all({ t: "dog", u, growl: st.party.breached && this.infected(u) ? 1 : 0 }); break;
      case "pupil": { // a torch held on someone's face: only the person holding it sees the answer
        const to = String(m.to || ""); if (!st.party || !this.near(u, to, 60)) break;
        this.send(ws, { t: "pupils", to, react: st.party.breached && this.infected(to) ? 0 : 1 });
        this.to(to, { t: "shone", by: u }); break;
      }
      case "hear": { // someone nearby is talking to somebody; you catch it if you're close
        const who = String(m.who || "").slice(0, 24), text = String(m.text || "").slice(0, 300);
        for (const r of st.roster) if (r.u !== u && this.near(u, r.u, HEAR_R)) this.to(r.u, { t: "hear", by: u, who, text, x: +m.x || 0, y: +m.y || 0 });
        break;
      }
      case "gossip": { // what a clean player half-remembers about the neighbours (one true thing, one red herring)
        if (!st.party || !st.party.breached || this.infected(u)) { this.send(ws, { t: "gossip", g: [] }); break; }
        const mine = this.charOf(u), car = st.party.carrier, others = st.roster.map(r => r.char).filter(c => c !== mine && c !== car);
        const r = () => crypto.getRandomValues(new Uint8Array(1))[0] % 3, g = [];
        if (car && car !== mine) g.push([car, "a", r()]);
        if (others.length) g.push([others[crypto.getRandomValues(new Uint8Array(1))[0] % others.length], "b", r()]);
        if (g.length === 2 && crypto.getRandomValues(new Uint8Array(1))[0] & 1) g.reverse();
        this.send(ws, { t: "gossip", g }); break;
      }
      case "cst": { // a player's own stats and bag, kept for the co-op save
        if (!st.party || !me.char) break; const s = JSON.stringify(m.s || {}); if (s.length > 20000) break;
        st.party.cst[me.char] = m.s; break;
      }
      case "csave": { // host: write the co-op save to the host's account
        if (!isHost || !st.party) break; await this.save();
        const acc = this.env.ACCOUNTS.get(this.env.ACCOUNTS.idFromName("global"));
        const data = { ph: st.party.ph, pf: st.party.pf, roles: st.party.roles, breached: st.party.breached, carrier: st.party.carrier, passed: st.party.passed || {}, cst: st.party.cst, day: st.party.day };
        const r = await acc.putCoop(u, data); this.send(ws, { t: "csaved", ok: !r.error }); break;
      }
      case "leave": {
        if (st.phase === "lobby") st.roster = st.roster.filter(r => r.u !== u);
        await this.gone(ws, true);
        break;
      }
    }
  }

  async webSocketClose(ws, code) { try { ws.close(1000, "bye"); } catch (e) { } await this.gone(ws); } // complete the closing handshake
  async webSocketError(ws) { await this.gone(ws); }
  async gone(ws, closeIt) {
    await this.load(); const st = this.st; if (!st) return;
    const a = ws.deserializeAttachment() || {}, u = a.u;
    if (a.dead) return;                       // already handled
    if (closeIt) this.kill(ws, 1000, "Left"); else { try { ws.serializeAttachment({ ...a, dead: 1 }); } catch (e) { } }
    if (u && !this.online(u)) {
      this.pos.delete(u);
      if (st.host === u) { st.host = null; this.pickHost(); if (st.host) this.all({ t: "host", u: st.host }); }
      this.all({ t: "left", u });
      this.all(this.roomMsg());
    }
    await this.save();
    this.meter(true);
    if (this.socks().length === 0) await this.ctx.storage.setAlarm(now() + 2 * 3600000); // tidy up after 2 h empty
  }
  async alarm() {
    if (this.socks().length === 0) { await this.ctx.storage.deleteAll(); this.st = null; this.loaded = true; }
  }
}

// =====================================================================
// WORKER — routing, auth, origin checks
// =====================================================================
function accounts(env) { return env.ACCOUNTS.get(env.ACCOUNTS.idFromName("global")); }
async function body(req) {
  const t = await req.text(); if (t.length > 70000) throw new Error("big");
  try { return JSON.parse(t || "{}"); } catch (e) { return {}; }
}
function ipOf(req) { return req.headers.get("cf-connecting-ip") || "local"; }
async function userOf(req, env) {
  const h = req.headers.get("authorization") || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7) : null;
  return tok ? await accounts(env).auth(tok) : null;
}
function tokenOf(req) { const h = req.headers.get("authorization") || ""; return h.startsWith("Bearer ") ? h.slice(7) : ""; }

async function api(req, env, url) {
  const p = url.pathname, M = req.method;
  // Cross-site protection: browsers send Origin; only our own page may call the API.
  const origin = req.headers.get("origin");
  const allowed = [url.origin].concat((env.EXTRA_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean));
  if (origin && !allowed.includes(origin)) return err("Not allowed from that site.", 403);

  if (p === "/api/ping") return json({ ok: true, t: now(), proto: PROTO });
  if (p === "/api/status") { const t = await accounts(env).today(); const lim = +(env.DAILY_BUDGET || 90000); return json({ ok: true, proto: PROTO, used: t.msgs, limit: lim }); }

  const acc = accounts(env), ip = ipOf(req);
  if (p === "/api/register" && M === "POST") { const b = await body(req); const r = await acc.register(b.u, b.p, ip, +(env.SIGNUP_LIMIT || 40)); return r.error ? err(r.error) : json(r); }
  if (p === "/api/login" && M === "POST") { const b = await body(req); const r = await acc.login(b.u, b.p, ip); return r.error ? err(r.error, 401) : json(r); }
  if (p === "/api/reset" && M === "POST") { const b = await body(req); const r = await acc.resetWithCode(b.u, b.code, b.p); return r.error ? err(r.error) : json(r); }

  if (p.startsWith("/api/admin/")) {
    const key = req.headers.get("x-admin-key") || "";
    const ok = !!env.ADMIN_KEY && env.ADMIN_KEY.length >= 12 && safeEq(key, env.ADMIN_KEY);
    const g = await acc.adminGate(ip, ok);
    if (g.locked) return err("Locked for an hour after wrong admin keys.", 429);
    if (!ok) return err(env.ADMIN_KEY ? "Wrong admin key." : "ADMIN_KEY isn't set in Cloudflare yet.", 403);
    const b = M === "POST" ? await body(req) : {};
    if (p === "/api/admin/reset") return json(await acc.adminReset(b.u));
    if (p === "/api/admin/delete") return json(await acc.adminDelete(b.u));
    if (p === "/api/admin/users") return json(await acc.adminUsers());
    if (p === "/api/admin/usage") return json({ limit: +(env.DAILY_BUDGET || 90000), days: await acc.usage() });
    return err("Unknown admin action.", 404);
  }

  const u = await userOf(req, env);
  if (!u) return err("Please sign in again.", 401);
  if (p === "/api/me") return json({ u });
  if (p === "/api/logout" && M === "POST") { await acc.logout(tokenOf(req)); return json({ ok: true }); }
  if (p === "/api/save" && M === "GET") return json(await acc.getSave(u));
  if (p === "/api/coop" && M === "GET") { const c = await acc.getCoop(u); return json(c ? { ph: c.data.ph, chars: Object.keys(c.data.cst || {}), day: c.data.day || "", updated: c.updated } : { none: true }); }
  if (p === "/api/coop" && M === "DELETE") return json(await acc.delCoop(u));
  if (p === "/api/save" && M === "PUT") { const b = await body(req); const r = await acc.putSave(u, b.data, b.baseRev | 0, !!b.force); return r.error ? err(r.error, 413) : json(r, r.conflict ? 409 : 200); }
  if (p === "/api/room" && M === "POST") {
    // The meter only warns: whether Cloudflare's free plan counts every message or 1 in 20 is
    // still unknown, so we don't refuse games on a guess. Cloudflare itself stops at the real limit.
    for (let i = 0; i < 6; i++) {
      const code = pickChars(CODE_ABC, 4);
      const r = await env.ROOMS.get(env.ROOMS.idFromName(code)).init(u, code);
      if (r.ok) return json({ code });
    }
    return err("Couldn't make a room. Try again.", 503);
  }
  return err("Not found.", 404);
}

async function ws(req, env, url) {
  if (req.headers.get("upgrade") !== "websocket") return err("Expected a WebSocket.", 426);
  const origin = req.headers.get("origin");
  const allowed = [url.origin].concat((env.EXTRA_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean));
  if (origin && !allowed.includes(origin)) return err("Not allowed from that site.", 403);
  if (url.pathname === "/ws/echo") { // connection test, no account needed
    const pair = new WebSocketPair(), s = pair[1]; s.accept(); let n = 0;
    s.addEventListener("message", e => { if (++n > 30) { s.close(1000, "done"); return; } s.send(typeof e.data === "string" ? e.data.slice(0, 200) : ""); });
    return new Response(null, { status: 101, webSocket: pair[0] });
  }
  const m = url.pathname.match(/^\/ws\/room\/([A-Z]{4})$/);
  if (!m) return err("Not found.", 404);
  // the session token travels as a WebSocket sub-protocol (never in the URL, so it isn't logged)
  const protos = (req.headers.get("sec-websocket-protocol") || "").split(",").map(s => s.trim());
  const tok = protos.find(s => s !== "lull");
  const u = tok ? await accounts(env).auth(tok) : null;
  if (!u) return err("Please sign in again.", 401);
  const h = new Headers(req.headers); h.set("x-user", u);
  return env.ROOMS.get(env.ROOMS.idFromName(m[1])).fetch(new Request(req, { headers: h }));
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (url.pathname.startsWith("/api/")) return await api(req, env, url);
      if (url.pathname.startsWith("/ws/")) return await ws(req, env, url);
    } catch (e) {
      const m = String(e && e.message || "");
      if (m === "big") return err("Too large.", 413);
      if (/exceeded|limit/i.test(m)) return err("Today's free online allowance is used up. Solo still works; online play resets at midnight UTC.", 429);
      return err("Server error.", 500);
    }
    return env.ASSETS ? env.ASSETS.fetch(req) : new Response("Not found", { status: 404 });
  },
};
