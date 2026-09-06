

'use strict';
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const { DatabaseSync } = require('node:sqlite');
const bcrypt = require('bcryptjs');

const { COUNTRIES } = require('./countries');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'panel.db');

const PORT = process.env.PORT || process.env.SERVER_PORT || 3000;

const e = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
const attrJson = (obj) => e(JSON.stringify(obj));

const SH = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Shanghai', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
function shParts(d) { const p = {}; for (const x of SH.formatToParts(d)) p[x.type] = x.value; return p; }
function shDateTime(d) { const p = shParts(d); return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}`; }
function hourKey(d) { const p = shParts(d); return `${p.year}${p.month}${p.day}${p.hour}`; }
const shTimeHM = new Intl.DateTimeFormat('zh-CN', { timeZone: 'Asia/Shanghai', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });

function kaIvText(m) {
  m = Math.max(1, m);
  if (m % 1440 === 0) return (m / 1440) + ' 天';
  if (m % 60 === 0) return (m / 60) + ' 小时';
  return m + ' 分钟';
}

let db = null;
const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS pm_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
  )`,
  `CREATE TABLE IF NOT EXISTS pm_clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    country TEXT NOT NULL DEFAULT '其他',
    url TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT '',
    sort_order INTEGER NOT NULL DEFAULT 0,
    keepalive INTEGER NOT NULL DEFAULT 0,
    ka_interval INTEGER,
    ka_ptero INTEGER NOT NULL DEFAULT 0,
    ka_ptero_url TEXT NOT NULL DEFAULT '',
    ka_ptero_key TEXT NOT NULL DEFAULT '',
    ka_ptero_sid TEXT NOT NULL DEFAULT '',
    renew INTEGER NOT NULL DEFAULT 0,
    renew_url TEXT NOT NULL DEFAULT '',
    rn_interval INTEGER
  )`,
  `CREATE TABLE IF NOT EXISTS pm_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS pm_group_members (
    group_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, client_id)
  )`,
  `CREATE TABLE IF NOT EXISTS pm_notify (
    id INTEGER PRIMARY KEY,
    type TEXT NOT NULL DEFAULT 'none',
    tg_token TEXT NOT NULL DEFAULT '',
    tg_chat TEXT NOT NULL DEFAULT '',
    custom_url TEXT NOT NULL DEFAULT ''
  )`,
  `CREATE TABLE IF NOT EXISTS pm_status_history (
    client_id TEXT NOT NULL,
    hour_key TEXT NOT NULL,
    up INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    ms_sum INTEGER NOT NULL DEFAULT 0,
    ms_n INTEGER NOT NULL DEFAULT 0,
    downs INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (client_id, hour_key)
  )`,
  `CREATE TABLE IF NOT EXISTS pm_status_last (
    client_id TEXT PRIMARY KEY,
    s INTEGER NOT NULL DEFAULT 0,
    ms INTEGER,
    t INTEGER NOT NULL DEFAULT 0,
    last_notify INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS pm_keepalive (
    id INTEGER PRIMARY KEY,
    interval_min INTEGER NOT NULL DEFAULT 5,
    last_run INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE TABLE IF NOT EXISTS pm_keepalive_results (
    client_id TEXT PRIMARY KEY,
    t INTEGER NOT NULL DEFAULT 0,
    code INTEGER NOT NULL DEFAULT 0,
    renew_t INTEGER NOT NULL DEFAULT 0,
    renew_code INTEGER NOT NULL DEFAULT 0
  )`,
];

function getDB() {
  if (db) return db;
  fs.mkdirSync(DATA_DIR, { recursive: true });
  db = new DatabaseSync(DB_FILE);
  db.exec('PRAGMA journal_mode = WAL');
  for (const sql of SCHEMA) db.exec(sql);
  
  if (get('SELECT COUNT(*) AS n FROM pm_users').n === 0) {
    run('INSERT INTO pm_users (username, password_hash) VALUES (?, ?)', 'admin', bcrypt.hashSync('admin', 10));
  }
  run('INSERT OR IGNORE INTO pm_keepalive (id, interval_min, last_run) VALUES (1, 5, 0)');
  return db;
}
const run = (sql, ...params) => getDB().prepare(sql).run(...params);
const get = (sql, ...params) => getDB().prepare(sql).get(...params);
const all = (sql, ...params) => getDB().prepare(sql).all(...params);

function rawRequest(targetUrl, { method = 'HEAD', timeout = 5000, headers = {}, body = null }) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(targetUrl); } catch { return resolve({ code: 0, ms: 0, location: '' }); }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return resolve({ code: 0, ms: 0, location: '' });
    const mod = u.protocol === 'https:' ? https : http;
    const t0 = Date.now();
    const req = mod.request(u, {
      method,
      headers: Object.assign({ 'User-Agent': 'Mozilla/5.0 (compatible; PanelManager/1.0)', Accept: '*/*' }, headers),
      rejectUnauthorized: false, 
      timeout,
    }, (res) => {
      res.resume();
      resolve({ code: res.statusCode || 0, ms: Date.now() - t0, location: res.headers.location || '' });
    });
    req.on('timeout', () => { req.destroy(); resolve({ code: 0, ms: Date.now() - t0, location: '' }); });
    req.on('error', () => resolve({ code: 0, ms: Date.now() - t0, location: '' }));
    if (body !== null) req.write(body);
    req.end();
  });
}
async function fetchFollow(url, opts, depth = 0) {
  if (depth > 5) return { code: 0, ms: 0 };
  const r = await rawRequest(url, opts);
  if ([301, 302, 303, 307, 308].includes(r.code) && r.location) {
    try { return await fetchFollow(new URL(r.location, url).toString(), opts, depth + 1); } catch { return { code: 0, ms: r.ms }; }
  }
  return r;
}
 
async function probeAll(urlMap, head = true) {
  const entries = Object.entries(urlMap);
  if (entries.length === 0) return {};
  const results = {};
  await Promise.all(entries.map(async ([key, url]) => {
    let r = await fetchFollow(url, { method: head ? 'HEAD' : 'GET', timeout: head ? 5000 : 8000 });

    if (head && (r.code === 405 || r.code === 501)) {
      r = await fetchFollow(url, { method: 'GET', timeout: 8000 });
    }
    results[key] = { code: r.code || 0, ms: r.ms };
  }));
  return results;
}

async function pteroApi(method, url, key, json) {
  const headers = { Authorization: 'Bearer ' + key, Accept: 'application/vnd.pterodactyl.v1+json' };
  if (json !== null && json !== undefined) headers['Content-Type'] = 'application/json';
  const r = await rawRequest(url, { method, timeout: 10000, headers, body: json !== null && json !== undefined ? JSON.stringify(json) : null });
  return { code: r.code };
}
function rawGetJson(url, key) {
  return new Promise((resolve) => {
    let u;
    try { u = new URL(url); } catch { return resolve({ code: 0, body: '' }); }
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, {
      method: 'GET', timeout: 10000, rejectUnauthorized: false,
      headers: { Authorization: 'Bearer ' + key, Accept: 'application/vnd.pterodactyl.v1+json' },
    }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ code: res.statusCode || 0, body }));
    });
    req.on('timeout', () => { req.destroy(); resolve({ code: 0, body: '' }); });
    req.on('error', () => resolve({ code: 0, body: '' }));
    req.end();
  });
}
 
async function pteroState(base, key, sid) {
  const r = await rawGetJson(`${base.replace(/\/+$/, '')}/api/client/servers/${encodeURIComponent(sid)}/resources`, key);
  if (r.code !== 200) return null;
  try { const d = JSON.parse(r.body); return String((d.attributes || {}).current_state || ''); } catch { return null; }
}
 
async function pteroManualStart(base, key, sid) {
  base = base.replace(/\/+$/, '');
  sid = encodeURIComponent(sid);
  const state = await pteroState(base, key, sid);
  if (state === null) return { code: 0, powered: false };
  if (state === 'offline' || state === 'stopping') {
    const { code } = await pteroApi('POST', `${base}/api/client/servers/${sid}/power`, key, { signal: 'start' });
    return { code, powered: true };
  }
  return { code: 200, powered: false };
}

function sendNotification(cfg, title, body) {
  return new Promise((resolve) => {
    const type = cfg.type || 'none';
    if (type === 'none') return resolve(null);
    let url;
    if (type === 'telegram') {
      const token = String(cfg.tg_token || '').trim(), chat = String(cfg.tg_chat || '').trim();
      if (token === '' || chat === '') return resolve('Telegram Token / Chat ID 未填写');
      url = 'https://api.telegram.org/bot' + token + '/sendMessage?' + new URLSearchParams({ chat_id: chat, text: title + '\n' + body }).toString();
    } else if (type === 'custom') {
      const tpl = String(cfg.custom_url || '').trim();
      if (tpl === '' || !/^https?:\/\//.test(tpl.replace('{title}', 'x').replace('{body}', 'x'))) return resolve('自定义通知 URL 未填写或无效');
      url = tpl.replace('{title}', encodeURIComponent(title)).replace('{body}', encodeURIComponent(body));
    } else return resolve('未知的通知方式');
    rawRequest(url, { method: 'GET', timeout: 5000 }).then(() => resolve(null)).catch(() => resolve('发送失败'));
  });
}

const NOTIFY_COOLDOWN = 60;
const KEEP_HOURS = 48;

function statusLogic() {
  const clients = all('SELECT id, url, name, country, keepalive, ka_interval, ka_ptero, ka_ptero_url, ka_ptero_key, ka_ptero_sid, renew, renew_url, rn_interval FROM pm_clients ORDER BY sort_order, id');
  const targets = {}, clientInfo = {}, kaTargets = {}, kaIv = {}, rnIv = {}, kaPtero = {}, rnTargets = {};
  for (const row of clients) {
    const id = String(row.id);
    const url = String(row.url || '').trim();
    targets[id] = /^https?:\/\/.+/i.test(url) ? url : '';
    clientInfo[id] = { name: String(row.name || '客户端'), country: String(row.country || '') };
    
    kaIv[id] = Number(row.ka_interval || 0);
    rnIv[id] = Number(row.rn_interval || 0);
    if (Number(row.keepalive) === 1 && targets[id] !== '') {
      kaTargets[id] = targets[id];
      const pUrl = String(row.ka_ptero_url || '').trim(), pKey = String(row.ka_ptero_key || '').trim(), pSid = String(row.ka_ptero_sid || '').trim();
      if (Number(row.ka_ptero) === 1 && pUrl !== '' && pKey !== '' && pSid !== '') kaPtero[id] = { url: pUrl, key: pKey, sid: pSid };
    }
    
    const rUrl = String(row.renew_url || '').trim();
    if (Number(row.renew) === 1 && /^https?:\/\/.+/i.test(rUrl)) rnTargets[id] = rUrl;
  }

  return probeAll(Object.fromEntries(Object.entries(targets).filter(([, u]) => u !== ''))).then((probes) => {
    const notify = get('SELECT type, tg_token, tg_chat, custom_url FROM pm_notify WHERE id = 1') || { type: 'none' };
    const lastStates = {};
    all('SELECT client_id, s, ms, t, last_notify FROM pm_status_last').forEach((r) => { lastStates[r.client_id] = r; });

    const now = Math.floor(Date.now() / 1000);
    const hourK = hourKey(new Date(now * 1000));
    const cutoff24 = hourKey(new Date((now - 86400) * 1000));
    const cutoff48 = hourKey(new Date((now - KEEP_HOURS * 3600) * 1000));

    const current = {};
    for (const [id, url] of Object.entries(targets)) {
      const code = url !== '' ? ((probes[id] || {}).code || 0) : 0;
      const ms = url !== '' ? ((probes[id] || {}).ms ?? null) : null;
      const s = code >= 200 && code < 500 ? 1 : 0;
      current[id] = { s, ms };

      const prev = lastStates[id];
      const prevS = prev ? Number(prev.s) : null;
      let lastNotify = prev ? Number(prev.last_notify) : 0;

      const isTransition = prevS !== null && prevS !== s;
      const msSum = s === 1 && ms !== null ? ms : 0;
      const msN = s === 1 && ms !== null ? 1 : 0;
      const downs = isTransition && s === 0 ? 1 : 0;

      run(
        'INSERT INTO pm_status_history (client_id, hour_key, up, total, ms_sum, ms_n, downs) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(client_id, hour_key) DO UPDATE SET up = up + excluded.up, total = total + excluded.total, ms_sum = ms_sum + excluded.ms_sum, ms_n = ms_n + excluded.ms_n, downs = downs + excluded.downs',
        id, hourK, s, 1, msSum, msN, downs
      );

      if (isTransition && notify.type !== 'none' && now - lastNotify >= NOTIFY_COOLDOWN) {
        const info = clientInfo[id] || { name: '客户端', country: '' };
        const title = s === 1 ? '✅ 客户端恢复在线' : '🔴 客户端掉线';
        let body = info.name + (info.country !== '' ? `（${info.country}）` : '') + ' · ' + shDateTime(new Date(now * 1000)).slice(11);
        if (url !== '') body += '\n' + url;
        
        run('INSERT INTO pm_status_last (client_id, s, ms, t, last_notify) VALUES (?, ?, ?, ?, ?) ON CONFLICT(client_id) DO UPDATE SET s = excluded.s, ms = excluded.ms, t = excluded.t, last_notify = excluded.last_notify',
          id, s, ms, now, now);
        sendNotification(notify, title, body);
        continue;
      }
      run('INSERT INTO pm_status_last (client_id, s, ms, t, last_notify) VALUES (?, ?, ?, ?, ?) ON CONFLICT(client_id) DO UPDATE SET s = excluded.s, ms = excluded.ms, t = excluded.t, last_notify = excluded.last_notify',
        id, s, ms, now, lastNotify);
    }

    run('DELETE FROM pm_status_history WHERE hour_key < ?', cutoff48);
    run('DELETE FROM pm_status_last WHERE client_id NOT IN (SELECT id FROM pm_clients)');
    run('DELETE FROM pm_keepalive_results WHERE client_id NOT IN (SELECT id FROM pm_clients)');

    const statRows = all('SELECT client_id, SUM(up) AS u, SUM(total) AS t, SUM(ms_sum) AS mss, SUM(ms_n) AS msn, SUM(downs) AS d FROM pm_status_history WHERE hour_key >= ? GROUP BY client_id', cutoff24);
    const stats = {};
    statRows.forEach((r) => { stats[r.client_id] = r; });

    const payload = {};
    for (const [id] of Object.entries(targets)) {
      const st = stats[id];
      const total = st ? Number(st.t) : 0;
      const up = st ? Number(st.u) : 0;
      const msN = st ? Number(st.msn) : 0;
      payload[id] = {
        s: Number((current[id] || {}).s || 0),
        ms: (current[id] || {}).ms ?? null,
        up24: total > 0 ? Math.round(up / total * 1000) / 10 : null,
        downs: st ? Number(st.d) : 0,
        avg: msN > 0 ? Math.round(Number(st ? st.mss : 0) / msN) : null,
      };
    }

    const kaRow = get('SELECT interval_min FROM pm_keepalive WHERE id = 1');
    const kaInterval = kaRow ? Math.max(1, Number(kaRow.interval_min)) : 5;
    const kaPrev = {}, kaPrevR = {};
    all('SELECT client_id, t, renew_t FROM pm_keepalive_results').forEach((r) => { kaPrev[r.client_id] = Number(r.t); kaPrevR[r.client_id] = Number(r.renew_t); });

    const due = [], duePtero = [], dueRenew = [];
    for (const [kid, url] of Object.entries(kaTargets)) {
      const iv = kaIv[kid] > 0 ? kaIv[kid] : kaInterval;
      const lastT = kaPrev[kid] || 0;
      if (now - lastT < iv * 60) continue;
      if (kaPtero[kid]) duePtero[kid] = kaPtero[kid];
      else due[kid] = url;
    }
    
    for (const [kid, url] of Object.entries(rnTargets)) {
      const iv = rnIv[kid] > 0 ? rnIv[kid] : kaInterval;
      const lastT = kaPrevR[kid] || 0;
      if (now - lastT >= iv * 60) dueRenew[kid] = url;
    }

    return (async () => {
      if (Object.keys(due).length > 0) {
        const runKa = await probeAll(due, false);
        for (const [kid, r] of Object.entries(runKa)) {
          run('INSERT INTO pm_keepalive_results (client_id, t, code) VALUES (?, ?, ?) ON CONFLICT(client_id) DO UPDATE SET t = excluded.t, code = excluded.code', kid, now, r.code);
        }
      }
      if (Object.keys(dueRenew).length > 0) {
        const runRn = await probeAll(dueRenew, false);
        for (const [kid, r] of Object.entries(runRn)) {
          run('INSERT INTO pm_keepalive_results (client_id, t, code, renew_t, renew_code) VALUES (?, 0, 0, ?, ?) ON CONFLICT(client_id) DO UPDATE SET renew_t = excluded.renew_t, renew_code = excluded.renew_code', kid, now, r.code);
        }
      }

      for (const [kid, cfg] of Object.entries(duePtero)) {
        const probeCode = (probes[kid] || {}).code || 0;
        let code;
        if (probeCode >= 200 && probeCode < 500) {
          code = probeCode;
        } else {
          const r = await pteroApi('POST', `${cfg.url.replace(/\/+$/, '')}/api/client/servers/${encodeURIComponent(cfg.sid)}/power`, cfg.key, { signal: 'start' });
          code = r.code;
        }
        run('INSERT INTO pm_keepalive_results (client_id, t, code) VALUES (?, ?, ?) ON CONFLICT(client_id) DO UPDATE SET t = excluded.t, code = excluded.code', kid, now, code);
      }

      const kaResults = {}, kaRenewals = {};
      all('SELECT client_id, t, code, renew_t, renew_code FROM pm_keepalive_results').forEach((r) => {
        kaResults[r.client_id] = { t: Number(r.t), code: Number(r.code) };
        if (Number(r.renew_t) > 0) kaRenewals[r.client_id] = { t: Number(r.renew_t), code: Number(r.renew_code) };
      });

      payload._ka = { interval: kaInterval, results: kaResults, renewals: kaRenewals };
      return payload;
    })();
  });
}

module.exports = { e, attrJson, shDateTime, hourKey, kaIvText, COUNTRIES, getDB, statusLogic, pteroApi, pteroManualStart, sendNotification, PORT, DB_FILE, shTimeHM };
