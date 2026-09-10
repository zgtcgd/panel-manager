'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const {
  e, shDateTime, getDB, runStatusLogic, pteroApi, pteroManualStart, sendNotification, PORT,
} = require('./core');
const { appPage } = require('./pages');

const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));

const sessions = new Map();
const COOKIE = 'pmsid';

app.use((req, res, next) => {
  const cookies = Object.fromEntries(
    String(req.headers.cookie || '').split(';').map((p) => p.trim().split('=')).filter((p) => p[0])
      .map(([k, ...v]) => [k, decodeURIComponent(v.join('='))])
  );
  let sid = cookies[COOKIE];
  let session = sid && sessions.get(sid);
  if (!session) {
    sid = crypto.randomBytes(24).toString('hex');
    session = { user: null, csrf: crypto.randomBytes(16).toString('hex'), fails: 0, lastFail: 0 };
    sessions.set(sid, session);
  }
  req.sid = sid;
  req.session = session;
  res.setHeader('Set-Cookie', `${COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Lax`);
  next();
});

function loggedIn(req) { return !!(req.session && req.session.user); }
function verifyCsrf(req) {
  if (req.session.csrf !== req.body.csrf) { req.res.status(419).send('请求已过期，请刷新页面重试'); return false; }
  return true;
}
const newId = () => crypto.randomBytes(6).toString('hex');

function parseDetectSec(val, unit) {
  const v = String(val ?? '').trim();
  if (v === '') return null;
  const mult = unit === 'min' ? 60 : (unit === 'hour' ? 3600 : (unit === 'day' ? 86400 : 1));
  return Math.max(5, Math.min(86400, (parseInt(v, 10) || 0) * mult));
}

function parseMinutesAllowZero(val, unit) {
  const v = String(val ?? '').trim();
  if (v === '') return null;
  const mult = unit === 'hour' ? 60 : (unit === 'day' ? 1440 : 1);
  return Math.min(43200, Math.max(0, parseInt(v, 10) || 0) * mult);
}

app.get('/', async (req, res) => {
  try {
    res.send(appPage(buildAppData(req)));
  } catch (err) {
    res.status(500).send('数据库错误：' + e(err.message));
  }
});

app.get('/status', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store').json(await runStatusLogic());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/', async (req, res) => {
  const action = req.body.action || '';

  if (action === 'login') {
    const name = String(req.body.username || '').trim();
    const fails = Number(req.session.fails || 0);
    const lastFail = Number(req.session.lastFail || 0);
    if (fails >= 5 && Date.now() / 1000 - lastFail < 60) {
      const d0 = buildAppData(req); d0.loginError = '失败次数过多，请 1 分钟后再试';
      return res.send(appPage(d0));
    }
    let hash = '';
    try { hash = String(getDB().prepare('SELECT password_hash FROM pm_users WHERE username = ?').get(name)?.password_hash || ''); } catch { hash = ''; }
    if (hash && bcrypt.compareSync(String(req.body.password || ''), hash)) {
      req.session.user = name;
      delete req.session.fails; delete req.session.lastFail;
      sessions.delete(req.sid);
      const sid = crypto.randomBytes(24).toString('hex');
      sessions.set(sid, { user: name, csrf: crypto.randomBytes(16).toString('hex'), fails: 0, lastFail: 0 });
      res.setHeader('Set-Cookie', `pmsid=${sid}; Path=/; HttpOnly; SameSite=Lax`);
      return res.redirect('/');
    }
    req.session.fails = fails + 1;
    req.session.lastFail = Math.floor(Date.now() / 1000);
    await new Promise((r) => setTimeout(r, 500));
    const d1 = buildAppData(req); d1.loginError = '用户名或密码错误';
    return res.send(appPage(d1));
  }

  if (action === 'logout') {
    sessions.delete(req.sid);
    res.setHeader('Set-Cookie', `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
    return res.redirect('/');
  }

  if (!loggedIn(req)) return res.redirect('/');
  if (!verifyCsrf(req)) return;
  const b = req.body;
  const db = getDB();
  const render = (msg) => res.send(appPage(buildAppData(req, msg.error, msg.success)));
  const json = (obj) => res.json(obj);

  try {
    switch (action) {
      case 'add_client': {
        const url = String(b.url || '').trim();
        if (!/^(https?:\/\/)?[\w-]+(\.[\w-]+)+(:\d+)?([\/?#].*)?$/i.test(url)) return render({ error: '请输入有效的客户端网址（如 example.com，可不带 http:// 或 https:// 前缀）' });
        const mx = db.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS mx FROM pm_clients').get().mx;
        db.prepare('INSERT INTO pm_clients (id, name, country, url, created_at, sort_order) VALUES (?, ?, ?, ?, ?, ?)')
          .run(newId(), String(b.name || '').trim() || '未命名客户端', String(b.country || '').trim() || '其他', url, shDateTime(new Date()), mx);
        return res.redirect('/');
      }
      case 'edit_client': {
        const url = String(b.url || '').trim();
        if (!/^(https?:\/\/)?[\w-]+(\.[\w-]+)+(:\d+)?([\/?#].*)?$/i.test(url)) return render({ error: '请输入有效的客户端网址（如 example.com，可不带 http:// 或 https:// 前缀）' });
        const detectSec = parseDetectSec(b.detect_interval, b.detect_interval_unit);
        const rnMode = b.renew_mode === '2' ? 2 : 1;
        const expOn = b.expire_enabled ? 1 : 0;
        let expDate = '';
        if (expOn) {
          const ey = String(b.expire_y || '').trim(), em = String(b.expire_m || '').trim(), ed = String(b.expire_d || '').trim();
          if (/^\d{4}$/.test(ey) && /^\d{1,2}$/.test(em) && /^\d{1,2}$/.test(ed)) {
            const yy = Number(ey), mm = Number(em), dd = Number(ed);
            const dt = new Date(yy, mm - 1, dd);
            if (dt.getFullYear() === yy && dt.getMonth() === mm - 1 && dt.getDate() === dd) expDate = ey + '-' + String(mm).padStart(2, '0') + '-' + String(dd).padStart(2, '0');
          }
          if (expDate === '') return render({ error: '请选择有效的到期日期（年 / 月 / 日）' });
        }
        db.prepare('UPDATE pm_clients SET name = ?, country = ?, url = ?, ka_interval = ?, ka_ptero = ?, ka_ptero_url = ?, ka_ptero_key = ?, ka_ptero_sid = ?, renew_url = ?, rn_interval = ?, detect_interval = ?, renew_mode = ?, expire_enabled = ?, expire_date = ? WHERE id = ?')
          .run(
            String(b.name || '').trim() || '未命名客户端', String(b.country || '').trim() || '其他', url,
            parseMinutesAllowZero(b.ka_interval, b.ka_interval_unit),
            b.ka_ptero ? 1 : 0, String(b.ka_ptero_url || '').trim(), String(b.ka_ptero_key || '').trim(), String(b.ka_ptero_sid || '').trim(),
            String(b.renew_url || '').trim(),
            parseMinutesAllowZero(b.rn_interval, b.rn_interval_unit),
            detectSec, rnMode, expOn, expDate,
            String(b.id || '')
          );
        return res.redirect('/');
      }
      case 'delete_client': {
        const delId = String(b.id || '');
        db.prepare('DELETE FROM pm_clients WHERE id = ?').run(delId);
        db.prepare('DELETE FROM pm_group_members WHERE client_id = ?').run(delId);
        return res.redirect('/');
      }
      case 'create_group': {
        const name = String(b.name || '').trim() || '未命名分组';
        const gid = newId();
        const mx = db.prepare('SELECT COALESCE(MAX(sort_order), -1) + 1 AS mx FROM pm_groups').get().mx;
        db.prepare('INSERT INTO pm_groups (id, name, sort_order) VALUES (?, ?, ?)').run(gid, name, mx);
        insertMembers(db, gid, b.client_ids);
        return res.redirect('/');
      }
      case 'edit_group': {
        const gid = String(b.id || '');
        const name = String(b.name || '').trim() || '未命名分组';
        db.prepare('UPDATE pm_groups SET name = ? WHERE id = ?').run(name, gid);
        db.prepare('DELETE FROM pm_group_members WHERE group_id = ?').run(gid);
        insertMembers(db, gid, b.client_ids);
        return res.redirect('/');
      }
      case 'delete_group': {
        const gid = String(b.id || '');
        db.prepare('DELETE FROM pm_group_members WHERE group_id = ?').run(gid);
        db.prepare('DELETE FROM pm_groups WHERE id = ?').run(gid);
        return res.redirect('/');
      }
      case 'delete_group_with_clients': {
        const gid = String(b.id || '');
        const delIds = db.prepare('SELECT client_id FROM pm_group_members WHERE group_id = ?').all(gid).map((r) => r.client_id);
        db.prepare('DELETE FROM pm_group_members WHERE group_id = ?').run(gid);
        db.prepare('DELETE FROM pm_groups WHERE id = ?').run(gid);
        for (const cid of delIds) {
          db.prepare('DELETE FROM pm_group_members WHERE client_id = ?').run(cid);
          db.prepare('DELETE FROM pm_clients WHERE id = ?').run(cid);
        }
        return res.redirect('/');
      }
      case 'save_layout': {
        let payload;
        try { payload = JSON.parse(String(b.layout || '')); } catch { payload = null; }
        if (payload && typeof payload === 'object') {
          const order = Array.isArray(payload.order) ? payload.order.map(String) : [];
          const membership = payload.membership && typeof payload.membership === 'object' ? payload.membership : {};
          const groupOrder = Array.isArray(payload.groupOrder) ? payload.groupOrder.map(String) : [];
          db.exec('BEGIN');
          try {
            const st = db.prepare('UPDATE pm_clients SET sort_order = ? WHERE id = ?');
            order.forEach((oid, i) => st.run(i, oid));
            const del = db.prepare('DELETE FROM pm_group_members WHERE group_id = ?');
            const ins = db.prepare('INSERT INTO pm_group_members (group_id, client_id, sort_order) VALUES (?, ?, ?)');
            for (const [gid, ids] of Object.entries(membership)) {
              if (gid === '') continue;
              del.run(gid);
              (Array.isArray(ids) ? ids.map(String) : []).forEach((cid, i) => ins.run(gid, cid, i));
            }
            const gst = db.prepare('UPDATE pm_groups SET sort_order = ? WHERE id = ?');
            groupOrder.forEach((gid, i) => gst.run(i, gid));
            db.exec('COMMIT');
          } catch (err) {
            db.exec('ROLLBACK');
            throw err;
          }
        }
        return res.redirect('/');
      }
      case 'change_password': {
        const oldP = String(b.old_password || ''), newP = String(b.new_password || ''), confirmP = String(b.confirm_password || '');
        const row = db.prepare('SELECT password_hash FROM pm_users WHERE username = ?').get(req.session.user || 'admin');
        const currentHash = row ? String(row.password_hash) : '';
        if (!bcrypt.compareSync(oldP, currentHash)) return render({ error: '当前密码不正确' });
        if (newP.length < 6) return render({ error: '新密码至少需要 6 位' });
        if (newP !== confirmP) return render({ error: '两次输入的新密码不一致' });
        db.prepare('UPDATE pm_users SET password_hash = ? WHERE username = ?').run(bcrypt.hashSync(newP, 10), req.session.user || 'admin');
        return render({ success: '管理员密码修改成功' });
      }
      case 'save_notify': {
        const type = ['none', 'telegram', 'custom'].includes(b.notify_type) ? b.notify_type : 'none';
        db.prepare('INSERT INTO pm_notify (id, type, tg_token, tg_chat, custom_url, remind_expire) VALUES (1, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET type = excluded.type, tg_token = excluded.tg_token, tg_chat = excluded.tg_chat, custom_url = excluded.custom_url, remind_expire = excluded.remind_expire')
          .run(type, String(b.tg_token || '').trim(), String(b.tg_chat || '').trim(), String(b.custom_url || '').trim(), b.remind_expire ? 1 : 0);
        return res.redirect('/');
      }
      case 'test_notify': {
        const type = ['none', 'telegram', 'custom'].includes(b.notify_type) ? b.notify_type : 'none';
        const cfg = { type, tg_token: b.tg_token, tg_chat: b.tg_chat, custom_url: b.custom_url };
        const err = await sendNotification(cfg, 'Panel Manager 测试通知', '这是一条测试消息，收到即表示通知配置有效。');
        return err === null ? render({ success: '测试通知已发送，请检查手机或群聊是否收到' }) : render({ error: '测试通知发送失败：' + err });
      }
      case 'toggle_keepalive': {
        const id = String(b.id || '');
        let on = false;
        if (id !== '') {
          db.prepare('UPDATE pm_clients SET keepalive = 1 - keepalive WHERE id = ?').run(id);
          on = Number(db.prepare('SELECT keepalive FROM pm_clients WHERE id = ?').get(id)?.keepalive) === 1;
          db.prepare('INSERT INTO pm_keepalive_results (client_id, t, code) VALUES (?, 0, 0) ON CONFLICT(client_id) DO UPDATE SET t = 0, code = 0').run(id);
        }
        return json({ ok: true, on });
      }
      case 'toggle_renew': {
        const id = String(b.id || '');
        let on = false;
        if (id !== '') {
          db.prepare('UPDATE pm_clients SET renew = 1 - renew WHERE id = ?').run(id);
          on = Number(db.prepare('SELECT renew FROM pm_clients WHERE id = ?').get(id)?.renew) === 1;
          db.prepare('INSERT INTO pm_keepalive_results (client_id, t, code, renew_t, renew_code) VALUES (?, 0, 0, 0, 0) ON CONFLICT(client_id) DO UPDATE SET renew_t = 0, renew_code = 0').run(id);
        }
        return json({ ok: true, on });
      }
      case 'ka_manual': {
        const u = String(b.url || '').trim(), k = String(b.key || '').trim(), s = String(b.sid || '').trim();
        const signal = b.signal === 'stop' ? 'stop' : 'start';
        if (u === '' || k === '' || s === '' || !/^https?:\/\/.+/i.test(u)) return json({ ok: false, code: 0, powered: false, signal });
        let r;
        if (signal === 'stop') {
          r = await pteroApi('POST', `${u.replace(/\/+$/, '')}/api/client/servers/${encodeURIComponent(s)}/power`, k, { signal: 'stop' });
          r = { code: r.code, powered: true };
        } else {
          r = await pteroManualStart(u, k, s);
        }
        return json({ ok: r.code >= 200 && r.code < 300, code: r.code, powered: r.powered, signal });
      }
      default:
        return res.redirect('/');
    }
  } catch (err) {
    return res.status(500).send('数据库错误：' + e(err.message));
  }
});

function insertMembers(db, gid, clientIds) {
  const ids = (Array.isArray(clientIds) ? clientIds : [clientIds]).filter(Boolean).map(String);
  const ins = db.prepare('INSERT INTO pm_group_members (group_id, client_id, sort_order) VALUES (?, ?, ?)');
  ids.forEach((cid, i) => ins.run(gid, cid, i));
}

function buildAppData(req, error, success) {
  const db = getDB();
  const userRow = db.prepare('SELECT password_hash FROM pm_users WHERE username = ?').get('admin');
  const weakPassword = userRow ? bcrypt.compareSync('admin', String(userRow.password_hash)) : false;
  const notify = db.prepare('SELECT type, tg_token, tg_chat, custom_url, remind_expire FROM pm_notify WHERE id = 1').get() || { type: 'none', tg_token: '', tg_chat: '', custom_url: '', remind_expire: 0 };
  const clients = db.prepare('SELECT id, name, country, url, created_at, keepalive, ka_interval, ka_ptero, ka_ptero_url, ka_ptero_key, ka_ptero_sid, renew, renew_url, rn_interval, detect_interval, renew_mode, expire_enabled, expire_date FROM pm_clients ORDER BY sort_order, id').all();
  const groups = db.prepare('SELECT id, name FROM pm_groups ORDER BY sort_order, id').all();
  const memberMap = {};
  db.prepare('SELECT group_id, client_id FROM pm_group_members ORDER BY sort_order, client_id').all()
    .forEach((m) => { (memberMap[m.group_id] = memberMap[m.group_id] || []).push(m.client_id); });
  groups.forEach((g) => { g.client_ids = memberMap[g.id] || []; });
  return {
    csrf: req.session.csrf, user: req.session.user, weakPassword, error: error || '', success: success || '',
    clients, groups, notify,
    isGuest: !loggedIn(req),
  };
}

getDB();
app.listen(PORT, () => {
  console.log('Panel Manager (SQLite) 已启动: http://127.0.0.1:' + PORT);
  console.log('默认管理员：admin / admin（登录后请立即修改）。数据库文件：data/panel.db');
});

setInterval(() => {
  runStatusLogic().catch((err) => console.error('[后台检测]', err.message));
}, 30000);
console.log('后台常驻检测已开启：每 30 秒自动执行（保活 / 继期 / 状态），不受浏览器开关影响。');
