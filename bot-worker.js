// NEON DROP: Telegram-бот + вход через Telegram (Cloudflare Worker)
// Переменные: BOT_TOKEN (Secret), GAME_URL (Text), WEBHOOK_SECRET (Secret, необязательно),
//             FIREBASE_SA (Secret) — весь JSON сервисного аккаунта Firebase (для входа через Telegram)
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
};
const J = (o, s = 200) => new Response(JSON.stringify(o, null, 2), {
  status: s, headers: { "content-type": "application/json; charset=utf-8", ...CORS }
});
const enc = new TextEncoder();
const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
const same = (a, b) => { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; };
async function hmac(keyBytes, data) {
  const k = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", k, enc.encode(data));
}
// Проверка данных Mini App (initData)
async function verifyInitData(initData, botToken) {
  const p = new URLSearchParams(initData);
  const hash = p.get("hash");
  if (!hash) return null;
  p.delete("hash");
  const data = [...p.entries()].map(([k, v]) => k + "=" + v).sort().join("\n");
  const secret = await hmac(enc.encode("WebAppData"), botToken);
  const sig = hex(await hmac(secret, data));
  if (!same(sig, hash)) return null;
  if (Date.now() / 1000 - Number(p.get("auth_date")) > 86400) return null;
  try { return JSON.parse(p.get("user")); } catch (e) { return null; }
}
// Проверка данных кнопки «Войти через Telegram» на сайте
async function verifyWidget(u, botToken) {
  const { hash, ...rest } = u || {};
  if (!hash) return null;
  const data = Object.keys(rest).sort().map(k => k + "=" + rest[k]).join("\n");
  const secret = await crypto.subtle.digest("SHA-256", enc.encode(botToken));
  const sig = hex(await hmac(secret, data));
  if (!same(sig, String(hash))) return null;
  if (Date.now() / 1000 - Number(rest.auth_date) > 86400) return null;
  return rest;
}
const b64u = b => { let s = ""; const a = new Uint8Array(b); for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
// Токен для входа в Firebase (custom token)
async function firebaseToken(sa, uid, claims) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(enc.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const body = b64u(enc.encode(JSON.stringify({
    iss: sa.client_email, sub: sa.client_email,
    aud: "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit",
    iat: now, exp: now + 3600, uid, claims
  })));
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(head + "." + body));
  return head + "." + body + "." + b64u(sig);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    const api = (method, body) =>
      fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {})
      }).then(r => r.json()).catch(e => ({ ok: false, description: String(e) }));

    if (request.method === "GET" && url.pathname === "/config") {
      const me = env.BOT_TOKEN ? await api("getMe") : null;
      return J({ bot: me && me.ok ? me.result.username : null });
    }

    // Открой адрес воркера в браузере — увидишь, что настроено и что не так
    if (request.method === "GET") {
      const info = {
        BOT_TOKEN: env.BOT_TOKEN ? "задан" : "НЕ ЗАДАН",
        GAME_URL: env.GAME_URL || "НЕ ЗАДАН",
        WEBHOOK_SECRET: env.WEBHOOK_SECRET ? "задан (webhook нужно ставить с secret_token)" : "не задан",
        FIREBASE_SA: env.FIREBASE_SA ? "задан" : "НЕ ЗАДАН (вход через Telegram работать не будет)"
      };
      if (env.BOT_TOKEN) {
        const me = await api("getMe");
        info.token = me.ok ? "рабочий, бот @" + me.result.username : "НЕ ПОДХОДИТ: " + me.description;
        const wh = await api("getWebhookInfo");
        if (wh.ok) {
          info.webhook_url = wh.result.url || "пусто";
          info.last_error = wh.result.last_error_message || "нет";
          info.pending_updates = wh.result.pending_update_count;
        }
      }
      return J(info);
    }

    // Вход через Telegram: /auth (Mini App) и /login (кнопка на сайте)
    if (request.method === "POST" && (url.pathname === "/auth" || url.pathname === "/login")) {
      try {
        if (!env.BOT_TOKEN || !env.FIREBASE_SA) return J({ error: "сервер входа не настроен" }, 500);
        const body = await request.json();
        const user = url.pathname === "/auth"
          ? await verifyInitData(String(body.initData || ""), env.BOT_TOKEN)
          : await verifyWidget(body.user, env.BOT_TOKEN);
        if (!user || !user.id) return J({ error: "подпись Telegram не прошла" }, 401);
        const token = await firebaseToken(JSON.parse(env.FIREBASE_SA), "tg_" + user.id, { tg: true });
        return J({ token, user: { id: user.id, first_name: user.first_name || "", username: user.username || "" } });
      } catch (e) {
        return J({ error: String((e && e.message) || e) }, 500);
      }
    }

    // Сообщения от Telegram (webhook)
    if (env.WEBHOOK_SECRET &&
        request.headers.get("X-Telegram-Bot-Api-Secret-Token") !== env.WEBHOOK_SECRET) {
      return new Response("forbidden", { status: 403 });
    }
    let update;
    try { update = await request.json(); } catch (e) { return new Response("ok"); }

    const msg = update.message;
    if (msg && typeof msg.text === "string" && msg.text.startsWith("/start")) {
      const text = "Добро пожаловать в NEON DROP! 💚\nОткрывай кейсы, делай апгрейды и играй с друзьями.\nНажми кнопку, чтобы начать 👇";
      const r = await api("sendMessage", {
        chat_id: msg.chat.id,
        text,
        reply_markup: { inline_keyboard: [[{ text: "🎮 Играть", web_app: { url: env.GAME_URL } }]] }
      });
      if (!r.ok) {
        console.log("sendMessage failed:", JSON.stringify(r));
        await api("sendMessage", { chat_id: msg.chat.id, text: text + "\n" + (env.GAME_URL || "") });
      }
    }
    return new Response("ok");
  }
};
