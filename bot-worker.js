// Telegram-бот NEON DROP (Cloudflare Worker) с диагностикой.
// Переменные: BOT_TOKEN (Secret), GAME_URL (Text), WEBHOOK_SECRET (Secret, необязательно)
export default {
  async fetch(request, env) {
    const api = (method, body) =>
      fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {})
      }).then(r => r.json()).catch(e => ({ ok: false, description: String(e) }));

    // Открой адрес воркера в браузере — увидишь, что настроено и что не так
    if (request.method === "GET") {
      const info = {
        BOT_TOKEN: env.BOT_TOKEN ? "задан" : "НЕ ЗАДАН",
        GAME_URL: env.GAME_URL || "НЕ ЗАДАН",
        WEBHOOK_SECRET: env.WEBHOOK_SECRET ? "задан (webhook нужно ставить с secret_token)" : "не задан"
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
      return new Response(JSON.stringify(info, null, 2), {
        headers: { "content-type": "application/json; charset=utf-8" }
      });
    }

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
        // запасной вариант: обычная ссылка без кнопки
        await api("sendMessage", { chat_id: msg.chat.id, text: text + "\n" + (env.GAME_URL || "") });
      }
    }
    return new Response("ok");
  }
};
