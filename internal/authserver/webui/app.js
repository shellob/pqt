// app.js — клиентская часть демонстрационного UI.
// Без фреймворков: vanilla JS, чтобы страница открывалась без сборки и
// работала с любого статичного хоста, который отдаёт index.html.
(() => {
  "use strict";

  // showResult печатает форматированный JSON или строку в указанный <pre>.
  function showResult(elID, value) {
    const el = document.getElementById(elID);
    if (typeof value === "string") {
      el.textContent = value;
    } else {
      el.textContent = JSON.stringify(value, null, 2);
    }
  }

  // showError печатает короткое сообщение об ошибке (только err.message).
  function showError(elID, prefix, err) {
    const el = document.getElementById(elID);
    el.textContent = prefix + ": " + (err && err.message ? err.message : err);
  }

  // postForm отправляет application/x-www-form-urlencoded и парсит JSON-ответ.
  // Возвращает { ok, status, body }.
  async function postForm(path, params) {
    const body = new URLSearchParams(params).toString();
    const resp = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const text = await resp.text();
    let parsed = text;
    try {
      parsed = text ? JSON.parse(text) : "";
    } catch {
      // Оставляем сырой текст, если это не JSON.
    }
    return { ok: resp.ok, status: resp.status, body: parsed };
  }

  // base64UrlToBytes распаковывает base64url-строку в Uint8Array.
  function base64UrlToBytes(b64u) {
    const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "===".slice(0, (4 - (b64.length % 4)) % 4);
    const bin = atob(padded);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  // base64UrlToString — байты + декод UTF-8. Используется только для текстовых
  // полей токена (header, payload в JSON-режиме). Подпись — это сырые байты,
  // её через TextDecoder прогонять нельзя: невалидный UTF-8 превратится в
  // U+FFFD, и длина строки разъедется с реальной длиной подписи.
  function base64UrlToString(b64u) {
    return new TextDecoder("utf-8").decode(base64UrlToBytes(b64u));
  }

  // login — отправляет форму логина, кладёт refresh в форму обновления.
  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const params = { grant_type: "password", username: fd.get("username"), password: fd.get("password") };
    if (fd.get("scope")) params.scope = fd.get("scope");

    try {
      const { ok, body } = await postForm("/auth/token", params);
      showResult("login-result", body);
      if (ok && body && body.refresh_token) {
        document.querySelector('#refresh-form textarea[name="refresh_token"]').value = body.refresh_token;
        document.querySelector('#revoke-form textarea[name="token"]').value = body.access_token;
        document.querySelector('#decode-form textarea[name="token"]').value = body.access_token;
      }
    } catch (err) {
      showError("login-result", "ошибка", err);
    }
  });

  document.getElementById("refresh-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const { body } = await postForm("/auth/refresh", {
        grant_type: "refresh_token",
        refresh_token: fd.get("refresh_token"),
      });
      showResult("refresh-result", body);
    } catch (err) {
      showError("refresh-result", "ошибка", err);
    }
  });

  document.getElementById("revoke-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      const { ok, status } = await postForm("/auth/revoke", { token: fd.get("token") });
      showResult("revoke-result", ok ? `OK (${status})` : `ошибка ${status}`);
    } catch (err) {
      showError("revoke-result", "ошибка", err);
    }
  });

  document.getElementById("decode-form").addEventListener("submit", (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const token = String(fd.get("token") || "").trim();
    const parts = token.split(".");
    if (parts.length !== 3) {
      showResult("decode-result", "ожидаем три части через '.', получено " + parts.length);
      return;
    }
    try {
      const header = JSON.parse(base64UrlToString(parts[0]));
      // Payload может быть JSON или CBOR — пытаемся как JSON, иначе показываем hex.
      let payload;
      try {
        payload = JSON.parse(base64UrlToString(parts[1]));
      } catch {
        payload = "<не JSON; вероятно CBOR — используйте `pqt-cli decode`>";
      }
      const sigBytes = base64UrlToBytes(parts[2]).length;
      showResult("decode-result", { header, payload, signature_size_bytes: sigBytes });
    } catch (err) {
      showError("decode-result", "не удалось разобрать", err);
    }
  });

  document.getElementById("jwks-btn").addEventListener("click", async () => {
    try {
      const resp = await fetch("/.well-known/pq-jwks");
      showResult("jwks-result", await resp.json());
    } catch (err) {
      showError("jwks-result", "ошибка", err);
    }
  });

  document.getElementById("discovery-btn").addEventListener("click", async () => {
    try {
      const resp = await fetch("/.well-known/oauth-authorization-server");
      showResult("discovery-result", await resp.json());
    } catch (err) {
      showError("discovery-result", "ошибка", err);
    }
  });
})();
