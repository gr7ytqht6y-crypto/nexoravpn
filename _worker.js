async function hashToken(token) {
  const data = new TextEncoder().encode(token);

  const hashBuffer = await crypto.subtle.digest(
    "SHA-256",
    data
  );

  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type": "application/json; charset=UTF-8",
        "Cache-Control": "no-store",
        ...extraHeaders
      }
    }
  );
}

function getCookie(request, name) {
  const cookieHeader =
    request.headers.get("Cookie") || "";

  const match = cookieHeader.match(
    new RegExp(
      "(?:^|;\\s*)" +
        name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
        "=([^;]+)"
    )
  );

  return match ? match[1] : null;
}

async function getAdminUser(request, env) {
  const sessionToken =
    getCookie(request, "nexora_session");

  if (!sessionToken) {
    return null;
  }

  const tokenHash =
    await hashToken(sessionToken);

  const admin = await env.DB
    .prepare(
      `SELECT
         users.id,
         users.email
       FROM sessions
       INNER JOIN admins
         ON admins.user_id = sessions.user_id
       INNER JOIN users
         ON users.id = sessions.user_id
       WHERE sessions.token_hash = ?
         AND sessions.expires_at > ?
       LIMIT 1`
    )
    .bind(
      tokenHash,
      new Date().toISOString()
    )
    .first();

  return admin || null;
}

async function checkRateLimit(env, key) {
  try {
    const result =
      await env.RATE_LIMITER.limit({
        key
      });

    return result.success === true;
  } catch (error) {
    console.error(
      "RATE LIMIT ERROR:",
      error
    );

    // Fail closed:
    // если Rate Limiter сломан, защищённый endpoint
    // не должен продолжать принимать запросы.
    return false;
  }
}

async function sendResetEmail(
  env,
  email,
  resetUrl
) {
  if (!env.RESEND_API_KEY) {
    throw new Error(
      "RESEND_API_KEY is not configured"
    );
  }

  /*
   * Для production желательно создать
   * RESEND_FROM_EMAIL в Runtime Variables.
   *
   * Например:
   * NexoraVPN <no-reply@your-verified-domain.com>
   *
   * Пока переменной нет, используем официальный
   * тестовый sender Resend.
   */
  const from =
    env.RESEND_FROM_EMAIL ||
    "NexoraVPN <onboarding@resend.dev>";

  const response =
    await fetch(
      "https://api.resend.com/emails",
      {
        method: "POST",

        headers: {
          "Authorization":
            `Bearer ${env.RESEND_API_KEY}`,

          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          from,

          to: [email],

          subject:
            "NexoraVPN — восстановление пароля",

          html: `
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport"
        content="width=device-width,initial-scale=1">
  <title>NexoraVPN — восстановление пароля</title>
</head>

<body style="
  margin:0;
  padding:0;
  background:#0b0b0b;
  color:#ffffff;
  font-family:Arial,Helvetica,sans-serif;
">

  <div style="
    max-width:600px;
    margin:0 auto;
    padding:40px 20px;
  ">

    <div style="
      background:#151515;
      border:1px solid #2a2a2a;
      border-radius:16px;
      padding:32px;
    ">

      <h1 style="
        margin:0 0 20px;
        font-size:28px;
      ">
        NexoraVPN
      </h1>

      <h2 style="
        margin:0 0 16px;
        font-size:22px;
      ">
        Восстановление пароля
      </h2>

      <p style="
        color:#cccccc;
        line-height:1.6;
      ">
        Мы получили запрос на восстановление
        пароля для вашего аккаунта NexoraVPN.
      </p>

      <p style="
        color:#cccccc;
        line-height:1.6;
      ">
        Нажмите кнопку ниже, чтобы установить
        новый пароль.
      </p>

      <div style="
        margin:30px 0;
      ">

        <a
          href="${resetUrl}"
          style="
            display:inline-block;
            padding:14px 24px;
            background:#e00000;
            color:#ffffff;
            text-decoration:none;
            border-radius:10px;
            font-weight:bold;
          "
        >
          Восстановить пароль
        </a>

      </div>

      <p style="
        color:#999999;
        font-size:14px;
        line-height:1.5;
      ">
        Ссылка действует 15 минут.
        После использования она становится
        недействительной.
      </p>

      <p style="
        color:#777777;
        font-size:13px;
        line-height:1.5;
        word-break:break-all;
      ">
        Если кнопка не работает, откройте ссылку:
        <br><br>
        ${resetUrl}
      </p>

      <hr style="
        border:none;
        border-top:1px solid #2a2a2a;
        margin:30px 0;
      ">

      <p style="
        color:#666666;
        font-size:12px;
      ">
        Если вы не запрашивали восстановление
        пароля, просто проигнорируйте это письмо.
      </p>

    </div>

  </div>

</body>
</html>
          `,

          tags: [
            {
              name: "category",
              value: "password_reset"
            }
          ]
        })
      }
    );

  const responseText =
    await response.text();

  if (!response.ok) {
    console.error(
      "RESEND ERROR:",
      response.status,
      responseText
    );

    throw new Error(
      "Resend email sending failed"
    );
  }

  let responseData = null;

  try {
    responseData =
      JSON.parse(responseText);
  } catch {
    responseData = null;
  }

  return responseData;
}

export default {
  async fetch(request, env) {
    const url =
      new URL(request.url);

    // ==================================================
    // ВОССТАНОВЛЕНИЕ ПАРОЛЯ — REQUEST
    // ==================================================

    if (
      url.pathname === "/api/forgot-password"
    ) {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            error: "Method not allowed"
          },
          405,
          {
            "Allow": "POST"
          }
        );
      }

      try {
        const ip =
          request.headers.get(
            "CF-Connecting-IP"
          ) || "unknown";

        const rateAllowed =
          await checkRateLimit(
            env,
            "forgot-password:" + ip
          );

        if (!rateAllowed) {
          return json(
            {
              success: false,
              error:
                "Слишком много попыток. Попробуйте позже."
            },
            429
          );
        }

        const contentType =
          request.headers.get(
            "content-type"
          ) || "";

        if (
          !contentType
            .toLowerCase()
            .includes("application/json")
        ) {
          return json(
            {
              success: false,
              error:
                "Неверный формат запроса"
            },
            415
          );
        }

        const body =
          await request.json();

        const email =
          String(body?.email || "")
            .trim()
            .toLowerCase();

        if (!email) {
          return json(
            {
              success: false,
              error:
                "Email обязателен"
            },
            400
          );
        }

        if (
          email.length < 5 ||
          email.length > 254
        ) {
          return json(
            {
              success: false,
              error:
                "Некорректный email"
            },
            400
          );
        }

        const emailRegex =
          /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

        if (!emailRegex.test(email)) {
          return json(
            {
              success: false,
              error:
                "Некорректный email"
            },
            400
          );
        }

        const user =
          await env.DB
            .prepare(
              `SELECT
                 id,
                 email
               FROM users
               WHERE email = ?
               LIMIT 1`
            )
            .bind(email)
            .first();

        /*
         * Не раскрываем существование аккаунта.
         */
        if (!user) {
          return json({
            success: true,
            message:
              "Если аккаунт существует, инструкции будут отправлены на email."
          });
        }

        const token =
          generateToken();

        const tokenHash =
          await hashToken(token);

        const expiresAt =
          new Date(
            Date.now() +
              15 * 60 * 1000
          ).toISOString();

        /*
         * Старые активные ссылки
         * пользователя становятся недействительными.
         */
        await env.DB
          .prepare(
            `UPDATE password_resets
             SET used = 1
             WHERE user_id = ?
               AND used = 0`
          )
          .bind(user.id)
          .run();

        await env.DB
          .prepare(
            `INSERT INTO password_resets
             (
               user_id,
               token_hash,
               expires_at,
               used
             )
             VALUES (?, ?, ?, 0)`
          )
          .bind(
            user.id,
            tokenHash,
            expiresAt
          )
          .run();

        const resetUrl =
          `${url.origin}/reset-password.html?token=` +
          encodeURIComponent(token);

        /*
         * Отправляем письмо через Resend.
         */
        try {
          await sendResetEmail(
            env,
            user.email,
            resetUrl
          );
        } catch (emailError) {
          console.error(
            "PASSWORD RESET EMAIL ERROR:",
            emailError
          );

          /*
           * Если письмо не отправилось,
           * созданную ссылку сразу инвалидируем.
           */
          await env.DB
            .prepare(
              `UPDATE password_resets
               SET used = 1
               WHERE token_hash = ?
                 AND used = 0`
            )
            .bind(tokenHash)
            .run();

          return json(
            {
              success: false,
              error:
                "Не удалось отправить письмо. Попробуйте позже."
            },
            500
          );
        }

        /*
         * Никогда не возвращаем resetUrl
         * обычному пользователю.
         */
        return json({
          success: true,
          message:
            "Если аккаунт существует, инструкции будут отправлены на email."
        });

      } catch (error) {
        console.error(
          "FORGOT PASSWORD ERROR:",
          error
        );

        return json(
          {
            success: false,
            error:
              "Ошибка сервера"
          },
          500
        );
      }
    }

    // ==================================================
    // ТЕСТОВАЯ RESET-ССЫЛКА — ТОЛЬКО АДМИН
    // ==================================================

    if (
      url.pathname === "/api/test-reset-link"
    ) {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            error:
              "Method not allowed"
          },
          405
        );
      }

      try {
        const admin =
          await getAdminUser(
            request,
            env
          );

        if (!admin) {
          return json(
            {
              success: false,
              error:
                "Доступ запрещён"
            },
            403
          );
        }

        const body =
          await request.json();

        const email =
          String(body?.email || "")
            .trim()
            .toLowerCase();

        if (!email) {
          return json(
            {
              success: false,
              error:
                "Email обязателен"
            },
            400
          );
        }

        const user =
          await env.DB
            .prepare(
              `SELECT
                 id,
                 email
               FROM users
               WHERE email = ?
               LIMIT 1`
            )
            .bind(email)
            .first();

        if (!user) {
          return json(
            {
              success: false,
              error:
                "Пользователь не найден"
            },
            404
          );
        }

        const token =
          generateToken();

        const tokenHash =
          await hashToken(token);

        const expiresAt =
          new Date(
            Date.now() +
              15 * 60 * 1000
          ).toISOString();

        await env.DB
          .prepare(
            `UPDATE password_resets
             SET used = 1
             WHERE user_id = ?
               AND used = 0`
          )
          .bind(user.id)
          .run();

        await env.DB
          .prepare(
            `INSERT INTO password_resets
             (
               user_id,
               token_hash,
               expires_at,
               used
             )
             VALUES (?, ?, ?, 0)`
          )
          .bind(
            user.id,
            tokenHash,
            expiresAt
          )
          .run();

        const resetUrl =
          `${url.origin}/reset-password.html?token=` +
          encodeURIComponent(token);

        return json({
          success: true,
          reset_url: resetUrl,
          expires_at: expiresAt
        });

      } catch (error) {
        console.error(
          "TEST RESET LINK ERROR:",
          error
        );

        return json(
          {
            success: false,
            error:
              "Ошибка сервера"
          },
          500
        );
      }
    }

    // ==================================================
    // СБРОС ПАРОЛЯ
    // ==================================================

    if (
      url.pathname === "/api/reset-password"
    ) {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            error:
              "Method not allowed"
          },
          405
        );
      }

      try {
        let body = {};

        try {
          body =
            await request.json();
        } catch {
          body = {};
        }

        const bodyToken =
          typeof body?.token === "string"
            ? body.token.trim()
            : "";

        const urlToken =
          url.searchParams.get(
            "token"
          ) || "";

        const token =
          bodyToken ||
          urlToken.trim();

        const password =
          typeof body?.password === "string"
            ? body.password
            : "";

        if (
          !token ||
          !password
        ) {
          return json(
            {
              success: false,
              error:
                "Недостаточно данных"
            },
            400
          );
        }

        /*
         * generateToken() создаёт 32 байта =
         * 64 hex-символа.
         */
        if (
          !/^[a-f0-9]{64}$/i.test(
            token
          )
        ) {
          return json(
            {
              success: false,
              error:
                "Недействительная ссылка восстановления"
            },
            400
          );
        }

        if (
          password.length < 8
        ) {
          return json(
            {
              success: false,
              error:
                "Пароль должен содержать минимум 8 символов"
            },
            400
          );
        }

        if (
          password.length > 128
        ) {
          return json(
            {
              success: false,
              error:
                "Пароль не должен содержать более 128 символов"
            },
            400
          );
        }

        const ip =
          request.headers.get(
            "CF-Connecting-IP"
          ) || "unknown";

        const rateAllowed =
          await checkRateLimit(
            env,
            "reset-password:" + ip
          );

        if (!rateAllowed) {
          return json(
            {
              success: false,
              error:
                "Слишком много попыток. Попробуйте позже."
            },
            429
          );
        }

        const tokenHash =
          await hashToken(token);

        const reset =
          await env.DB
            .prepare(
              `SELECT
                 id,
                 user_id,
                 token_hash,
                 expires_at,
                 used
               FROM password_resets
               WHERE token_hash = ?
               LIMIT 1`
            )
            .bind(tokenHash)
            .first();

        if (!reset) {
          console.error(
            "RESET TOKEN MISMATCH:",
            JSON.stringify({
              received_token_length:
                token.length,

              received_hash_length:
                tokenHash.length
            })
          );

          return json(
            {
              success: false,
              error:
                "Недействительная ссылка восстановления"
            },
            400
          );
        }

        const resetUsed =
          Number(reset.used) === 1;

        if (resetUsed) {
          return json(
            {
              success: false,
              error:
                "Эта ссылка уже использована"
            },
            400
          );
        }

        if (!reset.expires_at) {
          return json(
            {
              success: false,
              error:
                "Недействительная ссылка восстановления"
            },
            400
          );
        }

        const expiresAt =
          new Date(
            reset.expires_at
          ).getTime();

        if (
          !Number.isFinite(
            expiresAt
          ) ||
          expiresAt <= Date.now()
        ) {
          return json(
            {
              success: false,
              error:
                "Срок действия ссылки истёк"
            },
            400
          );
        }

        const user =
          await env.DB
            .prepare(
              `SELECT
                 id
               FROM users
               WHERE id = ?
               LIMIT 1`
            )
            .bind(reset.user_id)
            .first();

        if (!user) {
          return json(
            {
              success: false,
              error:
                "Пользователь не найден"
            },
            404
          );
        }

        /*
         * Сохраняем совместимость
         * с существующей системой паролей.
         */
        const passwordHash =
          await hashToken(password);

        await env.DB
          .prepare(
            `UPDATE users
             SET password_hash = ?
             WHERE id = ?`
          )
          .bind(
            passwordHash,
            reset.user_id
          )
          .run();

        /*
         * Используем только конкретную ссылку.
         */
        await env.DB
          .prepare(
            `UPDATE password_resets
             SET used = 1
             WHERE id = ?
               AND used = 0`
          )
          .bind(reset.id)
          .run();

        /*
         * После смены пароля все старые
         * сессии пользователя удаляются.
         */
        await env.DB
          .prepare(
            `DELETE FROM sessions
             WHERE user_id = ?`
          )
          .bind(reset.user_id)
          .run();

        console.log(
          "RESET PASSWORD SUCCESS: user_id=" +
            String(reset.user_id)
        );

        return json({
          success: true,
          message:
            "Пароль успешно изменён"
        });

      } catch (error) {
        console.error(
          "RESET PASSWORD ERROR:",
          error
        );

        return json(
          {
            success: false,
            error:
              "Не удалось изменить пароль"
          },
          500
        );
      }
    }

    // ==================================================
    // АДМИН — СПИСОК ПОЛЬЗОВАТЕЛЕЙ
    // ==================================================

    if (
      url.pathname ===
      "/api/admin/users"
    ) {
      if (request.method !== "GET") {
        return json(
          {
            success: false,
            error:
              "Method not allowed"
          },
          405
        );
      }

      try {
        const admin =
          await getAdminUser(
            request,
            env
          );

        if (!admin) {
          return json(
            {
              success: false,
              error:
                "Доступ запрещён"
            },
            403
          );
        }

        const users =
          await env.DB
            .prepare(
              `SELECT
                 id,
                 email,
                 created_at,
                 subscription_status,
                 subscription_plan,
                 subscription_expires_at
               FROM users
               ORDER BY id DESC`
            )
            .all();

        return json({
          success: true,
          users:
            users.results || []
        });

      } catch (error) {
        console.error(
          "ADMIN USERS ERROR:",
          error
        );

        return json(
          {
            success: false,
            error:
              "Не удалось получить пользователей"
          },
          500
        );
      }
    }

    // ==================================================
    // ВЫХОД
    // ==================================================

    if (
      url.pathname ===
      "/api/logout"
    ) {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            error:
              "Method not allowed"
          },
          405
        );
      }

      try {
        const sessionToken =
          getCookie(
            request,
            "nexora_session"
          );

        if (sessionToken) {
          const tokenHash =
            await hashToken(
              sessionToken
            );

          await env.DB
            .prepare(
              `DELETE FROM sessions
               WHERE token_hash = ?`
            )
            .bind(tokenHash)
            .run();
        }

        return json(
          {
            success: true,
            message:
              "Вы вышли из аккаунта"
          },
          200,
          {
            "Set-Cookie":
              "nexora_session=; " +
              "HttpOnly; Secure; " +
              "SameSite=Lax; " +
              "Path=/; Max-Age=0"
          }
        );

      } catch (error) {
        console.error(
          "LOGOUT ERROR:",
          error
        );

        return json(
          {
            success: false,
            error:
              "Не удалось выполнить выход"
          },
          500
        );
      }
    }

    // ==================================================
    // ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ
    // ==================================================

    if (
      url.pathname ===
      "/api/me"
    ) {
      if (request.method !== "GET") {
        return json(
          {
            success: false,
            error:
              "Method not allowed"
          },
          405
        );
      }

      try {
        const sessionToken =
          getCookie(
            request,
            "nexora_session"
          );

        if (!sessionToken) {
          return json(
            {
              success: false,
              error:
                "Не авторизован"
            },
            401
          );
        }

        const tokenHash =
          await hashToken(
            sessionToken
          );

        const session =
          await env.DB
            .prepare(
              `SELECT
                 sessions.user_id,
                 sessions.expires_at,
                 users.email,
                 users.subscription_status,
                 users.subscription_plan,
                 users.subscription_expires_at
               FROM sessions
               INNER JOIN users
                 ON users.id =
                    sessions.user_id
               WHERE sessions.token_hash = ?
               LIMIT 1`
            )
            .bind(tokenHash)
            .first();

        if (!session) {
          return json(
            {
              success: false,
              error:
                "Сессия недействительна"
            },
            401
          );
        }

        if (
          new Date(
            session.expires_at
          ).getTime() <= Date.now()
        ) {
          await env.DB
            .prepare(
              `DELETE FROM sessions
               WHERE token_hash = ?`
            )
            .bind(tokenHash)
            .run();

          return json(
            {
              success: false,
              error:
                "Сессия истекла"
            },
            401,
            {
              "Set-Cookie":
                "nexora_session=; " +
                "HttpOnly; Secure; " +
                "SameSite=Lax; " +
                "Path=/; Max-Age=0"
            }
          );
        }

        return json({
          success: true,

          user: {
            id:
              session.user_id,

            email:
              session.email,

            subscription_status:
              session.subscription_status,

            subscription_plan:
              session.subscription_plan,

            subscription_expires_at:
              session.subscription_expires_at
          }
        });

      } catch (error) {
        console.error(
          "ME ERROR:",
          error
        );

        return json(
          {
            success: false,
            error:
              "Не удалось проверить сессию"
          },
          500
        );
      }
    }

    // ==================================================
    // ВХОД
    // ==================================================

    if (
      url.pathname ===
      "/api/login"
    ) {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            error:
              "Method not allowed"
          },
          405
        );
      }

      try {
        const ip =
          request.headers.get(
            "CF-Connecting-IP"
          ) || "unknown";

        const rateAllowed =
          await checkRateLimit(
            env,
            "login:" + ip
          );

        if (!rateAllowed) {
          return json(
            {
              success: false,
              error:
                "Слишком много попыток. Попробуйте позже."
            },
            429
          );
        }

        const data =
          await request.json();

        if (
          !data ||
          typeof data.email !==
            "string" ||
          typeof data.password !==
            "string"
        ) {
          return json(
            {
              success: false,
              error:
                "Email и пароль обязательны"
            },
            400
          );
        }

        const email =
          data.email
            .trim()
            .toLowerCase();

        const password =
          data.password;

        const user =
          await env.DB
            .prepare(
              `SELECT
                 id,
                 email,
                 password_hash
               FROM users
               WHERE email = ?
               LIMIT 1`
            )
            .bind(email)
            .first();

        if (!user) {
          return json(
            {
              success: false,
              error:
                "Неверный email или пароль"
            },
            401
          );
        }

        const passwordHash =
          await hashToken(
            password
          );

        if (
          passwordHash !==
          user.password_hash
        ) {
          return json(
            {
              success: false,
              error:
                "Неверный email или пароль"
            },
            401
          );
        }

        const sessionToken =
          generateToken();

        const tokenHash =
          await hashToken(
            sessionToken
          );

        const expiresAt =
          new Date(
            Date.now() +
              30 *
                24 *
                60 *
                60 *
                1000
          ).toISOString();

        await env.DB
          .prepare(
            `INSERT INTO sessions
             (
               user_id,
               token_hash,
               expires_at
             )
             VALUES (?, ?, ?)`
          )
          .bind(
            user.id,
            tokenHash,
            expiresAt
          )
          .run();

        return json(
          {
            success: true,
            message:
              "Вход выполнен успешно"
          },
          200,
          {
            "Set-Cookie":
              `nexora_session=${sessionToken}; ` +
              "HttpOnly; Secure; " +
              "SameSite=Lax; " +
              "Path=/; Max-Age=2592000"
          }
        );

      } catch (error) {
        console.error(
          "LOGIN ERROR:",
          error
        );

        return json(
          {
            success: false,
            error:
              "Не удалось выполнить вход"
          },
          500
        );
      }
    }

    // ==================================================
    // РЕГИСТРАЦИЯ
    // ==================================================

    if (
      url.pathname ===
      "/api/register"
    ) {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            error:
              "Method not allowed"
          },
          405
        );
      }

      try {
        const ip =
          request.headers.get(
            "CF-Connecting-IP"
          ) || "unknown";

        const rateAllowed =
          await checkRateLimit(
            env,
            "register:" + ip
          );

        if (!rateAllowed) {
          return json(
            {
              success: false,
              error:
                "Слишком много попыток. Попробуйте позже."
            },
            429
          );
        }

        const contentType =
          request.headers.get(
            "content-type"
          ) || "";

        if (
          !contentType
            .toLowerCase()
            .includes(
              "application/json"
            )
        ) {
          return json(
            {
              success: false,
              error:
                "Неверный формат запроса"
            },
            415
          );
        }

        const contentLength =
          Number(
            request.headers.get(
              "content-length"
            ) || "0"
          );

        if (
          contentLength > 4096
        ) {
          return json(
            {
              success: false,
              error:
                "Слишком большой запрос"
            },
            413
          );
        }

        const data =
          await request.json();

        if (
          !data ||
          typeof data.email !==
            "string" ||
          typeof data.password !==
            "string"
        ) {
          return json(
            {
              success: false,
              error:
                "Email и пароль обязательны"
            },
            400
          );
        }

        const email =
          data.email
            .trim()
            .toLowerCase();

        const password =
          data.password;

        if (
          email.length < 5 ||
          email.length > 254
        ) {
          return json(
            {
              success: false,
              error:
                "Некорректный email"
            },
            400
          );
        }

        const emailRegex =
          /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

        if (
          !emailRegex.test(
            email
          )
        ) {
          return json(
            {
              success: false,
              error:
                "Некорректный email"
            },
            400
          );
        }

        if (
          password.length < 8 ||
          password.length > 128
        ) {
          return json(
            {
              success: false,
              error:
                "Пароль должен содержать от 8 до 128 символов"
            },
            400
          );
        }

        const existingUser =
          await env.DB
            .prepare(
              `SELECT id
               FROM users
               WHERE email = ?
               LIMIT 1`
            )
            .bind(email)
            .first();

        if (existingUser) {
          return json(
            {
              success: false,
              error:
                "Этот email уже зарегистрирован"
            },
            409
          );
        }

        const passwordHash =
          await hashToken(
            password
          );

        await env.DB
          .prepare(
            `INSERT INTO users
             (
               email,
               password_hash
             )
             VALUES (?, ?)`
          )
          .bind(
            email,
            passwordHash
          )
          .run();

        return json(
          {
            success: true,
            message:
              "Регистрация успешна!"
          },
          201
        );

      } catch (error) {
        console.error(
          "REGISTER ERROR:",
          error
        );

        if (
          String(error).includes(
            "UNIQUE"
          )
        ) {
          return json(
            {
              success: false,
              error:
                "Этот email уже зарегистрирован"
            },
            409
          );
        }

        return json(
          {
            success: false,
            error:
              "Не удалось зарегистрировать пользователя"
          },
          500
        );
      }
    }

    // ==================================================
    // EARLY ACCESS
    // ==================================================

    if (
      url.pathname ===
      "/api/early-access"
    ) {
      if (request.method !== "POST") {
        return json(
          {
            success: false,
            error:
              "Method not allowed"
          },
          405
        );
      }

      try {
        const ip =
          request.headers.get(
            "CF-Connecting-IP"
          ) || "unknown";

        const rateAllowed =
          await checkRateLimit(
            env,
            "early-access:" + ip
          );

        if (!rateAllowed) {
          return json(
            {
              success: false,
              error:
                "Слишком много запросов. Попробуйте позже."
            },
            429
          );
        }

        const contentType =
          request.headers.get(
            "content-type"
          ) || "";

        if (
          !contentType
            .toLowerCase()
            .includes(
              "application/json"
            )
        ) {
          return json(
            {
              success: false,
              error:
                "Неверный формат запроса"
            },
            415
          );
        }

        const contentLength =
          Number(
            request.headers.get(
              "content-length"
            ) || "0"
          );

        if (
          contentLength > 2048
        ) {
          return json(
            {
              success: false,
              error:
                "Слишком большой запрос"
            },
            413
          );
        }

        const data =
          await request.json();

        if (
          !data ||
          typeof data.email !==
            "string"
        ) {
          return json(
            {
              success: false,
              error:
                "Email не указан"
            },
            400
          );
        }

        const email =
          data.email
            .trim()
            .toLowerCase();

        if (
          email.length < 5 ||
          email.length > 254
        ) {
          return json(
            {
              success: false,
              error:
                "Некорректный email"
            },
            400
          );
        }

        const emailRegex =
          /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

        if (
          !emailRegex.test(
            email
          )
        ) {
          return json(
            {
              success: false,
              error:
                "Некорректный email"
            },
            400
          );
        }

        await env.DB
          .prepare(
            `INSERT INTO early_access
             (email)
             VALUES (?)`
          )
          .bind(email)
          .run();

        return json({
          success: true,
          message:
            "Вы добавлены в список раннего доступа!"
        });

      } catch (error) {
        console.error(
          "EARLY ACCESS ERROR:",
          error
        );

        if (
          String(error).includes(
            "UNIQUE"
          )
        ) {
          return json(
            {
              success: false,
              error:
                "Этот email уже зарегистрирован"
            },
            409
          );
        }

        return json(
          {
            success: false,
            error:
              "Не удалось обработать запрос"
          },
          500
        );
      }
    }

    // ==================================================
    // ЗАЩИТА ЛИЧНОГО КАБИНЕТА
    // ==================================================

    if (
      url.pathname ===
      "/account.html"
    ) {
      try {
        const sessionToken =
          getCookie(
            request,
            "nexora_session"
          );

        if (!sessionToken) {
          return Response.redirect(
            new URL(
              "/login.html",
              request.url
            ),
            302
          );
        }

        const tokenHash =
          await hashToken(
            sessionToken
          );

        const session =
          await env.DB
            .prepare(
              `SELECT
                 expires_at
               FROM sessions
               WHERE token_hash = ?
               LIMIT 1`
            )
            .bind(tokenHash)
            .first();

        if (!session) {
          return Response.redirect(
            new URL(
              "/login.html",
              request.url
            ),
            302
          );
        }

        if (
          new Date(
            session.expires_at
          ).getTime() <=
          Date.now()
        ) {
          await env.DB
            .prepare(
              `DELETE FROM sessions
               WHERE token_hash = ?`
            )
            .bind(tokenHash)
            .run();

          return Response.redirect(
            new URL(
              "/login.html",
              request.url
            ),
            302
          );
        }

      } catch (error) {
        console.error(
          "ACCOUNT PROTECTION ERROR:",
          error
        );

        return Response.redirect(
          new URL(
            "/login.html",
            request.url
          ),
          302
        );
      }
    }

    // ==================================================
    // САЙТ / ASSETS
    // ==================================================

    return env.ASSETS.fetch(
      request
    );
  }
};
