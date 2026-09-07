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
  const bytes = crypto.getRandomValues(new Uint8Array(32));

  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie");

  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...value] = cookie.trim().split("=");

    if (key === name) {
      return value.join("=");
    }
  }

  return null;
}

async function getAdminUser(env, request) {
  const sessionId = getCookie(request, "session");

  if (!sessionId) return null;

  const user = await env.DB.prepare(`
    SELECT
      users.id,
      users.email,
      users.created_at
    FROM sessions
    JOIN users
      ON users.id = sessions.user_id
    JOIN admins
      ON admins.user_id = users.id
    WHERE sessions.id = ?
      AND sessions.expires_at > datetime('now')
  `)
    .bind(sessionId)
    .first();

  return user || null;
}

async function checkRateLimit(env, request, key, limit = 10) {
  if (!env.RATE_LIMITER) {
    return true;
  }

  try {
    const ip =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For") ||
      "unknown";

    const result = await env.RATE_LIMITER.limit({
      key: `${key}:${ip}`
    });

    return result.success;
  } catch (error) {
    console.error("Rate limiter error:", error);
    return true;
  }
}

/*
 * BREVO
 */

async function sendPasswordResetEmail(
  env,
  recipientEmail,
  resetUrl
) {
  if (!env.BREVO_API_KEY) {
    console.error(
      "BREVO_API_KEY is missing from Worker secrets"
    );

    return {
      success: false,
      error: "BREVO_API_KEY is not configured"
    };
  }

  const payload = {
    sender: {
      name: "NexoraVPN",
      email: "nexoravpn7@gmail.com"
    },

    to: [
      {
        email: recipientEmail
      }
    ],

    subject: "NexoraVPN — восстановление пароля",

    htmlContent: `
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NexoraVPN — восстановление пароля</title>
</head>

<body style="
  margin:0;
  padding:0;
  background:#f4f4f4;
  font-family:Arial,Helvetica,sans-serif;
">

  <div style="
    max-width:600px;
    margin:40px auto;
    background:#ffffff;
    border-radius:12px;
    padding:32px;
    box-sizing:border-box;
  ">

    <h1 style="
      margin:0 0 10px 0;
      color:#111111;
      font-size:28px;
    ">
      NexoraVPN
    </h1>

    <h2 style="
      margin:0 0 20px 0;
      color:#222222;
      font-size:22px;
    ">
      Восстановление пароля
    </h2>

    <p style="
      color:#444444;
      font-size:16px;
      line-height:1.6;
    ">
      Мы получили запрос на восстановление пароля
      вашего аккаунта NexoraVPN.
    </p>

    <p style="
      color:#444444;
      font-size:16px;
      line-height:1.6;
    ">
      Нажмите кнопку ниже, чтобы установить новый пароль:
    </p>

    <div style="
      text-align:center;
      margin:30px 0;
    ">

      <a
        href="${resetUrl}"
        style="
          display:inline-block;
          background:#39ff14;
          color:#0b0f0d;
          text-decoration:none;
          padding:14px 26px;
          border-radius:8px;
          font-size:16px;
          font-weight:bold;
        "
      >
        Восстановить пароль
      </a>

    </div>

    <p style="
      color:#666666;
      font-size:14px;
      line-height:1.5;
    ">
      Ссылка действительна в течение 15 минут.
    </p>

    <p style="
      color:#666666;
      font-size:14px;
      line-height:1.5;
    ">
      Если вы не запрашивали восстановление пароля,
      просто проигнорируйте это письмо.
    </p>

    <hr style="
      border:none;
      border-top:1px solid #eeeeee;
      margin:30px 0;
    ">

    <p style="
      color:#999999;
      font-size:12px;
    ">
      NexoraVPN — Интернет. Без границ.
    </p>

  </div>

</body>
</html>
    `,

    textContent:
`NexoraVPN — восстановление пароля

Мы получили запрос на восстановление пароля вашего аккаунта NexoraVPN.

Перейдите по ссылке, чтобы установить новый пароль:

${resetUrl}

Ссылка действительна в течение 15 минут.

Если вы не запрашивали восстановление пароля, просто проигнорируйте это письмо.

NexoraVPN — Интернет. Без границ.`
  };

  try {
    const response = await fetch(
      "https://api.brevo.com/v3/smtp/email",
      {
        method: "POST",

        headers: {
          "accept": "application/json",
          "api-key": env.BREVO_API_KEY,
          "content-type": "application/json"
        },

        body: JSON.stringify(payload)
      }
    );

    const responseText = await response.text();

    if (!response.ok) {
      console.error(
        "BREVO ERROR",
        JSON.stringify({
          status: response.status,
          response: responseText
        })
      );

      return {
        success: false,
        error: responseText,
        status: response.status
      };
    }

    let result = {};

    try {
      result = JSON.parse(responseText);
    } catch {
      result = {};
    }

    console.log(
      "BREVO EMAIL SENT",
      JSON.stringify({
        recipient: recipientEmail,
        messageId: result.messageId || null
      })
    );

    return {
      success: true,
      messageId: result.messageId || null
    };

  } catch (error) {
    console.error(
      "BREVO FETCH ERROR",
      error
    );

    return {
      success: false,
      error: String(error)
    };
  }
}

/*
 * MAIN WORKER
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    /*
     * FORGOT PASSWORD
     */

    if (
      url.pathname === "/api/forgot-password" &&
      request.method === "POST"
    ) {
      const allowed = await checkRateLimit(
        env,
        request,
        "forgot-password",
        5
      );

      if (!allowed) {
        return json(
          {
            success: false,
            error: "Слишком много запросов"
          },
          429
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            success: false,
            error: "Некорректный JSON"
          },
          400
        );
      }

      const email =
        typeof body.email === "string"
          ? body.email.trim().toLowerCase()
          : "";

      if (!email || !email.includes("@")) {
        return json(
          {
            success: false,
            error: "Введите корректный email"
          },
          400
        );
      }

      let user;

      try {
        user = await env.DB.prepare(`
          SELECT id, email
          FROM users
          WHERE email = ?
        `)
          .bind(email)
          .first();
      } catch (error) {
        console.error(
          "FORGOT PASSWORD DB ERROR",
          error
        );

        return json(
          {
            success: false,
            error: "Ошибка базы данных"
          },
          500
        );
      }

      /*
       * Не раскрываем существование email.
       */

      if (!user) {
        return json({
          success: true,
          message:
            "Если аккаунт существует, инструкция по восстановлению будет отправлена."
        });
      }

      /*
       * Делаем старые токены недействительными.
       */

      try {
        await env.DB.prepare(`
          UPDATE password_resets
          SET used = 1
          WHERE user_id = ?
            AND used = 0
        `)
          .bind(user.id)
          .run();
      } catch (error) {
        console.error(
          "OLD RESET TOKENS DB ERROR",
          error
        );

        return json(
          {
            success: false,
            error: "Ошибка базы данных"
          },
          500
        );
      }

      /*
       * Создаём новый токен.
       */

      const token = generateToken();
      const tokenHash = await hashToken(token);

      try {
        await env.DB.prepare(`
          INSERT INTO password_resets (
            user_id,
            token_hash,
            expires_at,
            used
          )
          VALUES (
            ?,
            ?,
            datetime('now', '+15 minutes'),
            0
          )
        `)
          .bind(
            user.id,
            tokenHash
          )
          .run();
      } catch (error) {
        console.error(
          "RESET TOKEN INSERT ERROR",
          error
        );

        return json(
          {
            success: false,
            error: "Не удалось создать токен"
          },
          500
        );
      }

      /*
       * Ссылка восстановления.
       *
       * Используем /reset-password
       * вместо /reset-password.html
       */

      const resetUrl =
        `${url.origin}/reset-password?token=${encodeURIComponent(token)}`;

      console.log(
        "PASSWORD RESET URL CREATED",
        resetUrl
      );

      /*
       * Отправляем письмо.
       */

      const emailResult =
        await sendPasswordResetEmail(
          env,
          user.email,
          resetUrl
        );

      if (!emailResult.success) {
        console.error(
          "PASSWORD RESET EMAIL FAILED",
          JSON.stringify(emailResult)
        );

        /*
         * Токен делаем недействительным,
         * если письмо не отправилось.
         */

        try {
          await env.DB.prepare(`
            UPDATE password_resets
            SET used = 1
            WHERE token_hash = ?
          `)
            .bind(tokenHash)
            .run();
        } catch (error) {
          console.error(
            "TOKEN INVALIDATION ERROR",
            error
          );
        }

        return json(
          {
            success: false,
            error:
              "Не удалось отправить письмо. Попробуйте ещё раз позже."
          },
          500
        );
      }

      return json({
        success: true,
        message:
          "Если аккаунт существует, инструкция по восстановлению будет отправлена."
      });
    }

    /*
     * TEST RESET LINK
     *
     * Только администратор.
     */

    if (
      url.pathname === "/api/test-reset-link" &&
      request.method === "POST"
    ) {
      const admin =
        await getAdminUser(
          env,
          request
        );

      if (!admin) {
        return json(
          {
            success: false,
            error: "Доступ запрещён"
          },
          403
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            success: false,
            error: "Некорректный JSON"
          },
          400
        );
      }

      const email =
        typeof body.email === "string"
          ? body.email.trim().toLowerCase()
          : "";

      if (!email || !email.includes("@")) {
        return json(
          {
            success: false,
            error: "Введите корректный email"
          },
          400
        );
      }

      const user =
        await env.DB.prepare(`
          SELECT id, email
          FROM users
          WHERE email = ?
        `)
          .bind(email)
          .first();

      if (!user) {
        return json(
          {
            success: false,
            error: "Пользователь не найден"
          },
          404
        );
      }

      await env.DB.prepare(`
        UPDATE password_resets
        SET used = 1
        WHERE user_id = ?
          AND used = 0
      `)
        .bind(user.id)
        .run();

      const token = generateToken();
      const tokenHash =
        await hashToken(token);

      const expiresAt =
        new Date(
          Date.now() + 15 * 60 * 1000
        ).toISOString();

      await env.DB.prepare(`
        INSERT INTO password_resets (
          user_id,
          token_hash,
          expires_at,
          used
        )
        VALUES (
          ?,
          ?,
          ?,
          0
        )
      `)
        .bind(
          user.id,
          tokenHash,
          expiresAt
        )
        .run();

      const resetUrl =
        `${url.origin}/reset-password?token=${encodeURIComponent(token)}`;

      return json({
        success: true,
        reset_url: resetUrl,
        expires_at: expiresAt
      });
    }

    /*
     * RESET PASSWORD
     */

    if (
      url.pathname === "/api/reset-password" &&
      request.method === "POST"
    ) {
      const allowed =
        await checkRateLimit(
          env,
          request,
          "reset-password",
          5
        );

      if (!allowed) {
        return json(
          {
            success: false,
            error: "Слишком много запросов"
          },
          429
        );
      }

      let body = {};

      try {
        body = await request.json();
      } catch {
        body = {};
      }

      const token =
        typeof body.token === "string" &&
        body.token.trim()
          ? body.token.trim()
          : url.searchParams.get("token");

      const password =
        typeof body.password === "string"
          ? body.password
          : "";

      if (
        !token ||
        !/^[a-fA-F0-9]{64}$/.test(token)
      ) {
        return json(
          {
            success: false,
            error: "Недействительный токен"
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

      const tokenHash =
        await hashToken(token);

      const reset =
        await env.DB.prepare(`
          SELECT
            password_resets.*,
            users.email
          FROM password_resets
          JOIN users
            ON users.id = password_resets.user_id
          WHERE password_resets.token_hash = ?
        `)
          .bind(tokenHash)
          .first();

      if (!reset) {
        return json(
          {
            success: false,
            error:
              "Недействительный или истёкший токен"
          },
          400
        );
      }

      if (Number(reset.used) === 1) {
        return json(
          {
            success: false,
            error: "Этот токен уже использован"
          },
          400
        );
      }

      const expiresAt =
        new Date(
          reset.expires_at
        ).getTime();

      if (
        Number.isNaN(expiresAt) ||
        expiresAt <= Date.now()
      ) {
        return json(
          {
            success: false,
            error:
              "Срок действия токена истёк"
          },
          400
        );
      }

      /*
       * Хешируем новый пароль.
       */

      const passwordHash =
        await hashToken(password);

      try {
        await env.DB.prepare(`
          UPDATE users
          SET password_hash = ?
          WHERE id = ?
        `)
          .bind(
            passwordHash,
            reset.user_id
          )
          .run();

        await env.DB.prepare(`
          UPDATE password_resets
          SET used = 1
          WHERE token_hash = ?
        `)
          .bind(tokenHash)
          .run();

        /*
         * Завершаем все старые сессии.
         */

        await env.DB.prepare(`
          DELETE FROM sessions
          WHERE user_id = ?
        `)
          .bind(reset.user_id)
          .run();

      } catch (error) {
        console.error(
          "PASSWORD RESET DB ERROR",
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

      return json({
        success: true,
        message:
          "Пароль успешно изменён"
      });
    }

    /*
     * ADMIN USERS
     */

    if (
      url.pathname === "/api/admin/users" &&
      request.method === "GET"
    ) {
      const admin =
        await getAdminUser(
          env,
          request
        );

      if (!admin) {
        return json(
          {
            success: false,
            error: "Доступ запрещён"
          },
          403
        );
      }

      const result =
        await env.DB.prepare(`
          SELECT
            id,
            email,
            created_at,
            subscription_status,
            subscription_plan,
            subscription_expires_at
          FROM users
          ORDER BY id DESC
        `)
          .all();

      return json({
        success: true,
        users: result.results || []
      });
    }

    /*
     * LOGOUT
     */

    if (
      url.pathname === "/api/logout" &&
      request.method === "POST"
    ) {
      const sessionId =
        getCookie(
          request,
          "session"
        );

      if (sessionId) {
        await env.DB.prepare(`
          DELETE FROM sessions
          WHERE id = ?
        `)
          .bind(sessionId)
          .run();
      }

      return new Response(null, {
        status: 204,

        headers: {
          "Set-Cookie":
            "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        }
      });
    }

    /*
     * CURRENT USER
     */

    if (
      url.pathname === "/api/me" &&
      request.method === "GET"
    ) {
      const sessionId =
        getCookie(
          request,
          "session"
        );

      if (!sessionId) {
        return json({
          success: false,
          user: null
        });
      }

      const user =
        await env.DB.prepare(`
          SELECT
            users.id,
            users.email,
            users.created_at
          FROM sessions
          JOIN users
            ON users.id = sessions.user_id
          WHERE sessions.id = ?
            AND sessions.expires_at > datetime('now')
        `)
          .bind(sessionId)
          .first();

      if (!user) {
        return json({
          success: false,
          user: null
        });
      }

      return json({
        success: true,
        user
      });
    }

    /*
     * LOGIN
     */

    if (
      url.pathname === "/api/login" &&
      request.method === "POST"
    ) {
      const allowed =
        await checkRateLimit(
          env,
          request,
          "login",
          10
        );

      if (!allowed) {
        return json(
          {
            success: false,
            error:
              "Слишком много попыток входа"
          },
          429
        );
      }

      let body;

      try {
        body = await request.json();
      } catch {
        return json(
          {
            success: false,
            error: "Некорректный JSON"
          },
          400
        );
      }

      const email =
        typeof body.email === "string"
          ? body.email.trim().toLowerCase()
          : "";

      const password =
        typeof body.password === "string"
          ? body.password
          : "";

      if (
        !email ||
        !email.includes("@")
      ) {
        return json(
          {
            success: false,
            error:
              "Введите корректный email"
          },
          400
        );
      }

      if (!password) {
        return json(
          {
            success: false,
            error: "Введите пароль"
          },
          400
        );
      }

      const user =
        await env.DB.prepare(`
          SELECT *
          FROM users
          WHERE email = ?
        `)
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
        await hashToken(password);

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

      const sessionId =
        Date.now();

      const sessionToken =
        generateToken();

      const tokenHash =
        await hashToken(
          sessionToken
        );

      await env.DB.prepare(`
        INSERT INTO sessions (
          id,
          user_id,
          token_hash,
          expires_at
        )
        VALUES (
          ?,
          ?,
          ?,
          datetime('now', '+30 days')
        )
      `)
        .bind(
          sessionId,
          user.id,
          tokenHash
        )
        .run();

      return new Response(
        JSON.stringify({
          success: true,
          user: {
            id: user.id,
            email: user.email
          }
        }),
        {
          status: 200,

          headers: {
            "Content-Type":
              "application/json; charset=UTF-8",

            "Cache-Control":
              "no-store",

            "Set-Cookie":
              `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`
          }
        }
      );
    }

    /*
     * REGISTER
     */

    if (
      url.pathname === "/api/register" &&
      request.method === "POST"
    ) {
      const allowed =
        await checkRateLimit(
          env,
          request,
          "register",
          5
        );

      if (!allowed) {
        return json(
          {
            success: false,
            error:
              "Слишком много запросов"
          },
          429
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            success: false,
            error:
              "Некорректный JSON"
          },
          400
        );
      }

      const email =
        typeof body.email === "string"
          ? body.email.trim().toLowerCase()
          : "";

      const password =
        typeof body.password === "string"
          ? body.password
          : "";

      if (
        !email ||
        !email.includes("@")
      ) {
        return json(
          {
            success: false,
            error:
              "Введите корректный email"
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

      const existing =
        await env.DB.prepare(`
          SELECT id
          FROM users
          WHERE email = ?
        `)
          .bind(email)
          .first();

      if (existing) {
        return json(
          {
            success: false,
            error:
              "Пользователь уже существует"
          },
          409
        );
      }

      const passwordHash =
        await hashToken(password);

      const result =
        await env.DB.prepare(`
          INSERT INTO users (
            email,
            password_hash
          )
          VALUES (
            ?,
            ?
          )
        `)
          .bind(
            email,
            passwordHash
          )
          .run();

      return json({
        success: true,
        user: {
          id:
            result.meta.last_row_id,
          email
        }
      });
    }

    /*
     * EARLY ACCESS
     */

    if (
      url.pathname === "/api/early-access" &&
      request.method === "POST"
    ) {
      const allowed =
        await checkRateLimit(
          env,
          request,
          "early-access",
          10
        );

      if (!allowed) {
        return json(
          {
            success: false,
            error:
              "Слишком много запросов"
          },
          429
        );
      }

      let body;

      try {
        body =
          await request.json();
      } catch {
        return json(
          {
            success: false,
            error:
              "Некорректный JSON"
          },
          400
        );
      }

      const email =
        typeof body.email === "string"
          ? body.email.trim().toLowerCase()
          : "";

      if (
        !email ||
        !email.includes("@")
      ) {
        return json(
          {
            success: false,
            error:
              "Введите корректный email"
          },
          400
        );
      }

      try {
        await env.DB.prepare(`
          INSERT INTO early_access (
            email
          )
          VALUES (
            ?
          )
        `)
          .bind(email)
          .run();

        return json({
          success: true,
          message:
            "Вы успешно записались в ранний доступ"
        });

      } catch (error) {
        console.error(
          "EARLY ACCESS ERROR",
          error
        );

        return json(
          {
            success: false,
            error:
              "Этот email уже зарегистрирован"
          },
          409
        );
      }
    }

    /*
     * RESET PASSWORD PAGE
     *
     * /reset-password
     *
     * Если старый reset-password.html
     * тоже используется, оставляем его доступным.
     */

    /*
     * ACCOUNT PAGE PROTECTION
     */

    if (
      url.pathname === "/account.html"
    ) {
      const sessionId =
        getCookie(
          request,
          "session"
        );

      if (!sessionId) {
        return Response.redirect(
          `${url.origin}/login.html`,
          302
        );
      }

      const session =
        await env.DB.prepare(`
          SELECT id
          FROM sessions
          WHERE id = ?
            AND expires_at > datetime('now')
        `)
          .bind(sessionId)
          .first();

      if (!session) {
        return Response.redirect(
          `${url.origin}/login.html`,
          302
        );
      }
    }

    /*
     * STATIC ASSETS
     */

    try {
      return await env.ASSETS.fetch(
        request
      );
    } catch (error) {
      console.error(
        "ASSETS FETCH ERROR",
        error
      );

      return new Response(
        "NexoraVPN Worker error",
        {
          status: 500,
          headers: {
            "Content-Type":
              "text/plain; charset=UTF-8"
          }
        }
      );
    }
  }
};
