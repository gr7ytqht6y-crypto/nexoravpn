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
  async function getAdminUser(request, env) {
  const cookieHeader =
    request.headers.get("Cookie") || "";

  const match =
    cookieHeader.match(
      /(?:^|;\s*)nexora_session=([^;]+)/
    );

  if (!match) {
    return null;
  }

  const sessionToken = match[1];

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
}export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/forgot-password" && request.method === "POST") {
  try {
    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();

    if (!email) {
      return Response.json(
        { success: false, error: "Email обязателен" },
        { status: 400 }
      );
    }

    const user = await env.DB
      .prepare(
        `SELECT id, email
         FROM users
         WHERE email = ?
         LIMIT 1`
      )
      .bind(email)
      .first();

    // Не раскрываем, существует ли такой аккаунт.
    if (!user) {
      return Response.json({
        success: true,
        message: "Если аккаунт существует, инструкции будут отправлены на email."
      });
    }

    const token = generateToken();
    const tokenHash = await hashToken(token);

    const expiresAt = new Date(
      Date.now() + 15 * 60 * 1000
    ).toISOString();

    await env.DB
      .prepare(
        `UPDATE password_resets
         SET used = 1
         WHERE user_id = ? AND used = 0`
      )
      .bind(user.id)
      .run();

    await env.DB
      .prepare(
        `INSERT INTO password_resets
         (user_id, token_hash, expires_at)
         VALUES (?, ?, ?)`
      )
      .bind(user.id, tokenHash, expiresAt)
      .run();

    return Response.json({
      success: true,
      message: "Если аккаунт существует, инструкции будут отправлены на email."
    });

  } catch (error) {
    return Response.json(
      {
        success: false,
        error: "Ошибка сервера"
      },
      { status: 500 }
    );
  }
}
        // =========================
    // АДМИН: СПИСОК ПОЛЬЗОВАТЕЛЕЙ
    // =========================
    if (url.pathname === "/api/admin/users") {

      if (request.method !== "GET") {
        return Response.json(
          {
            success: false,
            error: "Method not allowed"
          },
          { status: 405 }
        );
      }

      try {
        const admin = await getAdminUser(request, env);

        if (!admin) {
          return Response.json(
            {
              success: false,
              error: "Доступ запрещён"
            },
            { status: 403 }
          );
        }

        const users = await env.DB
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

        return Response.json({
          success: true,
          users: users.results || []
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Не удалось получить пользователей"
          },
          { status: 500 }
        );
      }
    }
        // =========================
    // ВЫХОД ИЗ АККАУНТА
    // =========================
    if (url.pathname === "/api/logout") {

      if (request.method !== "POST") {
        return Response.json(
          {
            success: false,
            error: "Method not allowed"
          },
          { status: 405 }
        );
      }

      try {
        const cookieHeader =
          request.headers.get("Cookie") || "";

        const match =
          cookieHeader.match(
            /(?:^|;\s*)nexora_session=([^;]+)/
          );

        // Если cookie нет — просто очищаем её
        if (!match) {
          return new Response(
            JSON.stringify({
              success: true,
              message: "Вы вышли из аккаунта"
            }),
            {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "Set-Cookie":
                  "nexora_session=; HttpOnly; Secure; " +
                  "SameSite=Lax; Path=/; Max-Age=0"
              }
            }
          );
        }

        const sessionToken = match[1];

        const tokenHash =
          await hashToken(sessionToken);

        // Удаляем сессию из базы
        await env.DB
          .prepare(
            "DELETE FROM sessions WHERE token_hash = ?"
          )
          .bind(tokenHash)
          .run();

        return new Response(
          JSON.stringify({
            success: true,
            message: "Вы вышли из аккаунта"
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie":
                "nexora_session=; HttpOnly; Secure; " +
                "SameSite=Lax; Path=/; Max-Age=0"
            }
          }
        );

      } catch (error) {

        return Response.json(
          {
            success: false,
            error: "Не удалось выполнить выход"
          },
          { status: 500 }
        );

      }
    }
       // =========================
    // ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ
    // =========================
    if (url.pathname === "/api/me") {

      if (request.method !== "GET") {
        return Response.json(
          {
            success: false,
            error: "Method not allowed"
          },
          { status: 405 }
        );
      }

      try {
        const cookieHeader =
          request.headers.get("Cookie") || "";

        const match =
          cookieHeader.match(
            /(?:^|;\s*)nexora_session=([^;]+)/
          );

        if (!match) {
          return Response.json(
            {
              success: false,
              error: "Не авторизован"
            },
            { status: 401 }
          );
        }

        const sessionToken = match[1];

        const tokenHash =
          await hashToken(sessionToken);

        const session = await env.DB
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
               ON users.id = sessions.user_id
             WHERE sessions.token_hash = ?
             LIMIT 1`
          )
          .bind(tokenHash)
          .first();

        if (!session) {
          return Response.json(
            {
              success: false,
              error: "Сессия недействительна"
            },
            { status: 401 }
          );
        }

        if (
          new Date(session.expires_at).getTime() <=
          Date.now()
        ) {
          await env.DB
            .prepare(
              "DELETE FROM sessions WHERE token_hash = ?"
            )
            .bind(tokenHash)
            .run();

          return new Response(
            JSON.stringify({
              success: false,
              error: "Сессия истекла"
            }),
            {
              status: 401,
              headers: {
                "Set-Cookie":
                  "nexora_session=; HttpOnly; Secure; " +
                  "SameSite=Lax; Path=/; Max-Age=0"
              }
            }
          );
        }

        return Response.json({
          success: true,
          user: {
            id: session.user_id,
            email: session.email,
            subscription_status:
              session.subscription_status,
            subscription_plan:
              session.subscription_plan,
            subscription_expires_at:
              session.subscription_expires_at
          }
        });

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Не удалось проверить сессию"
          },
          { status: 500 }
        );
      }
    }
    // =========================
    // ВХОД
    // =========================
    if (url.pathname === "/api/login") {

      if (request.method !== "POST") {
        return Response.json(
          { success: false, error: "Method not allowed" },
          { status: 405 }
        );
      }

      const ip =
        request.headers.get("CF-Connecting-IP") || "unknown";

      const { success: rateLimitSuccess } =
        await env.RATE_LIMITER.limit({
          key: "login:" + ip
        });

      if (!rateLimitSuccess) {
        return Response.json(
          {
            success: false,
            error: "Слишком много попыток. Попробуйте позже."
          },
          { status: 429 }
        );
      }

      try {
        const data = await request.json();

        if (
          !data ||
          typeof data.email !== "string" ||
          typeof data.password !== "string"
        ) {
          return Response.json(
            {
              success: false,
              error: "Email и пароль обязательны"
            },
            { status: 400 }
          );
        }

        const email =
          data.email.trim().toLowerCase();

        const password =
          data.password;

        const user = await env.DB
          .prepare(
            `SELECT id, email, password_hash
             FROM users
             WHERE email = ?
             LIMIT 1`
          )
          .bind(email)
          .first();

        if (!user) {
          return Response.json(
            {
              success: false,
              error: "Неверный email или пароль"
            },
            { status: 401 }
          );
        }

        // Проверяем пароль
        const encoder = new TextEncoder();

        const passwordData =
          encoder.encode(password);

        const hashBuffer =
          await crypto.subtle.digest(
            "SHA-256",
            passwordData
          );

        const hashArray =
          Array.from(
            new Uint8Array(hashBuffer)
          );

        const passwordHash =
          hashArray
            .map((b) =>
              b.toString(16).padStart(2, "0")
            )
            .join("");

        if (passwordHash !== user.password_hash) {
          return Response.json(
            {
              success: false,
              error: "Неверный email или пароль"
            },
            { status: 401 }
          );
        }

                // Создаём случайный токен сессии
        const sessionToken = generateToken();

        // В базе храним только хеш токена
        const tokenHash = await hashToken(sessionToken);

        // Сессия действует 30 дней
        const expiresAt = new Date(
          Date.now() + 30 * 24 * 60 * 60 * 1000
        ).toISOString();

        await env.DB
          .prepare(
            `INSERT INTO sessions
              (user_id, token_hash, expires_at)
             VALUES (?, ?, ?)`
          )
          .bind(
            user.id,
            tokenHash,
            expiresAt
          )
          .run();

        return new Response(
          JSON.stringify({
            success: true,
            message: "Вход выполнен успешно"
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie":
                `nexora_session=${sessionToken}; ` +
                `HttpOnly; Secure; SameSite=Lax; Path=/; ` +
                `Max-Age=2592000`
            }
          }
        );

      } catch (error) {
        return Response.json(
          {
            success: false,
            error: "Не удалось выполнить вход"
          },
          { status: 500 }
        );
      }
    }
    // =========================
    // РЕГИСТРАЦИЯ
    // =========================
    if (url.pathname === "/api/register") {

      if (request.method !== "POST") {
        return Response.json(
          { success: false, error: "Method not allowed" },
          { status: 405 }
        );
      }

      const ip =
        request.headers.get("CF-Connecting-IP") || "unknown";

      const { success } = await env.RATE_LIMITER.limit({
        key: "register:" + ip
      });

      if (!success) {
        return Response.json(
          {
            success: false,
            error: "Слишком много попыток. Попробуйте позже."
          },
          { status: 429 }
        );
      }

      const contentType =
        request.headers.get("content-type") || "";

      if (
        !contentType
          .toLowerCase()
          .includes("application/json")
      ) {
        return Response.json(
          {
            success: false,
            error: "Неверный формат запроса"
          },
          { status: 415 }
        );
      }

      const contentLength = Number(
        request.headers.get("content-length") || "0"
      );

      if (contentLength > 4096) {
        return Response.json(
          {
            success: false,
            error: "Слишком большой запрос"
          },
          { status: 413 }
        );
      }

      try {
        const data = await request.json();

        if (
          !data ||
          typeof data.email !== "string" ||
          typeof data.password !== "string"
        ) {
          return Response.json(
            {
              success: false,
              error: "Email и пароль обязательны"
            },
            { status: 400 }
          );
        }

        const email = data.email.trim().toLowerCase();
        const password = data.password;

        // Проверка email
        if (email.length < 5 || email.length > 254) {
          return Response.json(
            {
              success: false,
              error: "Некорректный email"
            },
            { status: 400 }
          );
        }

        const emailRegex =
          /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

        if (!emailRegex.test(email)) {
          return Response.json(
            {
              success: false,
              error: "Некорректный email"
            },
            { status: 400 }
          );
        }

        // Минимальная длина пароля
        if (password.length < 8 || password.length > 128) {
          return Response.json(
            {
              success: false,
              error: "Пароль должен содержать от 8 до 128 символов"
            },
            { status: 400 }
          );
        }

        // Проверяем, существует ли пользователь
        const existingUser = await env.DB
          .prepare(
            "SELECT id FROM users WHERE email = ? LIMIT 1"
          )
          .bind(email)
          .first();

        if (existingUser) {
          return Response.json(
            {
              success: false,
              error: "Этот email уже зарегистрирован"
            },
            { status: 409 }
          );
        }

        // Хешируем пароль через Web Crypto
        const encoder = new TextEncoder();

        const passwordData =
          encoder.encode(password);

        const hashBuffer =
          await crypto.subtle.digest(
            "SHA-256",
            passwordData
          );

        const hashArray =
          Array.from(new Uint8Array(hashBuffer));

        const passwordHash =
          hashArray
            .map((b) =>
              b.toString(16).padStart(2, "0")
            )
            .join("");

        // Создаём пользователя
        await env.DB
          .prepare(
            `INSERT INTO users
              (email, password_hash)
             VALUES (?, ?)`
          )
          .bind(email, passwordHash)
          .run();

        return Response.json(
          {
            success: true,
            message: "Регистрация успешна!"
          },
          { status: 201 }
        );

      } catch (error) {
        if (String(error).includes("UNIQUE")) {
          return Response.json(
            {
              success: false,
              error: "Этот email уже зарегистрирован"
            },
            { status: 409 }
          );
        }

        return Response.json(
          {
            success: false,
            error: "Не удалось зарегистрировать пользователя"
          },
          { status: 500 }
        );
      }
    }

    // =========================
    // EARLY ACCESS
    // =========================
    if (url.pathname === "/api/early-access") {

      const ip =
        request.headers.get("CF-Connecting-IP") || "unknown";

      const { success } = await env.RATE_LIMITER.limit({
        key: "early-access:" + ip
      });

      if (!success) {
        return Response.json(
          {
            success: false,
            error: "Слишком много запросов. Попробуйте позже."
          },
          { status: 429 }
        );
      }

      if (request.method !== "POST") {
        return Response.json(
          { success: false, error: "Method not allowed" },
          { status: 405 }
        );
      }

      const contentType =
        request.headers.get("content-type") || "";

      if (
        !contentType
          .toLowerCase()
          .includes("application/json")
      ) {
        return Response.json(
          {
            success: false,
            error: "Неверный формат запроса"
          },
          { status: 415 }
        );
      }

      const contentLength = Number(
        request.headers.get("content-length") || "0"
      );

      if (contentLength > 2048) {
        return Response.json(
          {
            success: false,
            error: "Слишком большой запрос"
          },
          { status: 413 }
        );
      }

      try {
        const data = await request.json();

        if (
          !data ||
          typeof data.email !== "string"
        ) {
          return Response.json(
            {
              success: false,
              error: "Email не указан"
            },
            { status: 400 }
          );
        }

        const email = data.email
          .trim()
          .toLowerCase();

        if (
          email.length < 5 ||
          email.length > 254
        ) {
          return Response.json(
            {
              success: false,
              error: "Некорректный email"
            },
            { status: 400 }
          );
        }

        const emailRegex =
          /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

        if (!emailRegex.test(email)) {
          return Response.json(
            {
              success: false,
              error: "Некорректный email"
            },
            { status: 400 }
          );
        }

        await env.DB
          .prepare(
            "INSERT INTO early_access (email) VALUES (?)"
          )
          .bind(email)
          .run();

        return Response.json({
          success: true,
          message:
            "Вы добавлены в список раннего доступа!"
        });

      } catch (error) {

        if (String(error).includes("UNIQUE")) {
          return Response.json(
            {
              success: false,
              error:
                "Этот email уже зарегистрирован"
            },
            { status: 409 }
          );
        }

        return Response.json(
          {
            success: false,
            error:
              "Не удалось обработать запрос"
          },
          { status: 500 }
        );
      }
    }
    // =========================
    // ЗАЩИТА ЛИЧНОГО КАБИНЕТА
    // =========================
    if (url.pathname === "/account.html") {

      try {
        const cookieHeader =
          request.headers.get("Cookie") || "";

        const match =
          cookieHeader.match(
            /(?:^|;\s*)nexora_session=([^;]+)/
          );

        if (!match) {
          return Response.redirect(
            new URL("/login.html", request.url),
            302
          );
        }

        const sessionToken = match[1];

        const tokenHash =
          await hashToken(sessionToken);

        const session = await env.DB
          .prepare(
            `SELECT expires_at
             FROM sessions
             WHERE token_hash = ?
             LIMIT 1`
          )
          .bind(tokenHash)
          .first();

        if (!session) {
          return Response.redirect(
            new URL("/login.html", request.url),
            302
          );
        }

        if (
          new Date(session.expires_at).getTime() <=
          Date.now()
        ) {
          await env.DB
            .prepare(
              "DELETE FROM sessions WHERE token_hash = ?"
            )
            .bind(tokenHash)
            .run();

          return Response.redirect(
            new URL("/login.html", request.url),
            302
          );
        }

      } catch (error) {
        return Response.redirect(
          new URL("/login.html", request.url),
          302
        );
      }
    }
    // =========================
    // САЙТ
    // =========================
    return env.ASSETS.fetch(request);
  }
};
