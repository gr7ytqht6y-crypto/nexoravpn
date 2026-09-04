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
}export default {
  async fetch(request, env) {
    const url = new URL(request.url);
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
    // САЙТ
    // =========================
    return env.ASSETS.fetch(request);
  }
};
