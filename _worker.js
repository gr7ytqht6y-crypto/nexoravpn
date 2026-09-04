export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // API раннего доступа
    if (url.pathname === "/api/early-access") {

      // Rate limiting: 5 запросов в минуту с одного IP
      const ip =
        request.headers.get("CF-Connecting-IP") || "unknown";

      const { success } = await env.RATE_LIMITER.limit({
        key: ip
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

      // Разрешаем только POST
      if (request.method !== "POST") {
        return Response.json(
          { success: false, error: "Method not allowed" },
          { status: 405 }
        );
      }

      // Проверяем Content-Type
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

      // Ограничиваем размер запроса
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

        // Ограничение длины
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

        // Базовая проверка email
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
        // Email уже существует
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

        // Не раскрываем внутреннюю ошибку пользователю
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

    // Все остальные запросы → сайт
    return env.ASSETS.fetch(request);
  }
};
