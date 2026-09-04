export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // API раннего доступа
    if (url.pathname === "/api/early-access" && request.method === "POST") {
      try {
        const data = await request.json();
        const email = data.email?.trim().toLowerCase();

        if (!email || !email.includes("@")) {
          return Response.json(
            { success: false, error: "Введите корректный email" },
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
          message: "Вы добавлены в список раннего доступа!"
        });

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
            error: "Не удалось сохранить email"
          },
          { status: 500 }
        );
      }
    }

    // Все остальные запросы отправляем к сайту
    return env.ASSETS.fetch(request);
  }
};
