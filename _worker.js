export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/" || url.pathname === "/index.html") {
      return env.ASSETS.fetch(
        new Request(new URL("/index.html", request.url), request)
      );
    }

    if (url.pathname === "/early-access.html") {
      return env.ASSETS.fetch(
        new Request(new URL("/early-access.html", request.url), request)
      );
    }

    return new Response("NexoraVPN — Not Found", {
      status: 404,
      headers: {
        "content-type": "text/plain; charset=UTF-8"
      }
    });
  }
};
