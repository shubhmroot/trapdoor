const json = (status, message) => new Response(JSON.stringify({ error: message }), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
});

export default async (request) => {
  const configured = process.env.TRAPDOOR_BACKEND_URL?.trim();
  if (!configured) {
    return json(503, "Trapdoor's analysis service is not connected yet. Finish the deployment setup in Netlify.");
  }

  let backend;
  try {
    backend = new URL(configured);
  } catch {
    return json(503, "The configured Trapdoor service URL is invalid.");
  }
  if (backend.protocol !== "https:" || backend.username || backend.password || backend.search || backend.hash) {
    return json(503, "The Trapdoor service URL must be a clean HTTPS origin.");
  }
  const proxyToken = process.env.TRAPDOOR_PROXY_TOKEN?.trim();
  if (!proxyToken) {
    return json(503, "The private connection to Trapdoor's analysis service is not configured yet.");
  }

  const incoming = new URL(request.url);
  const destination = new URL(`${incoming.pathname}${incoming.search}`, backend.origin);
  const headers = new Headers();
  for (const name of ["accept", "content-type"]) {
    const value = request.headers.get(name);
    if (value) headers.set(name, value);
  }
  headers.set("authorization", `Bearer ${proxyToken}`);

  try {
    const upstream = await fetch(destination, {
      method: request.method,
      headers,
      body: request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer(),
      signal: AbortSignal.timeout(55_000),
    });
    const responseHeaders = new Headers();
    for (const name of ["content-type", "cache-control"]) {
      const value = upstream.headers.get(name);
      if (value) responseHeaders.set(name, value);
    }
    responseHeaders.set("cache-control", "no-store");
    return new Response(await upstream.arrayBuffer(), {
      status: upstream.status,
      headers: responseHeaders,
    });
  } catch {
    return json(502, "Trapdoor's analysis service is temporarily unavailable. Please try again shortly.");
  }
};

export const config = {
  path: "/api/*",
  method: ["GET", "POST"],
  rateLimit: {
    action: "rate_limit",
    aggregateBy: "ip",
    windowSize: 60,
    windowLimit: 10,
  },
};
