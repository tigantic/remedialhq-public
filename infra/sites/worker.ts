interface Env {
  ASSETS: Fetcher;
}

const rawDocuments = import.meta.glob("./documents/*.html", {
  eager: true,
  import: "default",
  query: "?raw",
}) as Record<string, string>;

const documents = new Map<string, string>();
let notFoundDocument = "";

for (const [modulePath, html] of Object.entries(rawDocuments)) {
  const filename = modulePath.slice(
    modulePath.lastIndexOf("/") + 1,
    -".html".length,
  );
  if (filename === "404") {
    notFoundDocument = html;
  } else {
    documents.set(filename === "index" ? "/" : `/${filename}`, html);
  }
}

if (!documents.has("/") || !notFoundDocument) {
  throw new Error("Required HTML documents are missing");
}

const staticHeaders = {
  "Content-Security-Policy":
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self' mailto:; upgrade-insecure-requests",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
};

function withProductionHeaders(
  response: Response,
  cacheControl = "public, max-age=0, must-revalidate",
): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(staticHeaders)) {
    headers.set(name, value);
  }
  headers.set("Cache-Control", cacheControl);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function htmlResponse(
  request: Request,
  html: string,
  status = 200,
  cacheControl = "public, max-age=0, must-revalidate",
): Response {
  return withProductionHeaders(
    new Response(request.method === "HEAD" ? null : html, {
      status,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    }),
    cacheControl,
  );
}

function permanentRedirect(request: Request, url: URL): Response {
  return withProductionHeaders(
    new Response(null, {
      status: 308,
      headers: { Location: url.toString() },
    }),
    request.method === "HEAD" ? "no-store" : "public, max-age=3600",
  );
}

function canonicalize(url: URL): boolean {
  let changed = false;
  if (url.hostname === "www.remedialhq.com") {
    url.protocol = "https:";
    url.hostname = "remedialhq.com";
    url.port = "";
    changed = true;
  }

  if (url.pathname === "/index" || url.pathname === "/index.html") {
    url.pathname = "/";
    changed = true;
  } else if (url.pathname.endsWith(".html")) {
    const cleanPath = url.pathname.slice(0, -".html".length) || "/";
    if (documents.has(cleanPath)) {
      url.pathname = cleanPath;
      changed = true;
    }
  } else if (url.pathname.length > 1 && url.pathname.endsWith("/")) {
    const cleanPath = url.pathname.slice(0, -1);
    if (documents.has(cleanPath)) {
      url.pathname = cleanPath;
      changed = true;
    }
  }
  return changed;
}

const worker = {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return withProductionHeaders(
        new Response("Method Not Allowed", {
          status: 405,
          headers: { Allow: "GET, HEAD" },
        }),
        "no-store",
      );
    }

    const url = new URL(request.url);
    if (canonicalize(url)) return permanentRedirect(request, url);

    const document = documents.get(url.pathname);
    if (document !== undefined) return htmlResponse(request, document);

    const assetResponse = await env.ASSETS.fetch(request);
    if (assetResponse.status !== 404) return withProductionHeaders(assetResponse);

    return htmlResponse(request, notFoundDocument, 404, "no-store");
  },
};

export default worker;
