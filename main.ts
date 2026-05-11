// mhrv-rs exit node - Deno Deploy compatible version
// TypeScript + web-standard Request/Response

const PSK = "Salman@9464";

// Headers that should not be forwarded (hop-by-hop headers)
const STRIP_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "proxy-connection",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-port",
  "x-real-ip",
  "forwarded",
  "via",
]);

function decodeBase64ToBytes(input: string): Uint8Array {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function encodeBytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

function sanitizeHeaders(h: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h || typeof h !== "object") return out;

  for (const [k, v] of Object.entries(h as Record<string, unknown>)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

// Main handler
export default {
  fetch: async (req: Request): Promise<Response> => {
    // Security: Prevent running with placeholder PSK
    if (PSK === "CHANGE_ME_TO_A_STRONG_SECRET") {
      return Response.json(
        {
          e: "exit_node misconfigured: PSK is still the placeholder. Set a strong secret before deploying.",
        },
        { status: 503 }
      );
    }

    try {
      if (req.method !== "POST") {
        return Response.json({ e: "method_not_allowed" }, { status: 405 });
      }

      const body = await req.json();
      if (!body || typeof body !== "object") {
        return Response.json({ e: "bad_json" }, { status: 400 });
      }

      const k = String((body as any).k ?? "");
      const u = String((body as any).u ?? "");
      const m = String((body as any).m ?? "GET").toUpperCase();
      const h = sanitizeHeaders((body as any).h);
      const b64 = (body as any).b;

      // Authentication
      if (k !== PSK) {
        return Response.json({ e: "unauthorized" }, { status: 401 });
      }

      // Validate URL
      if (!/^https?:\/\//i.test(u)) {
        return Response.json({ e: "bad_url" }, { status: 400 });
      }

      // Prevent loops (exit node calling itself)
      try {
        const reqUrl = new URL(req.url);
        const dstUrl = new URL(u);
        if (
          reqUrl.host === dstUrl.host &&
          reqUrl.protocol === dstUrl.protocol
        ) {
          return Response.json({ e: "exit-node_loop_refused" }, { status: 400 });
        }
      } catch {
        // Invalid URL will be caught by fetch
      }

      // Prepare body if present
      let payload: Uint8Array | undefined;
      if (typeof b64 === "string" && b64.length > 0) {
        payload = decodeBase64ToBytes(b64);
      }

      // Forward the request
      const resp = await fetch(u, {
        method: m,
        headers: h,
        body: payload,
        redirect: "manual",
      });

      // Get response body
      const data = new Uint8Array(await resp.arrayBuffer());

      // Prepare response headers (strip problematic ones)
      const respHeaders: Record<string, string> = {};
      resp.headers.forEach((value, key) => {
        const lower = key.toLowerCase();
        if (lower === "content-encoding" || lower === "content-length") {
          return;
        }
        respHeaders[key] = value;
      });

      return Response.json({
        s: resp.status,
        h: respHeaders,
        b: encodeBytesToBase64(data),
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return Response.json({ e: message }, { status: 500 });
    }
  },
} satisfies Deno.ServeDefaultExport;
