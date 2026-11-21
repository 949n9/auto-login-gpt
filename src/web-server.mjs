import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

const CONTENT_TYPES = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".css", "text/css; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
  [".png", "image/png"],
  [".ico", "image/x-icon"],
  [".woff2", "font/woff2"],
]);

export async function createConsoleWebServer({ root, hmrPort }) {
  if (process.env.NODE_ENV !== "production") {
    const [{ createServer }, { default: react }] = await Promise.all([import("vite"), import("@vitejs/plugin-react")]);
    return createServer({
      root, configFile: false, appType: "spa", plugins: [react()],
      server: { middlewareMode: true, hmr: { port: hmrPort, clientPort: hmrPort } },
    });
  }

  const directory = path.resolve(root, "dist");
  await fsp.access(path.join(directory, "index.html"));
  return {
    middlewares(req, res, next) {
      void serveAsset(req, res, directory).catch(next);
    },
    async close() {},
  };
}

async function serveAsset(req, res, directory) {
  if (!["GET", "HEAD"].includes(req.method)) {
    res.writeHead(405, { Allow: "GET, HEAD" }).end();
    return;
  }
  let pathname;
  try { pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname); }
  catch { res.writeHead(400).end(); return; }
  if (pathname.includes("\0") || pathname.includes("\\")) { res.writeHead(400).end(); return; }
  const relative = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  const target = path.resolve(directory, relative);
  if (!target.startsWith(directory + path.sep)) { res.writeHead(404).end(); return; }
  let stat;
  try { stat = await fsp.stat(target); }
  catch (error) { if (error.code === "ENOENT" || error.code === "ENOTDIR") { res.writeHead(404).end(); return; } throw error; }
  if (!stat.isFile()) { res.writeHead(404).end(); return; }
  res.setHeader("Content-Type", CONTENT_TYPES.get(path.extname(target)) || "application/octet-stream");
  res.setHeader("Content-Length", stat.size);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", relative.startsWith("assets/") ? "public, max-age=31536000, immutable" : "no-cache");
  if (req.method === "HEAD") { res.end(); return; }
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(target);
    stream.on("error", reject);
    res.on("close", () => { stream.destroy(); resolve(); });
    res.on("finish", resolve);
    stream.pipe(res);
  });
}
