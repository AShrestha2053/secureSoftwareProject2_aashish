// vulnerable_server.js
// WARNING: This server is insecure on purpose.

const http = require("http");
const { URL } = require("url");

const guestbook = []; // comments are kept in memory

function page(title, body) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title}</title></head>
<body><h1>${title}</h1>${body}</body></html>`;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");

  // Session cookie that JavaScript can read (no HttpOnly flag)
  res.setHeader("Set-Cookie", "sessionId=demo-session-123; Path=/");

  // Problem 1 (reflected XSS): the search text goes back into the page without encoding
  if (url.pathname === "/search") {
    const q = url.searchParams.get("q") || "";
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(page("Search", `<p>Results for: ${q}</p>`));
  }

  // Problem 2 (stored XSS): comments are saved and shown later without encoding
  if (url.pathname === "/guestbook" && req.method === "POST") {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      guestbook.push(new URLSearchParams(data).get("comment") || "");
      res.writeHead(302, { Location: "/guestbook" });
      res.end();
    });
    return;
  }
  if (url.pathname === "/guestbook") {
    const items = guestbook.map((c) => `<li>${c}</li>`).join("");
    const form =
      '<form method="POST" action="/guestbook">' +
      '<input name="comment"> <button>Send</button></form>';
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(page("Guestbook", `${form}<ul>${items}</ul>`));
  }

  // Problem 3 (code injection): the calculator runs any text it receives with eval()
  if (url.pathname === "/calc") {
    const expr = url.searchParams.get("expr") || "";
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    try {
      return res.end(String(eval(expr)));
    } catch (e) {
      return res.end("Error: " + e.message);
    }
  }

  res.writeHead(404);
  res.end("Not found");
});

server.listen(3001, "127.0.0.1", () => {
  console.log("Vulnerable app: http://127.0.0.1:3001");
});
