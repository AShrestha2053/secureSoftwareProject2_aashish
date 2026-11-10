// secure_server.js
// Same pages as vulnerable_server.js, with the security problems fixed.
const http = require("http");
const { URL } = require("url");

const MAX_BODY = 2000; // bytes allowed in a request body
const MAX_COMMENT = 200; // characters allowed in a comment
const MAX_QUERY = 200; // characters allowed in a search text
const MAX_EXPR = 100; // characters allowed in a calculator expression

const guestbook = [];

// Fix 1: output encoding.
// Special characters become plain text, so the browser cannot run them.
function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Fix 3: a small calculator for numbers, + - * / and brackets.
// It never calls eval().
function calculate(text) {
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_EXPR) {
    throw new Error("Invalid expression");
  }
  // Any character that is not a number, bracket or operator becomes a bad token
  const tokens = text.match(/\d+(\.\d+)?|[()+\-*/]|\S/g);
  let pos = 0;
  const peek = () => tokens[pos];
  const next = () => tokens[pos++];

  function parseExpression() {
    // handles + and -
    let value = parseTerm();
    while (peek() === "+" || peek() === "-") {
      const op = next();
      const right = parseTerm();
      value = op === "+" ? value + right : value - right;
    }
    return value;
  }
  function parseTerm() {
    // handles * and /
    let value = parseFactor();
    while (peek() === "*" || peek() === "/") {
      const op = next();
      const right = parseFactor();
      if (op === "/" && right === 0) throw new Error("Invalid expression");
      value = op === "*" ? value * right : value / right;
    }
    return value;
  }
  function parseFactor() {
    // numbers, brackets, minus sign
    const token = next();
    if (token === "-") return -parseFactor();
    if (token === "(") {
      const value = parseExpression();
      if (next() !== ")") throw new Error("Invalid expression");
      return value;
    }
    if (token !== undefined && /^\d+(\.\d+)?$/.test(token))
      return parseFloat(token);
    throw new Error("Invalid expression");
  }

  const result = parseExpression();
  if (pos < tokens.length) throw new Error("Invalid expression");
  return result;
}

// Fix 2: security headers.
// The policy blocks all scripts, even if one gets into the page.
function setSecurityHeaders(res) {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  // HttpOnly: JavaScript cannot read the cookie. SameSite: not sent from other sites.
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  const cookie =
    "sessionId=demo-session-123; Path=/; HttpOnly; SameSite=Strict";
  res.setHeader("Set-Cookie", cookie + secure);
}

function page(title, body) {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>${title}</title></head>
<body><h1>${title}</h1>${body}</body></html>`;
}

// Fix 4: limit the size of the request body
function readBody(req, res, callback) {
  let data = "";
  let tooBig = false;
  req.on("data", (chunk) => {
    if (tooBig) return;
    data += chunk;
    if (data.length > MAX_BODY) {
      tooBig = true;
      res.writeHead(413, {
        "Content-Type": "text/plain; charset=utf-8",
        Connection: "close",
      });
      res.end("Request too large");
    }
  });
  req.on("end", () => {
    if (!tooBig) callback(data);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  setSecurityHeaders(res);

  if (url.pathname === "/search" && req.method === "GET") {
    const q = (url.searchParams.get("q") || "").slice(0, MAX_QUERY);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(page("Search", `<p>Results for: ${escapeHtml(q)}</p>`));
  }

  if (url.pathname === "/guestbook" && req.method === "POST") {
    return readBody(req, res, (data) => {
      const comment = (new URLSearchParams(data).get("comment") || "").trim();
      if (comment.length === 0 || comment.length > MAX_COMMENT) {
        res.writeHead(400, { "Content-Type": "text/plain; charset=utf-8" });
        return res.end("Invalid comment");
      }
      guestbook.push(comment); // saved as plain text, encoded when it is shown
      res.writeHead(302, { Location: "/guestbook" });
      res.end();
    });
  }
  if (url.pathname === "/guestbook" && req.method === "GET") {
    const items = guestbook.map((c) => `<li>${escapeHtml(c)}</li>`).join("");
    const form =
      '<form method="POST" action="/guestbook">' +
      `<input name="comment" maxlength="${MAX_COMMENT}" required> <button>Send</button></form>`;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.end(page("Guestbook", `${form}<ul>${items}</ul>`));
  }

  if (url.pathname === "/calc" && req.method === "GET") {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    try {
      return res.end(String(calculate(url.searchParams.get("expr") || "")));
    } catch (e) {
      res.statusCode = 400;
      return res.end("Invalid expression"); // no details for the attacker
    }
  }

  res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Not found");
});

server.listen(3002, "127.0.0.1", () => {
  console.log("Secure app: http://127.0.0.1:3002");
});
