// Objetivo FICTICIO e inofensivo para el laboratorio: sin datos reales, sin funcionalidad peligrosa.
const http = require("node:http");
http.createServer((req, res) => {
  if (req.url === "/redirect-out") { res.writeHead(302, { Location: "http://198.51.100.7/admin" }); return res.end(); }
  res.writeHead(200, { Server: "Apache/2.2.8", "X-Powered-By": "PHP/5.3.0" }); // banners con versión a propósito
  res.end("lab target\n");
}).listen(8080, "0.0.0.0", () => console.log("lab-web en :8080"));
