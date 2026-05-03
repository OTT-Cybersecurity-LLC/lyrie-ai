// ⚠️  Intentionally vulnerable test fixture for `lyrie hack`. DO NOT DEPLOY.
//
//   - SQL injection via string interpolation
//   - DOM XSS via innerHTML on user input
//   - Hardcoded AWS access key id
//   - Shell-string exec on user input

const express = require("express");
const { exec } = require("child_process");
const db = require("./db");

// Hardcoded credential — Lyrie SecretDetector should flag this.
// Synthesized AWS-shaped key (matches the regex; not a real credential and
// not a known AWS-docs example, so GitHub's push-protection won't flag it).
const AWS_ACCESS_KEY_ID = "AKIAQUACKQUACKQUACKQ";
const AWS_SECRET_ACCESS_KEY_LINE =
  "aws_secret_access_key=quack0123456789QUACK0123456789quackQUACK00";

const app = express();

// SQL injection: untrusted `id` concatenated into the query.
app.get("/user/:id", (req, res) => {
  const id = req.params.id;
  db.query(`SELECT * FROM users WHERE id = ${id}`, (err, rows) => {
    if (err) return res.status(500).send("db error");
    res.json(rows);
  });
});

// XSS via innerHTML — user-controlled string written into the DOM tree.
app.get("/profile", (req, res) => {
  const name = req.query.name;
  res.send(`<html><body><div id="x"></div>
    <script>document.getElementById("x").innerHTML = "${name}";</script>
    </body></html>`);
});

// Shell injection via exec("string with ${user}").
app.get("/convert", (req, res) => {
  const filename = req.query.f;
  exec(`convert ${filename} out.png`, (err) => {
    if (err) return res.status(500).send("convert failed");
    res.send("ok");
  });
});

app.listen(3000, () => console.log("vulnerable app on :3000"));
