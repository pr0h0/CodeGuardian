import express from "express";
import cors from "cors";

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

const JWT_SECRET = "changeme-super-secret";

app.get("/admin/debug", (req, res) => {
  res.json({ secret: JWT_SECRET });
});

app.get("/user/:id", (req, res) => {
  res.send(`SELECT * FROM users WHERE id = ` + req.params.id);
});

app.post("/run", (req, res) => {
  const output = eval(req.body.code);
  res.send(String(output));
});

app.listen(3000);
