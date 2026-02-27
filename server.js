const express = require("express");
const session = require("express-session");
const { Issuer, generators } = require("openid-client");

const app = express();
const PORT = process.env.PORT || 3000;

let client;

async function init() {
  const issuer = await Issuer.discover(process.env.KEYCLOAK_ISSUER);
  client = new issuer.Client({
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    redirect_uris: [process.env.REDIRECT_URI],
    response_types: ["code"],
  });
}

app.use(session({ secret: "secret", resave: false, saveUninitialized: true }));

app.get("/", (req, res) => {
  if (!req.session.user) {
    return res.send(`<a href="/login">Login with Keycloak</a>`);
  }
  res.send(`<h2>Logged In 🚀</h2><pre>${JSON.stringify(req.session.user, null, 2)}</pre>`);
});

app.get("/login", async (req, res) => {
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  req.session.code_verifier = code_verifier;

  const authUrl = client.authorizationUrl({
    scope: "openid profile email",
    code_challenge,
    code_challenge_method: "S256",
  });

  res.redirect(authUrl);
});

app.get("/callback", async (req, res) => {
  const params = client.callbackParams(req);
  const tokenSet = await client.callback(
    process.env.REDIRECT_URI,
    params,
    { code_verifier: req.session.code_verifier }
  );

  const userinfo = await client.userinfo(tokenSet.access_token);
  req.session.user = userinfo;

  res.redirect("/");
});

init().then(() => {
  app.listen(PORT, () => console.log("App running on port", PORT));
});
