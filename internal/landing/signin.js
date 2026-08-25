/* Sign-in.

   Everything in this file is served to anyone who asks for the root, so it
   carries no prose beyond what a maintainer needs to read the code. The
   reasoning for all of it is in landing.go, which is not served.

   Discovery, dynamic client registration, an authorization code exchange with
   PKCE. The access token lives in this tab's sessionStorage and is never a
   cookie. The page then requests the route it was configured with, presenting
   that token, and replaces itself with what comes back. */
(function () {
  "use strict";

  var CFG = {};
  try { CFG = JSON.parse(document.getElementById("gate-config").textContent || "{}"); } catch (e) { CFG = {}; }
  var K = CFG.keys || {};
  /* The client_id is a public identifier, not a secret, and it is per origin:
     a different origin is a different issuer and a different client. */
  var CLIENT_KEY = (K.client || "oauth.client:") + location.origin;

  var meta = null, resource = "";

  function $(sel) { return document.querySelector(sel); }
  function ss(k) { try { return sessionStorage.getItem(k) || ""; } catch (e) { return ""; } }
  function ssSet(k, v) { try { sessionStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function ssDel(k) { try { sessionStorage.removeItem(k); } catch (e) { /* private mode */ } }
  function lsGet(k) { try { return localStorage.getItem(k) || ""; } catch (e) { return ""; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }
  function lsDel(k) { try { localStorage.removeItem(k); } catch (e) { /* private mode */ } }

  /* ---------- the one control ---------- */

  function notice(msg) {
    var slot = $("#notice");
    slot.textContent = "";
    if (!msg) return;
    var n = document.createElement("div");
    n.className = "notice";
    n.textContent = msg;
    slot.appendChild(n);
  }

  /* The card starts visible so a browser that never runs this script still
     shows the control. Script hides it only while a sign-in is in flight, when
     showing a button the person should not press would be misleading. */
  function hide() { $("#gate").style.visibility = "hidden"; }
  function show() { $("#gate").style.visibility = "visible"; }

  function busy(on) {
    var b = $("#signin");
    b.disabled = !!on;
    b.textContent = on ? "Signing in…" : "Sign in";
  }

  /* idle returns the page to its resting state: one enabled control, and a
     sentence when something needs saying. */
  function idle(msg) {
    busy(false);
    show();
    notice(msg || "");
  }

  function failed(e) {
    idle((e && e.message) || "Sign-in did not complete. Try again.");
  }

  /* ---------- discovery, registration, PKCE ---------- */

  /* Same-origin normalisation. This process serves the page and hosts its own
     authorization server, so an advertised endpoint is used on the origin the
     person actually reached — 127.0.0.1 and localhost are the same process but
     not the same browser origin. */
  function localize(u) {
    try { var x = new URL(u, location.origin); return x.pathname + x.search; } catch (e) { return u; }
  }

  async function getJSON(url) {
    var r = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store", credentials: "omit" });
    if (!r.ok) throw new Error("Sign-in is not available right now. Try again.");
    return r.json();
  }

  function b64url(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function randomB64(n) {
    var b = new Uint8Array(n);
    crypto.getRandomValues(b);
    return b64url(b);
  }
  async function challengeFor(verifier) {
    var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    return b64url(new Uint8Array(digest));
  }

  async function discover() {
    if (meta) return meta;
    var prm = await getJSON(localize(CFG.resource_metadata || "/.well-known/oauth-protected-resource"));
    resource = prm.resource || "";
    var issuer = (prm.authorization_servers && prm.authorization_servers[0]) || location.origin;
    meta = await getJSON(localize(issuer.replace(/\/+$/, "") + "/.well-known/oauth-authorization-server"));
    return meta;
  }

  async function ensureClient(registrationEndpoint, redirect) {
    var cached = lsGet(CLIENT_KEY);
    if (cached) return cached;
    var r = await fetch(localize(registrationEndpoint), {
      method: "POST", cache: "no-store", credentials: "omit",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        redirect_uris: [redirect],
        client_name: "Account",
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code"],
        response_types: ["code"]
      })
    });
    if (!r.ok) {
      throw new Error("Sign-in is not available on this address (" + r.status +
        "). Reach it over HTTPS, or on a loopback address over HTTP.");
    }
    var reg = await r.json();
    if (!reg.client_id) throw new Error("Sign-in did not complete. Try again.");
    lsSet(CLIENT_KEY, reg.client_id);
    return reg.client_id;
  }

  async function signIn() {
    if (!(window.crypto && window.crypto.subtle)) {
      idle("This browser will not sign in on an insecure origin. Reach this address over HTTPS, or on a loopback address.");
      return;
    }
    busy(true);
    notice("");
    var as = await discover();
    /* The redirect target is this page. */
    var redirect = location.origin + location.pathname;
    var clientID = await ensureClient(as.registration_endpoint, redirect);
    var verifier = randomB64(64);
    var nonce = randomB64(16);
    ssSet(K.pkce, JSON.stringify({
      v: verifier, s: nonce, r: redirect, res: resource || "", iss: as.issuer || ""
    }));
    ssSet(K.attempt, "1");
    var q = new URLSearchParams({
      response_type: "code",
      client_id: clientID,
      redirect_uri: redirect,
      code_challenge: await challengeFor(verifier),
      code_challenge_method: "S256",
      scope: "mcp",
      state: nonce
    });
    if (resource) q.set("resource", resource);
    location.href = localize(as.authorization_endpoint) + "?" + q.toString();
  }

  async function complete(params) {
    var pkce = {};
    try { pkce = JSON.parse(ss(K.pkce) || "{}"); } catch (e) { pkce = {}; }
    ssDel(K.pkce);
    ssDel(K.attempt);
    history.replaceState(null, "", location.pathname);

    if (params.get("error")) {
      idle("Sign-in was not completed: " + params.get("error") + ".");
      return;
    }
    var code = params.get("code");
    if (!code || !pkce.v) { idle("Sign-in did not complete. Try again."); return; }
    if (params.get("state") !== pkce.s) {
      idle("Sign-in was refused: the reply did not match the request this browser started.");
      return;
    }
    var issued = params.get("iss");
    if (issued && pkce.iss && issued !== pkce.iss) {
      idle("Sign-in was refused: the reply came from a different authorization server.");
      return;
    }
    var as = await discover();
    var form = new URLSearchParams({
      grant_type: "authorization_code",
      code: code,
      code_verifier: pkce.v,
      client_id: lsGet(CLIENT_KEY),
      redirect_uri: pkce.r
    });
    if (pkce.res) form.set("resource", pkce.res);
    var r = await fetch(localize(as.token_endpoint), {
      method: "POST", cache: "no-store", credentials: "omit",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString()
    });
    if (!r.ok) {
      /* A refused exchange usually means this browser's remembered client is no
         longer registered here. Drop it so the next attempt registers again. */
      lsDel(CLIENT_KEY);
      idle("Sign-in was refused. Try again.");
      return;
    }
    var tok = await r.json();
    if (!tok.access_token) { idle("Sign-in did not complete. Try again."); return; }
    /* Only the access token is kept, and only for this tab. The refresh token is
       deliberately dropped: a long-lived secret has no place in a browser. */
    ssSet(K.token, tok.access_token);
    await enter();
  }

  /* ---------- handing the tab over ---------- */

  /* enter requests the configured route with the token this tab holds and
     replaces the document with what it returns.

     It is fetched rather than navigated to because a navigation carries no
     Authorization header, and nothing here is kept in a cookie. See landing.go
     for why that matters. */
  async function enter() {
    var token = ss(K.token);
    if (!token) { idle(""); return; }
    hide();
    var r;
    try {
      r = await fetch(CFG.portal_path, {
        headers: { Authorization: "Bearer " + token, Accept: "text/html" },
        cache: "no-store", credentials: "omit"
      });
    } catch (e) {
      idle("Could not reach this address. Try again.");
      return;
    }
    /* A redirect means the token was not accepted, and following it would land
       back here. Treat it as a refusal rather than rendering the result. */
    if (r.redirected || !r.ok) {
      ssDel(K.token);
      idle(r.status === 401 ? "That session has ended. Sign in again." : "");
      return;
    }
    var page = await r.text();
    document.open();
    document.write(page);
    document.close();
  }

  /* ---------- start ---------- */

  $("#signin").onclick = function () { signIn().catch(failed); };

  var query = new URLSearchParams(location.search);
  if (query.get("code") || query.get("error")) {
    hide();
    complete(query).catch(failed);
  } else if (ss(K.token)) {
    enter().catch(failed);
  } else if (ss(K.attempt)) {
    /* We left for the authorization server and came back without a result — the
       person went back, or this browser's remembered client is no longer
       registered here. Forget it so the next attempt registers cleanly. */
    ssDel(K.attempt); ssDel(K.pkce); lsDel(CLIENT_KEY);
    idle("Sign-in did not complete. Try again.");
  } else {
    /* One sentence may be waiting in this tab's own storage, written by the
       page on the other side of sign-in. It is never part of what is served. */
    var handoff = ss(K.notice);
    ssDel(K.notice);
    idle(handoff);
  }
})();
