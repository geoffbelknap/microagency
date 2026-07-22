// Package authui renders microagency's served OAuth screens: the client-approval
// consent page, the upstream-connected callback, and generic notices. One shared
// stylesheet, no external assets, auto light/dark via prefers-color-scheme.
package authui

import (
	"html"
	"html/template"
	"net/http"
)

// css is the shared stylesheet. Tokens mirror the Agency design system; the dark
// block is applied by the OS setting. Self-host Fraunces/Space Mono woff2 subsets
// and add @font-face here if you want the exact display face; otherwise the system
// stack (Georgia / system-ui / ui-monospace) is used with zero network cost.
const css = `
:root{
 --warm:#FDFAF5;--warm-2:#FAF7F2;--warm-3:#F2ECE4;
 --ink:#1A1714;--ink-mid:#6B6560;--ink-faint:#B8B2AC;
 --ink-hairline:#E8E2D9;--ink-hairline-strong:#D4CEC8;
 --teal:#00A882;--teal-dark:#007A62;--teal-tint:#E1F5EE;--teal-border:#B8E8D8;
 --amber:#E5A000;--amber-tint:#FBF0D4;--red:#D94040;--red-tint:#FBE4E4;
 --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
 --display:Georgia,"Times New Roman",serif;--mono:ui-monospace,"SF Mono",Menlo,monospace;
}
@media (prefers-color-scheme:dark){:root{
 --warm:#1A1714;--warm-2:#211D19;--warm-3:#2C2622;
 --ink:#FDFAF5;--ink-mid:#B8B0A6;--ink-faint:#6B6560;
 --ink-hairline:#3A332D;--ink-hairline-strong:#4C433B;
 --teal:#00E5B4;--teal-dark:#00C296;--teal-tint:#1E3630;--teal-border:#2F5548;
 --amber:#F5B838;--amber-tint:#3A2E14;--red:#EF4444;--red-tint:#3A1F1F;
}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
 background:var(--warm-3);color:var(--ink);font-family:var(--sans);font-weight:300;-webkit-font-smoothing:antialiased}
.card{width:100%;max-width:360px;background:var(--warm);border:.5px solid var(--ink-hairline-strong);
 border-radius:12px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.10)}
.head{padding:18px 22px 14px;border-bottom:.5px solid var(--ink-hairline);display:flex;align-items:center;gap:11px}
.mark{width:30px;height:30px;border-radius:8px;display:grid;grid-template-columns:1fr 1fr;gap:2px;padding:4px;
 background:var(--warm-2);border:.5px solid var(--teal-border);flex-shrink:0}
.mark i{border-radius:2px;background:var(--ink)}.mark i:first-child{background:var(--teal)}
.word{font-family:var(--mono);font-size:13px;font-weight:700}
.sub{font-family:var(--mono);font-size:10px;color:var(--ink-faint)}
.body{padding:22px}
.eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--teal-dark)}
.title{font-family:var(--display);font-weight:400;font-size:23px;letter-spacing:-.015em;line-height:1.2;color:var(--ink)}
.title i{font-style:italic}
.lead{font-size:13px;line-height:1.55;color:var(--ink-mid);margin:11px 0 0}
.rows{margin-top:16px;display:flex;flex-direction:column;gap:1px;background:var(--ink-hairline);
 border:.5px solid var(--ink-hairline);border-radius:10px;overflow:hidden}
.row{display:flex;gap:12px;padding:11px 14px;background:var(--warm-2)}
.row .k{font-family:var(--mono);font-size:9.5px;color:var(--ink-faint);width:74px;flex-shrink:0;
 text-transform:uppercase;letter-spacing:.06em;padding-top:1px}
.row .v{font-size:12px;color:var(--ink);word-break:break-all}
.row .v.mono{font-family:var(--mono);font-size:11px}
form{margin:20px 0 0}
.actions{display:flex;gap:10px}
.btn{flex:1;padding:11px;border-radius:999px;border:.5px solid var(--ink-hairline-strong);
 background:var(--warm);color:var(--ink-mid);font-family:var(--sans);font-size:14px;cursor:pointer}
.btn.primary{flex:2;background:var(--teal);border-color:var(--teal);color:#fff}
.note{font-family:var(--mono);font-size:10px;color:var(--ink-faint);text-align:center;margin:14px 0 0}
.center{text-align:center}
.seal{width:46px;height:46px;margin:0 auto 16px;border-radius:12px;display:flex;align-items:center;justify-content:center}
.seal.ok{background:var(--teal-tint);border:.5px solid var(--teal-border)}
.seal.warn{background:var(--amber-tint);border:.5px solid var(--amber)}
.bar{margin-top:20px;height:2px;background:var(--warm-3);border-radius:2px;overflow:hidden}
.bar i{display:block;height:100%;width:40%;background:var(--teal);border-radius:2px;
 animation:scan 1.5s cubic-bezier(.2,0,.1,1) infinite}
@keyframes scan{from{transform:translateX(-120%)}to{transform:translateX(320%)}}
.link{display:inline-flex;align-items:center;gap:6px;margin-top:18px;font-family:var(--mono);
 font-size:11px;color:var(--teal-dark);text-decoration:none}`

const markSVG = `<span class="mark"><i></i><i></i><i></i><i></i></span>`

// shell wraps a body fragment in the full document with the shared stylesheet.
// extraHead is injected into <head> (used for the callback's meta-refresh).
func shell(title, extraHead, body string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>` + title + `</title>` + extraHead +
		`<style>` + css + `</style></head><body>` + body + `</body></html>`
}

// --- 1. Client consent -------------------------------------------------------

// consentTmpl keeps the original contract: POST back with approve=yes|no and the
// upstream authorize params replayed as hidden inputs from Fields.
var consentTmpl = template.Must(template.New("consent").Parse(shell(
	"microagency — Approve", "", `
<div class="card">
 <div class="head">`+markSVG+`<div><div class="word">microagency</div><div class="sub">authorize a client</div></div></div>
 <div class="body">
  <div class="eyebrow" style="margin-bottom:11px">Requesting access</div>
  <div class="title">Connect <i>{{.Name}}</i> to microagency?</div>
  <p class="lead">This client is requesting access to your microagency gateway. Approving issues it a token scoped to your operator session — it reaches your tools only through the three governed tools.</p>
  <div class="rows">
   <div class="row"><span class="k">Client</span><span class="v">{{.Name}}</span></div>
   <div class="row"><span class="k">Redirect</span><span class="v mono">{{.Redirect}}</span></div>
   <div class="row"><span class="k">Grants</span><span class="v">find_tools · call_tool · reduce</span></div>
  </div>
  <form method="post">
   {{range $k, $v := .Fields}}<input type="hidden" name="{{$k}}" value="{{$v}}">
   {{end}}<div class="actions">
    <button class="btn" name="approve" value="no">Deny</button>
    <button class="btn primary" name="approve" value="yes">Approve</button>
   </div>
  </form>
  <p class="note">a token is issued only after you approve · nothing is stored on this client</p>
 </div>
</div>`)))

// WriteConsent renders the client-approval page. Drop-in for renderConsent.
func WriteConsent(w http.ResponseWriter, name, redirect string, fields map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTmpl.Execute(w, struct {
		Name, Redirect string
		Fields         map[string]string
	}{name, redirect, fields})
}

// --- 2. Upstream connected (callback) ---------------------------------------

// WriteConnected renders the post-OAuth success page and auto-returns to the
// console after 2s. Drop-in for the inline callback HTML in oauthadd.go.
func WriteConnected(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `
<div class="card"><div class="body center" style="padding:34px 26px">
 <div class="seal ok"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--teal-dark)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 4 4L19 7"/></svg></div>
 <div class="title" style="font-size:25px">Connected ` + html.EscapeString(name) + `</div>
 <p class="lead" style="margin-top:10px">The credential is held by microagency — your agent never sees it. Returning to the console…</p>
 <div class="bar"><i></i></div>
</div></div>`
	_, _ = w.Write([]byte(shell("microagency",
		`<meta http-equiv="refresh" content="2;url=/console">`, body)))
}

// --- 3. Generic notice ------------------------------------------------------

// WriteMessage renders a short notice (expired request, denial, exchange error).
// Drop-in for the local writeHTML helper in oauthadd.go.
func WriteMessage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	body := `
<div class="card">
 <div class="head">` + markSVG + `<div><div class="word">microagency</div><div class="sub">authorization</div></div></div>
 <div class="body">
  <div class="seal warn" style="margin:0 0 16px"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--amber)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/></svg></div>
  <p class="lead" style="margin-top:0;font-size:14px;color:var(--ink)">` + html.EscapeString(msg) + `</p>
  <a class="link" href="/console">Open the console
   <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 17 17 7M8 7h9v9"/></svg></a>
 </div>
</div>`
	_, _ = w.Write([]byte(shell("microagency", "", body)))
}
