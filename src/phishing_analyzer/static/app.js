"use strict";
const file = document.querySelector("#email-file"), sample = document.querySelector("#sample");
const button = document.querySelector("#analyze"), status = document.querySelector("#status");
const panel = document.querySelector("#report"), empty = document.querySelector("#empty");
let currentReport = null;
const el = (tag, text, cls) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (cls) node.className = cls; return node; };
function resetReport() { currentReport = null; panel.replaceChildren(); panel.hidden = true; empty.hidden = false; }
function clear() { resetReport(); file.value = ""; sample.value = ""; document.querySelector("#file-description").textContent = "Choose an .eml file · up to 5 MiB"; status.textContent = "Ready when you are."; file.focus(); }
file.addEventListener("change", () => { sample.value = ""; document.querySelector("#file-description").textContent = file.files[0]?.name || "Choose an .eml file · up to 5 MiB"; resetReport(); });
sample.addEventListener("change", () => { file.value = ""; document.querySelector("#file-description").textContent = "Choose an .eml file · up to 5 MiB"; resetReport(); });
function section(title) { const s = el("section", undefined, "card report-section"); s.append(el("h3", title)); panel.append(s); return s; }
function line(parent, label, value) { const row = el("div", undefined, "data-row"); row.append(el("span", label, "data-label"), el("span", value || "Unavailable", "data-value")); parent.append(row); }
function details(title, text) { const d = el("details"); d.append(el("summary", title), el("pre", text)); return d; }
function render(data) {
  const r = data.report; currentReport = r; panel.hidden = false; empty.hidden = true;
  const top = section("Analysis overview");
  const rating = el("div", undefined, "rating " + (r.score === null ? "partial" : r.score >= 4 ? "high" : r.score >= 2 ? "medium" : "low"));
  rating.append(el("span", r.rating || "Incomplete analysis", "rating-title"), el("span", r.score === null ? "No overall score" : r.score + " weighted points", "points")); top.append(rating);
  top.append(el("p", r.summary, "muted")); line(top, "File", r.filename); line(top, "Coverage", r.completeness === "complete" ? "Complete within configured limits" : "Partial — review warnings");
  r.warnings.forEach(w => top.append(el("p", w, "warning")));
  const actions = el("div", undefined, "actions"); const download = el("button", "Download JSON", "secondary"), another = el("button", "Analyze another email", "text-button");
  download.type = another.type = "button";
  download.addEventListener("click", () => { if (!currentReport) return; const blob = new Blob([JSON.stringify(currentReport, null, 2)], {type: "application/json"}); const url = URL.createObjectURL(blob); const a = el("a"); a.href = url; a.download = "email-analysis.json"; document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); });
  another.addEventListener("click", clear); actions.append(download, another); top.append(actions);
  const findings = section("Observed indicators");
  if (!r.findings.length) findings.append(el("p", "No configured indicators were found. Consider the message's context and the analysis limitations.", "muted"));
  r.findings.forEach(f => { const item = el("article", undefined, "finding"); const head = el("div", undefined, "finding-head"); head.append(el("span", f.rule_id, "rule"), el("span", "+" + f.weight, "weight")); item.append(head, el("h4", f.title), el("p", f.explanation), details("View evidence", f.evidence.map(e => e.reference + "\n" + e.observed).join("\n\n")), el("p", f.recommendation, "recommendation")); findings.append(item); });
  const headers = section("Message details");
  ["from", "reply-to", "subject", "to", "date"].forEach(key => line(headers, key === "reply-to" ? "Reply-To" : key.charAt(0).toUpperCase() + key.slice(1), r.headers[key].map(v => v.value).join(" | ")));
  const links = section("Link destinations");
  if (!r.links.length) links.append(el("p", "No HTTP(S) destinations extracted.", "muted"));
  r.links.forEach(l => { const box = el("div", undefined, "observation"); box.append(el("code", l.url), el("p", l.id + " · Host: " + l.host + " · " + l.occurrences.length + " occurrence(s)", "muted")); links.append(box); });
  const attachments = section("Attachment metadata");
  if (!r.attachments.length) attachments.append(el("p", "No attachments observed.", "muted"));
  r.attachments.forEach(a => { const box = el("div", undefined, "observation"); box.append(el("strong", a.filename), el("p", a.content_type + " · " + (a.size === null ? "Size unavailable" : a.size + " decoded bytes"), "muted")); if(a.note) box.append(el("p",a.note)); attachments.append(box); });
  const auth = section("Authentication observations"); auth.append(el("p", "Unverified headers — results can be forged and do not affect the score.", "warning"));
  if (!r.authentication.length) auth.append(el("p", "Authentication-Results headers unavailable.", "muted"));
  r.authentication.forEach(a => auth.append(details(a.authserv_id || "Uninterpreted header", a.raw)));
  const limitations = section("Analysis boundaries"); const list = el("ul"); r.limitations.forEach(t => list.append(el("li", t))); limitations.append(list, details("Input fingerprint · SHA-256", r.sha256));
  const preview = section("Email text preview"); preview.append(details("Expand extracted text", data.preview.text || "No body text extracted.")); if(data.preview.truncated) preview.append(el("p", "Preview truncated to 20,000 characters; see coverage status for analysis completeness.", "muted"));
}
button.addEventListener("click", async () => {
  if (button.disabled) return;
  resetReport(); const chosen = file.files[0];
  if (!chosen && !sample.value) { status.textContent = "Choose an .eml file or a sample first."; return; }
  if (chosen && chosen.size > 5242880) { status.textContent = "Email exceeds the 5 MiB limit."; return; }
  button.disabled = true; file.disabled = sample.disabled = true; status.textContent = "Inspecting email…";
  const headers = {"X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content};
  const options = {method: "POST", headers}; let path;
  if(chosen) { path = "/api/analyze"; headers["Content-Type"] = "application/octet-stream"; headers["X-Email-Filename"] = encodeURIComponent(chosen.name); options.body = chosen; } else path = "/api/sample/" + encodeURIComponent(sample.value);
  try { const response = await fetch(path, options); const data = await response.json(); if (!response.ok) throw new Error(data.error || "Analysis could not complete."); render(data); status.textContent = "Analysis ready. Review the evidence and limitations."; }
  catch(error) { resetReport(); status.textContent = error.message || "Connection failed. Check that the local app is running."; }
  finally { button.disabled = false; file.disabled = sample.disabled = false; }
});
