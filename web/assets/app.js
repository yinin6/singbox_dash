let state = null;
let currentServiceId = "";
let currentTab = "edit";

const $ = (id) => document.getElementById(id);

async function loadState() {
  state = await fetch("/api/state").then((r) => r.json());
  currentServiceId = state.services?.[0]?.id || "";
  render();
}

async function saveState(options) {
  const shouldRender = !options || options.render !== false;
  normalizeClientState();
  state = await fetch("/api/state", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(state),
  }).then((r) => r.json());
  $("status").textContent = "已保存 " + new Date().toLocaleTimeString();
  if (shouldRender) render();
}

async function addService() {
  state = await fetch("/api/service", { method: "POST" }).then((r) => r.json());
  currentServiceId = state.services[state.services.length - 1].id;
  render();
}

async function addCert() {
  state = await fetch("/api/certificate", { method: "POST" }).then((r) => r.json());
  render();
}

async function deleteCurrentService() {
  if (!currentServiceId) return;
  state = await fetch("/api/service/" + encodeURIComponent(currentServiceId), { method: "DELETE" }).then((r) => r.json());
  currentServiceId = state.services?.[0]?.id || "";
  render();
}

function render() {
  $("host").value = state.panel.host || "";
  $("dnsStrategy").value = state.panel.dns_strategy || "prefer_ipv4";
  $("subToken").value = state.panel.sub_token || "";
  $("singBoxPath").value = state.panel.sing_box_path || "sing-box";
  $("runtimeConfigPath").value = state.panel.runtime_config_path || "data/runtime/server.json";
  $("runtimePIDPath").value = state.panel.runtime_pid_path || "data/runtime/sing-box.pid";
  $("runtimeLogPath").value = state.panel.runtime_log_path || "data/runtime/sing-box.log";
  $("autoRestart").checked = state.panel.auto_restart !== false;
  $("subUrl").textContent = location.origin + "/sub/" + state.panel.sub_token + "?user=" + encodeURIComponent(firstUserId());
  $("clientLink").href = "/export/client.json?user=" + encodeURIComponent(firstUserId());
  renderServices();
  renderCerts();
  renderEditor();
  renderPreviewUsers();
  if (currentTab === "preview") refreshPreview();
}

function renderServices() {
  $("serviceList").innerHTML = "";
  for (const svc of state.services || []) {
    const btn = document.createElement("button");
    btn.className = svc.id === currentServiceId ? "active" : "";
    btn.onclick = () => {
      currentServiceId = svc.id;
      renderEditor();
      renderServices();
    };
    btn.innerHTML =
      "<span>" +
      escapeHTML(svc.name || svc.protocol) +
      '<br><span class="muted">' +
      svc.protocol +
      " : " +
      svc.port +
      '</span></span><span class="pill">' +
      (svc.enabled ? "on" : "off") +
      "</span>";
    $("serviceList").appendChild(btn);
  }
}

function renderCerts() {
  $("certList").innerHTML = "";
  for (const cert of state.certificates || []) {
    const card = document.createElement("div");
    card.className = "card cert-card stack";
    const expires = cert.expires_at && !cert.expires_at.startsWith("0001-") ? new Date(cert.expires_at).toLocaleString() : "未读取";
    const mode = cert.mode || "file";
    const realityAction =
      mode === "reality" ? '<button onclick="generateCertRealityKeypair(\'' + cert.id + '\')">Reality 密钥</button>' : "";
    card.innerHTML =
      '<div class="row between cert-header">' +
      '<div class="cert-status"><strong>' +
      escapeHTML(cert.last_status || "unknown") +
      "</strong><br>" +
      escapeHTML(cert.last_message || "") +
      "<br>到期：" +
      escapeHTML(expires) +
      "</div>" +
      '<div class="cert-actions"><button onclick="issueCert(\'' +
      cert.id +
      "')\">签发/续期</button><button onclick=\"refreshCert('" +
      cert.id +
      "')\">刷新</button>" +
      realityAction +
      "</div>" +
      "</div>" +
      '<div class="cert-grid">' +
      '<label>名称 <input value="' +
      escapeAttr(cert.name || "") +
      '" data-cert="' +
      cert.id +
      '" data-field="name"></label>' +
      '<label>模式 <select data-cert="' +
      cert.id +
      '" data-field="mode">' +
      '<option value="file">手动文件</option><option value="self_signed">自签名</option><option value="reality">Reality</option><option value="acme_http">ACME HTTP-01</option><option value="acme_tls_alpn">ACME TLS-ALPN-01</option><option value="acme_dns">ACME DNS-01</option>' +
      "</select></label>" +
      '<label>' +
      (mode === "reality" ? "握手域名" : "服务名") +
      ' <input value="' +
      escapeAttr(cert.server_name || "") +
      '" data-cert="' +
      cert.id +
      '" data-field="server_name"></label>' +
      buildCertificateModeFields(cert, mode) +
      "</div>" +
      buildCertificateExtraFields(cert, mode) +
      '<label class="row"><input type="checkbox" data-cert="' +
      cert.id +
      '" data-field="auto_renew"> 自动续期</label>' +
      '<button class="danger" onclick="deleteCert(\'' +
      cert.id +
      "')\">删除证书</button>";
    $("certList").appendChild(card);
    card.querySelector('[data-field="mode"]').value = cert.mode || "file";
    const caField = card.querySelector('[data-field="ca"]');
    if (caField) caField.value = cert.ca || "letsencrypt";
    card.querySelector('[data-field="auto_renew"]').checked = !!cert.auto_renew;
    const utlsField = card.querySelector('[data-field="utls_fingerprint"]');
    if (utlsField) utlsField.value = cert.utls_fingerprint || "chrome";
  }
  $("certList").querySelectorAll("input, select").forEach((el) => {
    el.oninput = () => {
      const cert = state.certificates.find((c) => c.id === el.dataset.cert);
      cert[el.dataset.field] = el.type === "checkbox" ? el.checked : el.value;
      if (el.dataset.field === "mode") {
        render();
      }
    };
  });
  $("certList").querySelectorAll("textarea").forEach((el) => {
    el.oninput = () => {
      const cert = state.certificates.find((c) => c.id === el.dataset.cert);
      cert[el.dataset.field] = el.value;
    };
  });
}

function buildCertificateModeFields(cert, mode) {
  if (mode === "reality") {
    return (
      '<label>Reality 端口 <input value="' +
      escapeAttr(cert.reality_port || "443") +
      '" data-cert="' +
      cert.id +
      '" data-field="reality_port" type="number" min="1" max="65535"></label>' +
      '<label>Reality Private Key <input value="' +
      escapeAttr(cert.reality_private_key || "") +
      '" data-cert="' +
      cert.id +
      '" data-field="reality_private_key"></label>' +
      '<label>Reality Public Key <input value="' +
      escapeAttr(cert.reality_public_key || "") +
      '" data-cert="' +
      cert.id +
      '" data-field="reality_public_key"></label>' +
      '<label>Reality Short ID <input value="' +
      escapeAttr(cert.reality_short_id || "") +
      '" data-cert="' +
      cert.id +
      '" data-field="reality_short_id"></label>' +
      '<label>uTLS 指纹 <select data-cert="' +
      cert.id +
      '" data-field="utls_fingerprint"><option value="chrome">chrome</option><option value="firefox">firefox</option><option value="safari">safari</option><option value="edge">edge</option><option value="ios">ios</option><option value="android">android</option></select></label>' +
      '<label>Reality 最大时间差 <input value="' +
      escapeAttr(cert.reality_max_time_diff || "1m") +
      '" data-cert="' +
      cert.id +
      '" data-field="reality_max_time_diff"></label>'
    );
  }

  let html = "";
  if (mode === "acme_http" || mode === "acme_tls_alpn" || mode === "acme_dns") {
    html +=
      '<label>邮箱 <input value="' +
      escapeAttr(cert.email || "") +
      '" data-cert="' +
      cert.id +
      '" data-field="email"></label>' +
      '<label>CA <select data-cert="' +
      cert.id +
      '" data-field="ca">' +
      '<option value="letsencrypt">Lets Encrypt</option><option value="zerossl">ZeroSSL</option><option value="buypass">Buypass</option><option value="ssl.com">SSL.com</option>' +
      "</select></label>";
  }
  if (mode === "acme_http") {
    html +=
      '<label>Webroot <input value="' +
      escapeAttr(cert.webroot || "") +
      '" data-cert="' +
      cert.id +
      '" data-field="webroot" placeholder="/var/www/html"></label>';
  }
  if (mode === "acme_dns") {
    html +=
      '<label>DNS Provider <input value="' +
      escapeAttr(cert.dns_provider || "") +
      '" data-cert="' +
      cert.id +
      '" data-field="dns_provider" placeholder="dns_cf / dns_ali / dns_dp"></label>';
  }
  html +=
    '<label>证书路径 <input value="' +
    escapeAttr(cert.cert_path || "") +
    '" data-cert="' +
    cert.id +
    '" data-field="cert_path"></label>' +
    '<label>私钥路径 <input value="' +
    escapeAttr(cert.key_path || "") +
    '" data-cert="' +
    cert.id +
    '" data-field="key_path"></label>';
  return html;
}

function buildCertificateExtraFields(cert, mode) {
  if (mode !== "acme_dns") return "";
  return (
    '<label>DNS 环境变量 <textarea data-cert="' +
    cert.id +
    '" data-field="dns_credentials" placeholder="CF_Token=...&#10;CF_Account_ID=...">' +
    escapeHTML(cert.dns_credentials || "") +
    "</textarea></label>"
  );
}

async function deleteCert(id) {
  state = await fetch("/api/certificate/" + encodeURIComponent(id), { method: "DELETE" }).then((r) => r.json());
  render();
}

async function issueCert(id) {
  await saveState({ render: false });
  const res = await fetch("/api/certificate/" + encodeURIComponent(id) + "/issue", { method: "POST" });
  const body = await res.json();
  if (!res.ok) $("status").textContent = body.error || "证书签发失败";
  await loadState();
}

async function refreshCert(id) {
  await saveState({ render: false });
  await fetch("/api/certificate/" + encodeURIComponent(id) + "/status", { method: "POST" });
  await loadState();
}

async function generateCertRealityKeypair(id) {
  await saveState({ render: false });
  state = await fetch("/api/certificate/" + encodeURIComponent(id) + "/reality-keypair", { method: "POST" }).then((r) => r.json());
  render();
}

function renderEditor() {
  const svc = currentService();
  if (!svc) {
    $("editPane").classList.add("hidden");
    return;
  }
  $("editPane").classList.remove("hidden");
  $("serviceTitle").textContent = svc.name || "服务详情";
  $("svcName").value = svc.name || "";
  $("svcProtocol").value = svc.protocol || "vless";
  $("svcListen").value = svc.listen || "::";
  $("svcPort").value = svc.port || 443;
  $("svcTransport").value = svc.transport || "tcp";
  $("svcPath").value = svc.path || "";
  $("svcMethod").value = svc.method || "";
  $("svcEnabled").checked = !!svc.enabled;
  $("svcTLS").checked = !!svc.tls;
  $("svcCert").innerHTML =
    '<option value="">未选择</option>' +
    (state.certificates || [])
      .map((c) => '<option value="' + c.id + '">' + escapeHTML(c.name || c.id) + "</option>")
      .join("");
  $("svcCert").value = svc.cert_id || "";
  renderUsers(svc);
}

function renderUsers(svc) {
  $("userList").innerHTML = "";
  for (const user of svc.users || []) {
    const card = document.createElement("div");
    card.className = "card stack";
    card.innerHTML =
      '<div class="grid">' +
      '<label>用户名 <input value="' +
      escapeAttr(user.name || "") +
      '" data-user="' +
      user.id +
      '" data-field="name"></label>' +
      '<label>UUID <input value="' +
      escapeAttr(user.uuid || "") +
      '" data-user="' +
      user.id +
      '" data-field="uuid"></label>' +
      '<label>密码 <input value="' +
      escapeAttr(user.password || "") +
      '" data-user="' +
      user.id +
      '" data-field="password"></label>' +
      '<label>VLESS Flow <select data-user="' +
      user.id +
      '" data-field="flow">' +
      '<option value="">none</option><option value="xtls-rprx-vision">xtls-rprx-vision</option>' +
      "</select></label>" +
      "</div>" +
      '<button class="danger" onclick="deleteUser(\'' +
      user.id +
      "')\">删除用户</button>";
    $("userList").appendChild(card);
    card.querySelector('[data-field="flow"]').value = user.flow || "";
  }
  $("userList").querySelectorAll("input, select").forEach((el) => {
    el.oninput = () => {
      const user = currentService().users.find((u) => u.id === el.dataset.user);
      user[el.dataset.field] = el.value;
      renderPreviewUsers();
    };
  });
}

function updatePanel() {
  state.panel.host = $("host").value;
  state.panel.dns_strategy = $("dnsStrategy").value;
  state.panel.sub_token = $("subToken").value;
  state.panel.sing_box_path = $("singBoxPath").value;
  state.panel.runtime_config_path = $("runtimeConfigPath").value;
  state.panel.runtime_pid_path = $("runtimePIDPath").value;
  state.panel.runtime_log_path = $("runtimeLogPath").value;
  state.panel.auto_restart = $("autoRestart").checked;
  $("subUrl").textContent = location.origin + "/sub/" + state.panel.sub_token + "?user=" + encodeURIComponent(firstUserId());
}

function updateService() {
  const svc = currentService();
  if (!svc) return;
  svc.name = $("svcName").value;
  svc.protocol = $("svcProtocol").value;
  svc.listen = $("svcListen").value;
  svc.port = Number($("svcPort").value || 0);
  svc.transport = $("svcTransport").value;
  svc.path = $("svcPath").value;
  svc.method = $("svcMethod").value;
  svc.cert_id = $("svcCert").value;
  svc.enabled = $("svcEnabled").checked;
  svc.tls = $("svcTLS").checked;
  renderServices();
}

function addUser() {
  const svc = currentService();
  svc.users = svc.users || [];
  svc.users.push({
    id: "user-" + rand(),
    name: "user",
    uuid: crypto.randomUUID(),
    password: rand() + rand(),
    flow: svc.protocol === "vless" && svc.transport === "tcp" ? "xtls-rprx-vision" : "",
  });
  renderUsers(svc);
  renderPreviewUsers();
}

function deleteUser(id) {
  const svc = currentService();
  svc.users = (svc.users || []).filter((u) => u.id !== id);
  renderUsers(svc);
  renderPreviewUsers();
}

function setTab(tab) {
  currentTab = tab;
  $("tabEdit").classList.toggle("active", tab === "edit");
  $("tabPreview").classList.toggle("active", tab === "preview");
  $("editPane").classList.toggle("hidden", tab !== "edit");
  $("previewPane").classList.toggle("hidden", tab !== "preview");
  if (tab === "preview") refreshPreview();
}

async function refreshPreview() {
  await saveState({ render: false });
  const type = $("previewType").value;
  const user = $("previewUser").value || firstUserId();
  if (type === "server") {
    $("preview").value = await fetch("/export/server.json").then((r) => r.text());
  } else if (type === "client") {
    $("preview").value = await fetch("/export/client.json?user=" + encodeURIComponent(user)).then((r) => r.text());
  } else {
    const sub = location.origin + "/sub/" + state.panel.sub_token + "?user=" + encodeURIComponent(user);
    const body = await fetch(sub).then((r) => r.text());
    $("preview").value = sub + "\n\n" + body;
  }
}

async function validateServer() {
  await saveState({ render: false });
  const result = await fetch("/api/validate/server", { method: "POST" }).then((r) => r.json());
  $("status").textContent = result.ok ? "服务端配置检测通过" : "服务端配置检测失败";
  if (currentTab !== "preview") setTab("preview");
  $("previewType").value = "server";
  $("preview").value = (result.message || "") + "\n\n" + (result.output || "");
}

async function applyRuntime() {
  await saveState({ render: false });
  const result = await fetch("/api/runtime/apply", { method: "POST" }).then((r) => r.json());
  $("status").textContent = result.ok ? "已应用到 sing-box" : "应用失败";
  showRuntimeResult(result);
}

async function stopRuntime() {
  const result = await fetch("/api/runtime/stop", { method: "POST" }).then((r) => r.json());
  $("status").textContent = "sing-box 已停止";
  showRuntimeResult(result);
}

async function refreshRuntimeStatus() {
  const result = await fetch("/api/runtime/status").then((r) => r.json());
  showRuntimeResult(result);
}

function showRuntimeResult(result) {
  $("runtimeStatus").textContent =
    "状态: " +
    (result.running ? "运行中" : "未运行") +
    (result.pid ? "\nPID: " + result.pid : "") +
    "\n消息: " +
    (result.message || "") +
    "\n配置: " +
    (result.config_path || state.panel.runtime_config_path || "") +
    "\n日志: " +
    (result.log_path || state.panel.runtime_log_path || "");
  if (currentTab !== "preview") setTab("preview");
  $("preview").value = JSON.stringify(result, null, 2) + (result.log_tail ? "\n\n--- log tail ---\n" + result.log_tail : "");
}

function renderPreviewUsers() {
  const selected = $("previewUser").value;
  const users = [];
  for (const svc of state.services || []) {
    for (const user of svc.users || []) {
      users.push({ id: user.id, name: user.name + " / " + svc.name });
    }
  }
  $("previewUser").innerHTML = users.map((u) => '<option value="' + u.id + '">' + escapeHTML(u.name) + "</option>").join("");
  $("previewUser").value = users.some((u) => u.id === selected) ? selected : firstUserId();
}

function currentService() {
  return (state.services || []).find((s) => s.id === currentServiceId);
}

function firstUserId() {
  for (const svc of state.services || []) {
    if (svc.users?.length) return svc.users[0].id;
  }
  return "";
}

function normalizeClientState() {
  state.updated_at = new Date().toISOString();
  for (const svc of state.services || []) {
    svc.port = Number(svc.port || 0);
    svc.users = svc.users || [];
  }
}

function rand() {
  return Math.random().toString(16).slice(2, 10);
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function escapeAttr(value) {
  return escapeHTML(value);
}

loadState();
