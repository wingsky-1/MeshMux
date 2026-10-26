// Only the read-only status fragment uses HTMX. Authentication uses native forms.
for (const name of ["htmx:responseError", "htmx:sendError", "htmx:timeout"]) {
  document.addEventListener(name, (event) => {
    const feedback = document.getElementById("status-feedback");
    if (!feedback) return;
    const status = event.detail.xhr?.status;
    feedback.textContent =
      status === 401
        ? "会话已失效，请刷新页面并重新登录。"
        : "状态刷新失败，请检查连接后重试。";
  });
}
document.addEventListener("htmx:afterSwap", () => {
  const feedback = document.getElementById("status-feedback");
  if (feedback) feedback.textContent = "";
});

// Nodes page: the role radio switches between the port fields (Line/Out) and
// the URL field (external HTTP proxy). Progressive: without this script both
// groups are visible and the server validates by role.
for (const role of document.querySelectorAll('#enroll input[name="role"]')) {
  role.addEventListener("change", syncNodeRoleFields);
}
syncNodeRoleFields();

function syncNodeRoleFields() {
  const form = document.querySelector("#enroll form");
  if (!form) return;
  const portFields = form.querySelector("#node-port-fields");
  const proxyFields = form.querySelector("#http-proxy-fields");
  const selected = form.querySelector('input[name="role"]:checked');
  const external = !!selected && selected.value === "http";
  if (portFields) portFields.hidden = external;
  if (proxyFields) proxyFields.hidden = !external;
  const vless = form.querySelector("#vless_port");
  const ssh = form.querySelector("#ssh_port");
  const proxyURL = form.querySelector("#proxy_url");
  if (vless) vless.required = !external;
  if (ssh) ssh.required = !external;
  if (proxyURL) proxyURL.required = external;
}
