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

// Shared one-click copy: any element with data-copy-target="#id" copies the
// text of that target; any <code data-copy> copies its own text. Progressive:
// without JavaScript the values stay selectable as before.
document.addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-copy-target],code[data-copy]");
  if (!trigger) return;
  const source = trigger.dataset.copyTarget
    ? document.querySelector(trigger.dataset.copyTarget)
    : trigger;
  if (!source) return;
  const text = source.textContent.trim();
  const done = () => {
    const original = trigger.textContent;
    trigger.textContent = "已复制";
    trigger.disabled = true;
    setTimeout(() => {
      trigger.textContent = original;
      trigger.disabled = false;
    }, 1500);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
  } else {
    fallbackCopy(text, done);
  }
});

function fallbackCopy(text, done) {
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  try {
    document.execCommand("copy");
    done();
  } finally {
    area.remove();
  }
}

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
