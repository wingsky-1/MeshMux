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
