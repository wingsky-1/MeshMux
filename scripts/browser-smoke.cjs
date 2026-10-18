const { chromium } = require("playwright");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");
const state = fs.mkdtempSync(path.join(os.tmpdir(), "meshmux-browser-"));
const origin = "http://127.0.0.1:19080";
const app = spawn(
  process.env.MESHMUX_WEB_BINARY || "/tmp/meshmux-web",
  [
    "--listen",
    "127.0.0.1:19080",
    "--origin",
    origin,
    "--data-dir",
    state,
    "--dev-http",
  ],
  { stdio: ["ignore", "inherit", "inherit"] },
);
let browser;
let page;
let appFailure;
app.on("error", (error) => {
  appFailure = error;
});
app.on("exit", (code) => {
  if (code) appFailure = new Error("Web exited with code " + code);
});
(async () => {
  for (let i = 0; i < 100; i++) {
    if (appFailure) throw appFailure;
    try {
      if ((await fetch(origin + "/healthz")).ok) break;
    } catch {}
    if (i === 99) throw Error("Web did not start");
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
  });
  page = await ctx.newPage();
  const token = fs
    .readFileSync(path.join(state, "bootstrap.token"), "utf8")
    .trim();
  fs.mkdirSync("artifacts/web-preview", { recursive: true });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const first = await page.goto(origin + "/setup");
  if (
    !first.headers()["content-security-policy"] ||
    first.headers()["cache-control"] !== "no-store"
  )
    throw Error("missing security headers");
  await page.locator("#bootstrap").fill(token);
  await page.locator("#password").fill("isolated-browser-password-47!");
  await page.getByRole("button", { name: "初始化管理员" }).click();
  await page.waitForURL("**/login");
  await page.screenshot({
    path: "artifacts/web-preview/login-desktop.png",
    fullPage: true,
  });
  await page.locator("#password").fill("wrong-password");
  await page.getByRole("button", { name: "登录控制台" }).click();
  if (!(await page.getByRole("alert").innerText()).includes("AUTH_FAILED"))
    throw Error("missing login failure feedback");
  await page.locator("#password").fill("isolated-browser-password-47!");
  await page.getByRole("button", { name: "登录控制台" }).click();
  await page.waitForURL(origin + "/");
  await page.screenshot({
    path: "artifacts/web-preview/overview-desktop.png",
    fullPage: true,
  });
  const cookie = (await ctx.cookies()).find((c) => c.name === "meshmux_dev");
  if (
    !cookie ||
    cookie.secure ||
    !cookie.httpOnly ||
    cookie.sameSite !== "Strict"
  )
    throw Error("incorrect explicit development cookie");
  await page.getByRole("link", { name: "刷新状态" }).click();
  await page.locator("#web-status").getByText(/UTC/).waitFor();
  await page
    .getByRole("link", { name: "系统设置", exact: false })
    .first()
    .click();
  await page.waitForURL("**/settings");
  await page.screenshot({
    path: "artifacts/web-preview/settings-desktop.png",
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(origin + "/");
  await page.screenshot({
    path: "artifacts/web-preview/overview-mobile.png",
    fullPage: true,
  });
  for (const path of [
    "/",
    "/nodes",
    "/subscribers",
    "/mesh",
    "/policies",
    "/tasks",
    "/logs",
    "/settings",
  ]) {
    await page.goto(origin + path);
    if (
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      )
    )
      throw Error("mobile overflow " + path);
  }
  await page.goto(origin + "/tasks");
  await page.screenshot({
    path: "artifacts/web-preview/task-mobile.png",
    fullPage: true,
  });
  await page.goto(origin + "/settings");
  await page.locator("#current").fill("isolated-browser-password-47!");
  await page.locator("#new").fill("isolated-browser-new-password-96!");
  await page.getByRole("button", { name: "修改密码并退出登录" }).click();
  await page.waitForURL("**/login");
  await page.screenshot({
    path: "artifacts/web-preview/login-mobile.png",
    fullPage: true,
  });
  await page.locator("#password").fill("isolated-browser-new-password-96!");
  await page.getByRole("button", { name: "登录控制台" }).click();
  await page.waitForURL(origin + "/");
  const csrf = await page.locator("input[name=csrf]").first().inputValue();
  const result = await page.evaluate(async (csrf) => {
    const r = await fetch("/logout", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "csrf=wrong",
    });
    return { status: r.status, html: await r.text() };
  }, csrf);
  if (result.status !== 403 || !result.html.includes("CSRF_REJECTED"))
    throw Error("csrf accepted");
  await page.getByRole("button", { name: "退出", exact: true }).click();
  await page.waitForURL("**/login");
  if (errors.length) throw Error("browser errors: " + errors.join(","));
  console.log(
    JSON.stringify({
      desktop: "1440x1000",
      mobile: "390x844",
      pages: 8,
      checks: [
        "bootstrap",
        "login failure",
        "login",
        "development HttpOnly SameSite cookie",
        "HTMX status refresh",
        "no horizontal overflow",
        "password change revocation",
        "CSRF rejection",
        "logout",
      ],
      pageErrors: errors.length,
    }),
  );
})()
  .catch(async (e) => {
    if (page) {
      await page
        .screenshot({
          path: "artifacts/web-preview/failure.png",
          fullPage: true,
        })
        .catch(() => {});
      console.error(
        "Failure page:",
        await page
          .locator("body")
          .innerText()
          .catch(() => "unavailable"),
      );
    }
    console.error(e);
    process.exitCode = 1;
  })
  .finally(async () => {
    if (browser) await browser.close();
    app.kill("SIGTERM");
  });
