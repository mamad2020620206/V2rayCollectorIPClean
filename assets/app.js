/* =====================================================================
 *  app.js  —  نسخه گیت‌هاب (کلاینت-ساید، LocalStorage + پروکسی CORS)
 * ===================================================================== */
(function () {
  "use strict";
  const E = window.V2Engine;
  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);
  const KEY = "v2ray_collector_state_v1";

  /* ---------- وضعیت ---------- */
  const state = {
    channels: [],
    cleanIPs: [],
    perChannel: 3,
    proxy: "https://api.allorigins.win/raw?url=",
    customProxy: "",
    onlyTls: false,
    theme: "dark",
    fetched: [], // کانفیگ‌های جمع‌آوری‌شده
  };

  function load() {
    try {
      const s = JSON.parse(localStorage.getItem(KEY) || "{}");
      Object.assign(state, s);
    } catch (e) {}
  }
  function save() {
    localStorage.setItem(KEY, JSON.stringify(state));
  }

  /* ---------- ابزار ---------- */
  function toast(msg) {
    const t = $("#toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(t._t);
    t._t = setTimeout(() => t.classList.remove("show"), 2400);
  }
  function logLine(msg, cls) {
    const log = $("#progressLog");
    log.hidden = false;
    const div = document.createElement("div");
    div.className = cls || "info";
    div.textContent = msg;
    log.appendChild(div);
    log.scrollTop = log.scrollHeight;
  }
  function copy(text) {
    navigator.clipboard.writeText(text).then(
      () => toast("کپی شد ✅"),
      () => {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
        toast("کپی شد ✅");
      }
    );
  }
  function normalizeChannel(input) {
    let s = input.trim();
    s = s.replace(/^https?:\/\/t\.me\//i, "").replace(/^https?:\/\/telegram\.me\//i, "");
    s = s.replace(/^@/, "").replace(/^s\//, "").replace(/\/+$/, "");
    s = s.split("/")[0].split("?")[0];
    return s;
  }

  /* ---------- رندر ---------- */
  function renderChannels() {
    const list = $("#channelList");
    list.innerHTML = "";
    $("#channelEmpty").style.display = state.channels.length ? "none" : "block";
    state.channels.forEach((ch, i) => {
      const li = document.createElement("li");
      li.innerHTML = `<div><span class="ch-name">@${ch}</span></div>
        <button class="del" data-i="${i}" title="حذف">×</button>`;
      list.appendChild(li);
    });
    $$("#channelList .del").forEach((b) =>
      b.addEventListener("click", () => {
        state.channels.splice(+b.dataset.i, 1);
        save();
        renderChannels();
      })
    );
  }

  /* ---------- دریافت از تلگرام ---------- */
  function proxify(url) {
    const p = state.customProxy || state.proxy;
    if (!p) return url;
    return p + encodeURIComponent(url);
  }
  async function fetchChannel(ch) {
    const url = "https://t.me/s/" + ch;
    const res = await fetch(proxify(url), { headers: { "Accept": "text/html" } });
    if (!res.ok) throw new Error("HTTP " + res.status);
    return await res.text();
  }

  async function doFetch() {
    if (!state.channels.length) return toast("اول کانال اضافه کنید");
    state.fetched = [];
    $("#progressLog").innerHTML = "";
    logLine("شروع جمع‌آوری از " + state.channels.length + " کانال...", "info");

    for (const ch of state.channels) {
      try {
        logLine("📡 دریافت @" + ch + " ...", "info");
        const html = await fetchChannel(ch);
        let configs = E.extractConfigs(html);
        configs = E.dedupe(configs).filter(E.isValid);
        if (state.onlyTls) {
          configs = configs.filter((c) => /tls|reality|security=tls|security=reality/i.test(c) || c.startsWith("vmess://"));
        }
        // جدیدترین‌ها انتهای صفحه هستند → آخرین N تا
        const picked = configs.slice(-state.perChannel);
        state.fetched.push(...picked);
        logLine("  ✓ " + picked.length + " کانفیگ از @" + ch, "ok");
      } catch (e) {
        logLine("  ✗ خطا در @" + ch + " : " + e.message, "err");
      }
    }
    state.fetched = E.dedupe(state.fetched);
    logLine("مجموع کانفیگ جمع‌آوری‌شده: " + state.fetched.length, "info");
    if (!state.fetched.length) {
      logLine("⚠ اگر همه کانال‌ها خطا دادند، پروکسی CORS را در تنظیمات عوض کنید.", "err");
    }
    save();
    toast("جمع‌آوری انجام شد");
  }

  /* ---------- تولید نهایی ---------- */
  function doBuild() {
    if (!state.fetched.length) return toast("اول از کانال‌ها جمع‌آوری کنید");
    const { configs, report } = E.build(state.fetched, state.cleanIPs, {});
    $("#stats").hidden = false;
    $("#statSources").textContent = report.sourceValid;
    $("#statClean").textContent = state.cleanIPs.length;
    $("#statFinal").textContent = report.generated;

    const sub = E.toSubscription(configs);
    $("#subOutput").value = sub;
    $("#rawOutput").value = configs.join("\n");
    $("#outputBlock").hidden = false;
    window._lastConfigs = configs;
    window._lastSub = sub;
    toast(report.generated + " کانفیگ نهایی ساخته شد ✅");
  }

  /* ---------- تب‌ها ---------- */
  function initTabs() {
    $$(".tab").forEach((tab) =>
      tab.addEventListener("click", () => {
        $$(".tab").forEach((t) => t.classList.remove("active"));
        $$(".panel").forEach((p) => p.classList.remove("active"));
        tab.classList.add("active");
        $("#tab-" + tab.dataset.tab).classList.add("active");
      })
    );
  }

  /* ---------- تم ---------- */
  function applyTheme() {
    document.documentElement.classList.toggle("light", state.theme === "light");
    $("#themeToggle").textContent = state.theme === "light" ? "☀️" : "🌙";
  }

  /* ---------- راهنما ---------- */
  function renderGuide() {
    $("#guideContent").innerHTML = `
      <p>این صفحه به‌صورت کامل در مرورگر شما اجرا می‌شود و داده‌ها در حافظه‌ی مرورگر (LocalStorage) ذخیره می‌گردند.</p>

      <h3>۱) استفاده روزمره</h3>
      <ol>
        <li>در تب <b>کانال‌ها</b> آدرس کانال‌های عمومی تلگرام را اضافه کنید (مثل <code>@free_v2ray</code>).</li>
        <li>تعداد جدیدترین کانفیگ‌ها از هر کانال را تعیین کنید (پیش‌فرض ۳).</li>
        <li>در تب <b>آی‌پی تمیز</b> آدرس‌های تمیز کلودفلر را وارد و ذخیره کنید.</li>
        <li>در تب <b>تولید</b> ابتدا «جمع‌آوری از کانال‌ها» و سپس «تولید کانفیگ نهایی» را بزنید.</li>
        <li>لینک ساب را کپی کنید و در <b>هیدیفای</b> یا <b>V2rayNG</b> به‌عنوان Subscription اضافه کنید، یا کانفیگ‌های خام را مستقیم Import کنید.</li>
      </ol>

      <h3>۲) فعال‌سازی روی گیت‌هاب (GitHub Pages)</h3>
      <div class="step">
        <ol>
          <li>یک ریپازیتوری جدید بسازید (مثلاً <code>v2ray-collector</code>) و این فایل‌ها را در آن آپلود کنید.</li>
          <li>به <b>Settings → Pages</b> بروید و در بخش Source گزینه <code>Deploy from a branch</code> و شاخه <code>main</code> / پوشه <code>/ (root)</code> را انتخاب کنید.</li>
          <li>بعد از چند دقیقه آدرسی مثل <code>https://USERNAME.github.io/v2ray-collector/</code> فعال می‌شود.</li>
        </ol>
      </div>

      <h3>۳) جمع‌آوری کاملاً خودکار با GitHub Actions (پیشنهادی)</h3>
      <p>به‌جای جمع‌آوری دستی در مرورگر، می‌توانید بگذارید گیت‌هاب هر چند ساعت یک‌بار خودش کانفیگ‌ها را جمع کند و فایل ساب را داخل ریپو بسازد. لینک ساب ثابت و دائمی خواهد بود:</p>
      <div class="step">
        <ol>
          <li>فایل‌های <code>scripts/collect.py</code> و <code>.github/workflows/collect.yml</code> از همین پروژه را در ریپو نگه دارید.</li>
          <li>کانال‌ها و آی‌پی‌های تمیز را در فایل <code>data/config.json</code> ویرایش کنید.</li>
          <li>به تب <b>Actions</b> در گیت‌هاب بروید و یک بار اجرا (Run workflow) را بزنید. بعد از آن طبق زمان‌بندی خودکار اجرا می‌شود.</li>
          <li>لینک ساب دائمی شما این خواهد بود:</li>
        </ol>
        <pre>https://raw.githubusercontent.com/USERNAME/REPO/main/sub/sub.txt</pre>
        <p>همین لینک را در هیدیفای/V2rayNG به‌عنوان Subscription وارد کنید. هر بار که Action اجرا شود، کانفیگ‌های شما به‌روز می‌شوند.</p>
      </div>

      <h3>۴) آی‌پی تمیز چطور تزریق می‌شود؟</h3>
      <p>آدرس اتصال کانفیگ (<code>add</code> در vmess یا hostname در vless/trojan) با آی‌پی تمیز جایگزین می‌شود، اما <b>SNI</b> و <b>Host</b> اصلی (دامنه‌ی واقعی) حفظ می‌گردد تا روی کلودفلر کار کند. از هر کانفیگ به تعداد آی‌پی‌های تمیز، یک کانفیگ جدید ساخته می‌شود.</p>

      <h3>۵) نکات</h3>
      <ul>
        <li>اگر در مرورگر هیچ کانفیگی نگرفت، در تب تنظیمات <b>پروکسی CORS</b> را عوض کنید.</li>
        <li>تست واقعی سلامت/پینگ نیاز به سوکت دارد و در مرورگر ممکن نیست؛ برای تست واقعی از <b>نسخه شخصی (هاست)</b> استفاده کنید.</li>
        <li>گزینه «فقط TLS/Reality» کانفیگ‌های امن‌تر را نگه می‌دارد.</li>
      </ul>
    `;
  }

  /* ---------- اتصال رویدادها ---------- */
  function bind() {
    $("#addChannel").addEventListener("click", () => {
      const v = normalizeChannel($("#channelInput").value);
      if (!v) return;
      if (state.channels.includes(v)) return toast("قبلاً اضافه شده");
      state.channels.push(v);
      $("#channelInput").value = "";
      save();
      renderChannels();
    });
    $("#channelInput").addEventListener("keydown", (e) => { if (e.key === "Enter") $("#addChannel").click(); });
    $("#perChannel").addEventListener("change", (e) => { state.perChannel = Math.max(1, +e.target.value || 3); save(); });

    $("#saveCleanIP").addEventListener("click", () => {
      state.cleanIPs = $("#cleanIPInput").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      save();
      toast(state.cleanIPs.length + " آی‌پی ذخیره شد");
    });
    $("#clearCleanIP").addEventListener("click", () => { $("#cleanIPInput").value = ""; state.cleanIPs = []; save(); });

    $("#fetchBtn").addEventListener("click", () => doFetch());
    $("#buildBtn").addEventListener("click", () => doBuild());

    $("#copySub").addEventListener("click", () => copy($("#subOutput").value));
    $("#copyRaw").addEventListener("click", () => copy($("#rawOutput").value));
    $("#downloadSub").addEventListener("click", () => {
      const blob = new Blob([$("#subOutput").value], { type: "text/plain" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "sub.txt";
      a.click();
    });

    $("#proxySelect").addEventListener("change", (e) => { state.proxy = e.target.value; });
    $("#saveSettings").addEventListener("click", () => {
      state.proxy = $("#proxySelect").value;
      state.customProxy = $("#customProxy").value.trim();
      state.onlyTls = $("#onlyTls").checked;
      save();
      toast("تنظیمات ذخیره شد");
    });
    $("#resetAll").addEventListener("click", () => {
      if (confirm("همه داده‌ها پاک شوند؟")) { localStorage.removeItem(KEY); location.reload(); }
    });

    $("#themeToggle").addEventListener("click", () => {
      state.theme = state.theme === "light" ? "dark" : "light";
      applyTheme();
      save();
    });
  }

  /* ---------- مقداردهی اولیه ---------- */
  function init() {
    load();
    initTabs();
    bind();
    renderChannels();
    renderGuide();
    applyTheme();
    $("#perChannel").value = state.perChannel;
    $("#cleanIPInput").value = state.cleanIPs.join("\n");
    $("#proxySelect").value = state.proxy;
    $("#customProxy").value = state.customProxy;
    $("#onlyTls").checked = state.onlyTls;
    $("#storageNote").textContent =
      "حجم داده ذخیره‌شده: " + ((localStorage.getItem(KEY) || "").length / 1024).toFixed(1) + " کیلوبایت";
  }
  document.addEventListener("DOMContentLoaded", init);
})();
