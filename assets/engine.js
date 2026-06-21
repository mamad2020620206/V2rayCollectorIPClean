/* =====================================================================
 *  V2Ray Config Engine  —  مشترک بین نسخه گیت‌هاب و نسخه شخصی
 *  پارس، اعتبارسنجی، حذف تکراری و تزریق آی‌پی تمیز به کانفیگ‌ها
 *  پشتیبانی: vmess:// vless:// trojan:// ss://
 * ===================================================================== */
(function (global) {
  "use strict";

  /* ---------- Base64 امن برای یونیکد ---------- */
  function b64EncodeUnicode(str) {
    return btoa(
      encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (_, p1) =>
        String.fromCharCode("0x" + p1)
      )
    );
  }
  function b64DecodeUnicode(str) {
    // نرمال‌سازی base64url و padding
    str = str.replace(/-/g, "+").replace(/_/g, "/");
    while (str.length % 4) str += "=";
    try {
      return decodeURIComponent(
        Array.prototype.map
          .call(atob(str), (c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
    } catch (e) {
      return atob(str);
    }
  }

  /* ---------- استخراج همه‌ی کانفیگ‌ها از یک متن/HTML ---------- */
  function extractConfigs(text) {
    if (!text) return [];
    // حذف entity های HTML رایج
    const cleaned = text
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/&#x2F;/g, "/");
    const re = /(vmess|vless|trojan|ss):\/\/[^\s<>"'`\\]+/gi;
    const matches = cleaned.match(re) || [];
    // تمیزکاری انتهای رشته از کاراکترهای نامعتبر
    return matches.map((m) => m.replace(/[.,;)\]}>]+$/g, ""));
  }

  /* ---------- شناسایی نوع ---------- */
  function protocolOf(uri) {
    const m = /^(vmess|vless|trojan|ss):\/\//i.exec(uri);
    return m ? m[1].toLowerCase() : null;
  }

  /* ---------- پارس برای اعتبارسنجی ساختاری ---------- */
  function parse(uri) {
    const proto = protocolOf(uri);
    if (!proto) return null;
    try {
      if (proto === "vmess") {
        const json = JSON.parse(b64DecodeUnicode(uri.slice(8)));
        if (!json.add || !json.port || !json.id) return null;
        return { proto, host: json.add, port: json.port, tag: json.ps || "", raw: json };
      } else {
        // vless / trojan / ss  →  URI استاندارد
        const body = uri.split("://")[1].split("#")[0];
        if (proto === "ss" && body.indexOf("@") === -1) {
          // فرمت کاملاً base64: ss://BASE64#name
          const dec = b64DecodeUnicode(body);
          const at = dec.lastIndexOf("@");
          if (at === -1) return null;
          const hp = dec.slice(at + 1).split(":");
          if (!hp[0] || !hp[1]) return null;
          return { proto, host: hp[0], port: hp[1], tag: "", raw: uri };
        }
        const u = new URL(uri);
        if (!u.hostname || !u.port) return null;
        return { proto, host: u.hostname, port: u.port, tag: decodeURIComponent((u.hash || "").slice(1)), raw: uri };
      }
    } catch (e) {
      return null;
    }
  }

  function isValid(uri) {
    return parse(uri) !== null;
  }

  /* ---------- حذف تکراری ---------- */
  function dedupe(list) {
    const seen = new Set();
    const out = [];
    for (const c of list) {
      const key = c.trim();
      if (key && !seen.has(key)) {
        seen.add(key);
        out.push(key);
      }
    }
    return out;
  }

  /* ---------- آی‌پی/دامنه تمیز: استخراج آدرس و پورت اختیاری ---------- */
  function parseCleanEntry(entry) {
    // پشتیبانی از  1.2.3.4  یا  1.2.3.4:8443  یا  domain.com:2053
    const s = entry.trim();
    if (!s) return null;
    const m = /^([^\s:]+)(?::(\d+))?$/.exec(s);
    if (!m) return null;
    return { ip: m[1], port: m[2] ? parseInt(m[2], 10) : null };
  }

  /* ---------- تزریق آی‌پی تمیز ---------- */
  function injectVmess(uri, clean, label) {
    const json = JSON.parse(b64DecodeUnicode(uri.slice(8)));
    const originalAddr = json.add;
    const tls = (json.tls || "").toLowerCase();
    // حفظ SNI/Host اصلی به‌عنوان دامنه‌ی واقعی (تکنیک کلودفلر)
    if (tls === "tls" || tls === "reality") {
      if (!json.sni) json.sni = json.host || originalAddr;
    }
    if (!json.host && (json.net === "ws" || json.net === "h2" || json.net === "grpc")) {
      json.host = originalAddr;
    }
    json.add = clean.ip;
    if (clean.port) json.port = clean.port;
    json.ps = (json.ps || "config") + " 🧹 " + label;
    return "vmess://" + b64EncodeUnicode(JSON.stringify(json));
  }

  function injectUriStyle(uri, clean, label, proto) {
    // vless / trojan با ساختار  proto://id@host:port?params#name
    if (proto === "ss" && uri.indexOf("@") === -1) {
      // فرمت کاملاً base64 → بازنویسی به فرمت @host
      const hashIdx = uri.indexOf("#");
      const name = hashIdx > -1 ? uri.slice(hashIdx + 1) : "";
      let body = uri.slice(5, hashIdx > -1 ? hashIdx : undefined);
      let dec = b64DecodeUnicode(body);
      const at = dec.lastIndexOf("@");
      const cred = dec.slice(0, at);
      const hp = dec.slice(at + 1).split(":");
      const port = clean.port || hp[1];
      const newBody = b64EncodeUnicode(cred + "@" + clean.ip + ":" + port);
      return "ss://" + newBody + "#" + encodeURIComponent(decodeURIComponent(name) + " 🧹 " + label);
    }

    const u = new URL(uri);
    const sp = u.searchParams;
    const security = (sp.get("security") || "").toLowerCase();
    const originalHost = u.hostname;
    // حفظ SNI و Host اصلی
    if (security === "tls" || security === "reality" || security === "xtls") {
      if (!sp.get("sni")) sp.set("sni", originalHost);
    }
    if (!sp.get("host") && (sp.get("type") === "ws" || sp.get("type") === "grpc" || sp.get("type") === "httpupgrade")) {
      sp.set("host", originalHost);
    }
    u.hostname = clean.ip;
    if (clean.port) u.port = String(clean.port);
    const baseName = decodeURIComponent((u.hash || "").slice(1)) || proto;
    u.hash = encodeURIComponent(baseName + " 🧹 " + label);
    u.search = sp.toString();
    return u.toString();
  }

  function inject(uri, clean, label) {
    const proto = protocolOf(uri);
    try {
      if (proto === "vmess") return injectVmess(uri, clean, label);
      return injectUriStyle(uri, clean, label, proto);
    } catch (e) {
      return null;
    }
  }

  /* ---------- خروجی نهایی: ترکیب کانفیگ‌ها × آی‌پی‌های تمیز ---------- */
  function build(configs, cleanIPs, opts) {
    opts = opts || {};
    const validConfigs = dedupe(configs).filter(isValid);
    const cleans = (cleanIPs || []).map(parseCleanEntry).filter(Boolean);

    const out = [];
    const report = { sourceValid: validConfigs.length, generated: 0, perConfig: cleans.length || 1 };

    if (cleans.length === 0) {
      // بدون آی‌پی تمیز → خود کانفیگ‌ها برگردانده می‌شوند
      for (const c of validConfigs) out.push(c);
    } else {
      for (const c of validConfigs) {
        let i = 1;
        for (const clean of cleans) {
          const label = clean.ip + (clean.port ? ":" + clean.port : "") + " #" + i++;
          const injected = inject(c, clean, label);
          if (injected) out.push(injected);
        }
      }
    }
    const finalList = dedupe(out);
    report.generated = finalList.length;
    return { configs: finalList, report };
  }

  /* ---------- ساخت محتوای ساب (base64) ---------- */
  function toSubscription(configs) {
    return b64EncodeUnicode(configs.join("\n"));
  }

  const Engine = {
    b64EncodeUnicode,
    b64DecodeUnicode,
    extractConfigs,
    protocolOf,
    parse,
    isValid,
    dedupe,
    parseCleanEntry,
    inject,
    build,
    toSubscription,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = Engine;
  global.V2Engine = Engine;
})(typeof window !== "undefined" ? window : globalThis);
