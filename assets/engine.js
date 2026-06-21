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

  /* ---------- آی‌پی/دامنه تمیز ----------
     فقط آدرس استخراج می‌شود. پورت کانفیگ اصلی هرگز تغییر نمی‌کند
     (اگر کاربر ip:port بدهد، فقط بخش ip استفاده می‌شود). */
  function parseCleanEntry(entry) {
    const s = entry.trim();
    if (!s) return null;
    // فقط بخش آدرس (قبل از : اول) — پورت نادیده گرفته می‌شود
    const ip = s.split(":")[0].trim();
    if (!ip) return null;
    return { ip: ip };
  }

  /* ---------- تزریق آی‌پی تمیز ----------
     مطابق منطق آزموده‌شده: فقط آدرس عوض می‌شود؛ پورت، SNI، Host و
     همه‌ی پارامترها دست‌نخورده می‌مانند تا کانفیگ سالم بماند. */
  function injectVmess(uri, clean, label) {
    const json = JSON.parse(b64DecodeUnicode(uri.slice(8)));
    json.add = clean.ip; // فقط آدرس
    const oldName = (json.ps || "Config").split(" | ")[0];
    json.ps = oldName + " | " + clean.ip + " " + label;
    return "vmess://" + b64EncodeUnicode(JSON.stringify(json));
  }

  function injectUriStyle(uri, clean, label, proto) {
    // ss با فرمت کاملاً base64:  ss://BASE64#name
    if (proto === "ss" && uri.split("://")[1].split("#")[0].indexOf("@") === -1) {
      const hashIdx = uri.indexOf("#");
      const name = hashIdx > -1 ? uri.slice(hashIdx + 1) : "";
      const body = uri.slice(5, hashIdx > -1 ? hashIdx : undefined);
      const dec = b64DecodeUnicode(body);
      const at = dec.lastIndexOf("@");
      const cred = dec.slice(0, at);
      const port = dec.slice(at + 1).split(":")[1]; // پورت اصلی حفظ می‌شود
      const newBody = b64EncodeUnicode(cred + "@" + clean.ip + ":" + port);
      const oldName = decodeURIComponent(name).split(" | ")[0] || "Config";
      return "ss://" + newBody + "#" + encodeURIComponent(oldName + " | " + clean.ip + " " + label);
    }
    // vless / trojan / ss(@host):  فقط host بین @ و :port عوض می‌شود
    // ساختار:  proto://userinfo@HOST:port?params#name
    const re = /^((?:vless|trojan|ss):\/\/[^@]+@)([^:\/?#]+)(:\d+[^#]*)?(#.*)?$/i;
    return uri.replace(re, function (m, p1, p2, p3, p4) {
      const params = p3 || ""; // شامل :port و ?query — دست‌نخورده
      const oldName = (p4 ? decodeURIComponent(p4.slice(1)) : "Config").split(" | ")[0];
      const newName = "#" + encodeURIComponent(oldName + " | " + clean.ip + " " + label);
      return p1 + clean.ip + params + newName;
    });
  }

  function inject(uri, clean, label) {
    const proto = protocolOf(uri);
    try {
      if (proto === "vmess") return injectVmess(uri, clean, label);
      return injectUriStyle(uri, clean, label, proto);
    } catch (e) {
      return uri; // در صورت خطا، خود کانفیگ اصلی برگردانده می‌شود
    }
  }

  /* ---------- خروجی نهایی: ترکیب کانفیگ‌ها × آی‌پی‌های تمیز ---------- */
  function build(configs, cleanIPs, opts) {
    opts = opts || {};
    const validConfigs = dedupe(configs).filter(isValid);
    const cleans = (cleanIPs || []).map(parseCleanEntry).filter(Boolean);

    const out = [];
    const report = { sourceValid: validConfigs.length, generated: 0, perConfig: cleans.length || 1 };

    const emojis = ["🚀", "🔥", "⚡", "💎", "👑", "🌟", "🎯", "🛡️", "🌐", "🛸"];
    if (cleans.length === 0) {
      // بدون آی‌پی تمیز → خود کانفیگ‌ها برگردانده می‌شوند
      for (const c of validConfigs) out.push(c);
    } else {
      for (const c of validConfigs) {
        cleans.forEach((clean, idx) => {
          const label = emojis[idx % emojis.length] + "-" + (idx + 1);
          const injected = inject(c, clean, label);
          if (injected) out.push(injected);
        });
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
