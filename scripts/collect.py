#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
جمع‌آوری خودکار کانفیگ V2Ray از کانال‌های تلگرام، تزریق آی‌پی تمیز و ساخت فایل ساب.
این اسکریپت توسط GitHub Actions اجرا می‌شود و خروجی را در پوشه sub/ می‌نویسد.

ورودی:  data/config.json  →  { "channels": [...], "clean_ips": [...], "per_channel": 3, "only_tls": false }
خروجی:
    sub/sub.txt   →  لینک ساب (base64)  ← این را در هیدیفای/V2rayNG وارد کنید
    sub/raw.txt   →  کانفیگ‌های نهایی (متن خام)
    sub/report.json → آمار
"""
import os
import re
import json
import base64
import urllib.request
import urllib.parse
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(ROOT, "data", "config.json")
SUB_DIR = os.path.join(ROOT, "sub")

CONFIG_RE = re.compile(r"(vmess|vless|trojan|ss)://[^\s<>\"'`\\]+", re.IGNORECASE)
ENTITY = {"&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'", "&#x2F;": "/"}


# ----------------------- base64 helpers -----------------------
def b64decode(s: str) -> str:
    s = s.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


def b64encode(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


# ----------------------- fetch -----------------------
def fetch_channel(channel: str) -> str:
    url = "https://t.me/s/" + channel
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; v2ray-collector)"})
    with urllib.request.urlopen(req, timeout=25) as r:
        return r.read().decode("utf-8", "ignore")


def extract_configs(text: str):
    for k, v in ENTITY.items():
        text = text.replace(k, v)
    out = []
    for m in CONFIG_RE.finditer(text):
        out.append(m.group(0).rstrip(".,;)]}>"))
    return out


def dedupe(seq):
    seen, out = set(), []
    for x in seq:
        x = x.strip()
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ----------------------- validation -----------------------
def is_valid(uri: str) -> bool:
    proto = uri.split("://", 1)[0].lower()
    try:
        if proto == "vmess":
            j = json.loads(b64decode(uri[8:]))
            return bool(j.get("add") and j.get("port") and j.get("id"))
        else:
            body = uri.split("://", 1)[1].split("#")[0]
            if proto == "ss" and "@" not in body:
                # فرمت کاملاً base64:  ss://BASE64#name
                dec = b64decode(body)
                if "@" in dec:
                    hp = dec.rsplit("@", 1)[1].split(":")
                    return bool(hp[0] and len(hp) > 1 and hp[1])
                return False
            u = urllib.parse.urlparse(uri)
            return bool(u.hostname and u.port)
    except Exception:
        return False


# ----------------------- clean ip parsing -----------------------
def parse_clean(entry: str):
    # فقط آدرس استخراج می‌شود؛ پورت نادیده گرفته می‌شود (پورت کانفیگ اصلی حفظ می‌شود)
    s = entry.strip()
    if not s:
        return None
    ip = s.split(":")[0].strip()
    return {"ip": ip} if ip else None


# ----------------------- injection -----------------------
# منطق آزموده‌شده: فقط آدرس عوض می‌شود؛ پورت/SNI/Host/پارامترها دست‌نخورده می‌مانند.
INJECT_RE = re.compile(r"^((?:vless|trojan|ss)://[^@]+@)([^:/?#]+)(:\d+[^#]*)?(#.*)?$", re.IGNORECASE)


def inject_vmess(uri, clean, label):
    j = json.loads(b64decode(uri[8:]))
    j["add"] = clean["ip"]  # فقط آدرس
    old_name = (j.get("ps") or "Config").split(" | ")[0]
    j["ps"] = f"{old_name} | {clean['ip']} {label}"
    return "vmess://" + b64encode(json.dumps(j, ensure_ascii=False))


def inject_uri(uri, clean, label, proto):
    body = uri.split("://", 1)[1].split("#")[0]
    if proto == "ss" and "@" not in body:
        hash_idx = uri.find("#")
        name = uri[hash_idx + 1:] if hash_idx > -1 else ""
        b = uri[5:hash_idx] if hash_idx > -1 else uri[5:]
        dec = b64decode(b)
        cred, hp = dec.rsplit("@", 1)
        port = hp.split(":")[1]  # پورت اصلی حفظ می‌شود
        new_body = b64encode(f"{cred}@{clean['ip']}:{port}")
        old_name = (urllib.parse.unquote(name).split(" | ")[0]) or "Config"
        return f"ss://{new_body}#{urllib.parse.quote(old_name + ' | ' + clean['ip'] + ' ' + label)}"

    def repl(m):
        p1, p2, p3, p4 = m.group(1), m.group(2), m.group(3) or "", m.group(4)
        old_name = (urllib.parse.unquote(p4[1:]) if p4 else "Config").split(" | ")[0]
        new_name = "#" + urllib.parse.quote(f"{old_name} | {clean['ip']} {label}")
        return p1 + clean["ip"] + p3 + new_name

    return INJECT_RE.sub(repl, uri)


def inject(uri, clean, label):
    proto = uri.split("://", 1)[0].lower()
    try:
        if proto == "vmess":
            return inject_vmess(uri, clean, label)
        return inject_uri(uri, clean, label, proto)
    except Exception:
        return uri


# ----------------------- main -----------------------
def main():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)

    channels = cfg.get("channels", [])
    clean_ips = [c for c in (parse_clean(x) for x in cfg.get("clean_ips", [])) if c]
    per_channel = int(cfg.get("per_channel", 3))
    only_tls = bool(cfg.get("only_tls", False))

    collected = []
    log = []
    for ch in channels:
        ch = ch.strip().lstrip("@")
        try:
            html = fetch_channel(ch)
            configs = [c for c in dedupe(extract_configs(html)) if is_valid(c)]
            if only_tls:
                configs = [c for c in configs if c.startswith("vmess://") or re.search(r"tls|reality", c, re.I)]
            picked = configs[-per_channel:]
            collected.extend(picked)
            log.append(f"OK @{ch}: {len(picked)} configs")
            print(f"[OK] @{ch}: {len(picked)} configs")
        except Exception as e:
            log.append(f"ERR @{ch}: {e}")
            print(f"[ERR] @{ch}: {e}")

    collected = dedupe(collected)

    # ترکیب با آی‌پی‌های تمیز
    emojis = ["🚀", "🔥", "⚡", "💎", "👑", "🌟", "🎯", "🛡️", "🌐", "🛸"]
    final = []
    if clean_ips:
        for c in collected:
            for i, clean in enumerate(clean_ips):
                label = emojis[i % len(emojis)] + "-" + str(i + 1)
                inj = inject(c, clean, label)
                if inj:
                    final.append(inj)
    else:
        final = list(collected)
    final = dedupe(final)

    os.makedirs(SUB_DIR, exist_ok=True)
    raw = "\n".join(final)
    with open(os.path.join(SUB_DIR, "raw.txt"), "w", encoding="utf-8") as f:
        f.write(raw)
    with open(os.path.join(SUB_DIR, "sub.txt"), "w", encoding="utf-8") as f:
        f.write(b64encode(raw))
    report = {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "channels": len(channels),
        "source_configs": len(collected),
        "clean_ips": len(clean_ips),
        "final_configs": len(final),
        "log": log,
    }
    with open(os.path.join(SUB_DIR, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
