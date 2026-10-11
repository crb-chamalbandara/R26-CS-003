"""
Component 1 - Static Extension Profile

The classifier answers one question (how malicious does this look?). A reviewer
needs the other half: what *is* this extension, and what is it set up to do?
This module reads the manifest and the code and writes that down as plain facts:

  * where its code runs (service worker, declared and runtime-registered
    content scripts, which JS world, which sites)
  * what it schedules (alarms), what it phones (domains found in its code, the
    uninstall URL) and how much it relies on dynamic code (eval, remote scripts)
  * which sensitive browser APIs its code calls
  * the size and shape of the package (file types, binaries, rule sets)

Nothing here changes a score. It is evidence for the report, built from the
same inputs the classifier gets plus, when the unpacked folder is available,
the files themselves (the classifier input is capped at 300 KB of JavaScript,
which a large extension exceeds).

No network access, no execution of the extension: it is only text analysis.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Safety caps so a hostile or enormous package cannot stall an analysis.
_MAX_FILE_BYTES   = 3_000_000
_MAX_TOTAL_BYTES  = 12_000_000
_MAX_RULE_BYTES   = 12_000_000
_MAX_HOSTS        = 25
_MAX_SAMPLES      = 3

# ── What counts as a "sensitive" browser API, and how to spot a call ─────────
# Counted on a copy of the code where chrome["tabs"]["query"] has been rewritten
# to chrome.tabs.query, because minified and obfuscated code routinely uses
# bracket access. Counts, not verdicts: a content blocker uses webRequest and
# scripting legitimately; the point is to show the reviewer what is in use.
_API_PATTERNS: List[Tuple[str, str]] = [
    ("cookies",            r"\bchrome\.cookies\.\w+"),
    ("history",            r"\bchrome\.history\.\w+"),
    ("webRequest",         r"\bchrome\.webRequest\.\w+"),
    ("declarativeNetRequest", r"\bchrome\.declarativeNetRequest\.\w+"),
    ("scripting",          r"\bchrome\.scripting\.\w+"),
    ("tabs",               r"\bchrome\.tabs\.\w+"),
    ("downloads",          r"\bchrome\.downloads\.\w+"),
    ("management",         r"\bchrome\.management\.\w+"),
    ("identity",           r"\bchrome\.identity\.\w+"),
    ("proxy",              r"\bchrome\.proxy\.\w+"),
    ("debugger",           r"\bchrome\.debugger\.\w+"),
    ("webNavigation",      r"\bchrome\.webNavigation\.\w+"),
    ("notifications",      r"\bchrome\.notifications\.\w+"),
    ("storage",            r"\bchrome\.storage\.\w+"),
    ("alarms",             r"\bchrome\.alarms\.\w+"),
    ("clipboard",          r"\bnavigator\.clipboard\b|\bclipboardRead\b"),
]

_NETWORK_PATTERNS: List[Tuple[str, str]] = [
    ("fetch",            r"\bfetch\s*\("),
    ("XMLHttpRequest",   r"\bXMLHttpRequest\b"),
    ("sendBeacon",       r"\bsendBeacon\s*\("),
    ("WebSocket",        r"\bnew\s+WebSocket\s*\("),
    ("importScripts",    r"\bimportScripts\s*\("),
    ("document.cookie",  r"\bdocument\.cookie\b"),
    ("localStorage",     r"\b(?:localStorage|sessionStorage)\b"),
    ("keyboard events",  r"""['"](?:keydown|keypress|keyup)['"]"""),
    ("form access",      r"\bFormData\b|\binput\[type\s*=\s*['\"]?password"),
]

_COMPILED_API = [(n, re.compile(p)) for n, p in _API_PATTERNS]
_COMPILED_NET = [(n, re.compile(p)) for n, p in _NETWORK_PATTERNS]

_BRACKET_ACCESS = re.compile(r"""\[\s*(["'])([A-Za-z_$][\w$]*)\1\s*\]""")
# Stops at `$` and `{` as well: in bundled code a URL is often the start of a template
# literal (`https://host/${id}`), and what follows is code, not part of the address.
_URL_RE         = re.compile(r"""https?://[^\s"'`<>\\)\]}${]{3,300}""", re.IGNORECASE)
_CONST_RE       = re.compile(r"""(?:\b(?:const|let|var)\s+|[,;{(]\s*)([A-Za-z_$][\w$]*)\s*=\s*(["'])([^"'\\\n]{1,200})\2""")
_ALARM_RE       = re.compile(r"""\balarms\.create\s*\(\s*(?:(["'])([^"']{1,80})\1|([A-Za-z_$][\w$.]*))\s*,?\s*(\{[^}]{0,240}\})?""")
_NUM_FIELD      = r"\b{k}\s*:\s*(\d+(?:\.\d+)?)"
_IMPORT_RE      = re.compile(r"""\bimportScripts\s*\(([^)]{0,400})\)""")
_QUOTED_RE      = re.compile(r"""["']([^"']{1,200})["']""")
_UNINSTALL_RE   = re.compile(r"""\bsetUninstallURL\s*\(""")
_REGISTER_CS_RE = re.compile(r"""\bregisterContentScripts\s*\(""")
_EXEC_SCRIPT_RE = re.compile(r"""\bexecuteScript\s*\(""")
_EVAL_RE        = re.compile(r"""(?<![\w$.])eval\s*\(""")
_NEW_FUNC_RE    = re.compile(r"""\bnew\s+Function\s*\(""")
_ATOB_RE        = re.compile(r"""\batob\s*\(""")
_HEX_IDENT_RE   = re.compile(r"""\b_0x[0-9a-f]{3,6}\b""")
_REMOTE_IMPORT  = re.compile(r"""\bimportScripts\s*\([^)]*https?://""", re.IGNORECASE)
_REMOTE_SCRIPT  = re.compile(r"""\.src\s*=\s*["']https?://""", re.IGNORECASE)

# Hosts that show up in source as documentation, licence headers, schema
# namespaces or the store listing rather than as something the extension talks
# to. Showing them would bury the real endpoints.
_NOISE_HOSTS = (
    "w3.org", "schema.org", "mozilla.org", "apache.org", "opensource.org",
    "github.com", "githubusercontent.com", "example.com", "example.org",
    "chromewebstore.google.com", "chrome.google.com", "developer.chrome.com",
    "developer.mozilla.org", "stackoverflow.com", "npmjs.com", "wikipedia.org",
    "ietf.org", "whatwg.org", "localhost", "reactjs.org", "react.dev",
    "xmlns.com", "purl.org", "creativecommons.org", "gnu.org",
    # documentation links that framework bundles carry in their warning messages
    "vuejs.org", "angular.io", "nodejs.org", "jquery.com", "lodash.com", "momentjs.com",
    "getbootstrap.com", "mths.be", "facebook.github.io",
)

_STORE_UPDATE_HOSTS = ("clients2.google.com", "edge.microsoft.com", "update.googleapis.com")

_BINARY_EXTS = {".exe", ".dll", ".so", ".dylib", ".bat", ".cmd", ".ps1", ".msi",
                ".jar", ".wasm", ".node", ".scr", ".vbs", ".apk", ".bin", ".sh"}

_ALL_SITES = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "http://*/", "https://*/")


# ══════════════════════════════════════════════════════════════════════════════
#  Reading the package
# ══════════════════════════════════════════════════════════════════════════════

def _read_text(path: str) -> str:
    try:
        if os.path.getsize(path) > _MAX_FILE_BYTES:
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    except OSError:
        return ""


def _js_sources(source_code: str, ext_path: str) -> List[Tuple[str, str]]:
    """[(relative name, text)] for every JavaScript file we can read.

    The unpacked folder is preferred because it is complete and keeps file
    names (an alarm or an endpoint is more useful with the file it lives in).
    The concatenated string the classifier uses is the fallback.
    """
    out: List[Tuple[str, str]] = []
    if ext_path and os.path.isdir(ext_path):
        total = 0
        for root, _dirs, files in os.walk(ext_path):
            for name in sorted(files):
                if not name.lower().endswith((".js", ".mjs")):
                    continue
                full = os.path.join(root, name)
                text = _read_text(full)
                if not text:
                    continue
                total += len(text)
                if total > _MAX_TOTAL_BYTES:
                    return out
                out.append((os.path.relpath(full, ext_path).replace("\\", "/"), text))
    if not out and source_code:
        out.append(("(combined source)", source_code))
    return out


def _normalise(text: str) -> str:
    """chrome["tabs"]["query"] -> chrome.tabs.query, so one pattern covers both
    spellings. Used only for API detection, never shown to the reader."""
    return _BRACKET_ACCESS.sub(r".\2", text)


# ══════════════════════════════════════════════════════════════════════════════
#  Manifest facts
# ══════════════════════════════════════════════════════════════════════════════

def _host_patterns(manifest: dict) -> List[str]:
    patterns: List[str] = []
    for key in ("host_permissions", "optional_host_permissions"):
        patterns += [p for p in (manifest.get(key) or []) if isinstance(p, str)]
    for perm in manifest.get("permissions") or []:
        if isinstance(perm, str) and ("://" in perm or perm == "<all_urls>"):
            patterns.append(perm)
    for entry in manifest.get("content_scripts") or []:
        if isinstance(entry, dict):
            patterns += [m for m in (entry.get("matches") or []) if isinstance(m, str)]
    return list(dict.fromkeys(patterns))


def _site_access(manifest: dict, dynamic_all_sites: bool) -> Dict[str, Any]:
    patterns = _host_patterns(manifest)
    everywhere = dynamic_all_sites or any(p in _ALL_SITES or p.startswith("*://*/") for p in patterns)
    if everywhere:
        scope = "all_sites"
    elif patterns:
        scope = "limited"
    else:
        scope = "none"
    return {"scope": scope, "count": len(patterns), "patterns": patterns[:8]}


def _background(manifest: dict) -> Dict[str, Any]:
    bg = manifest.get("background")
    if not isinstance(bg, dict) or not bg:
        return {"kind": "none", "files": []}
    if bg.get("service_worker"):
        return {"kind": "service_worker", "files": [str(bg["service_worker"])],
                "module": bg.get("type") == "module"}
    if bg.get("page"):
        return {"kind": "page", "files": [str(bg["page"])]}
    scripts = [str(s) for s in (bg.get("scripts") or [])]
    persistent = bg.get("persistent")
    return {"kind": "scripts", "files": scripts, "persistent": persistent if isinstance(persistent, bool) else None}


def _declared_content_scripts(manifest: dict) -> List[Dict[str, Any]]:
    out = []
    for entry in manifest.get("content_scripts") or []:
        if not isinstance(entry, dict):
            continue
        out.append({
            "matches":    [m for m in (entry.get("matches") or []) if isinstance(m, str)][:6],
            "js":         [str(f) for f in (entry.get("js") or [])][:6],
            "css":        [str(f) for f in (entry.get("css") or [])][:4],
            "run_at":     entry.get("run_at") or "document_idle",
            "world":      entry.get("world") or "ISOLATED",
            "all_frames": bool(entry.get("all_frames")),
        })
    return out


def _update_source(manifest: dict) -> str:
    url = str(manifest.get("update_url") or "").strip()
    if not url:
        return "none"
    host = (urlparse(url).hostname or "").lower()
    return "store" if host in _STORE_UPDATE_HOSTS else "custom"


def _web_accessible(manifest: dict) -> Dict[str, Any]:
    """How much of the package any website can load (a fingerprinting and
    detection surface)."""
    resources = manifest.get("web_accessible_resources") or []
    count = 0
    any_site = False
    for item in resources:
        if isinstance(item, str):               # MV2: a bare list of paths, open to all
            count += 1
            any_site = True
        elif isinstance(item, dict):
            count += len(item.get("resources") or [])
            matches = [m for m in (item.get("matches") or []) if isinstance(m, str)]
            if any(m in _ALL_SITES or m.startswith("*://*/") for m in matches):
                any_site = True
    return {"count": count, "any_site": any_site}


# ══════════════════════════════════════════════════════════════════════════════
#  Code facts
# ══════════════════════════════════════════════════════════════════════════════

def _string_constants(sources: List[Tuple[str, str]]) -> Dict[str, Dict[str, List[str]]]:
    """{file: {identifier: [strings]}} for simple `const x = "..."` assignments.
    Minified code keeps names like an alarm in a constant declared in another
    file, so the alarm finder needs this to turn `create(n, ...)` into a name.
    Every value is kept because one-letter names are reused all over minified
    code."""
    table: Dict[str, Dict[str, List[str]]] = {}
    for name, text in sources:
        found: Dict[str, List[str]] = {}
        for match in _CONST_RE.finditer(text):
            found.setdefault(match.group(1), []).append(match.group(3))
        table[name] = found
    return table


def _imports_of(text: str) -> List[str]:
    names: List[str] = []
    for call in _IMPORT_RE.finditer(text):
        names += [q.group(1) for q in _QUOTED_RE.finditer(call.group(1))]
    return [n.lstrip("/") for n in names]


_NAME_LIKE = re.compile(r"[\w.:\-]{2,60}")


def _resolve_name(ident: str, file: str, consts: Dict[str, Dict[str, List[str]]],
                  imports: List[str]) -> Optional[str]:
    """Turn an identifier passed as an alarm name back into its string.

    Looks in the file itself, then in the files it imports, then anywhere, and
    stops at the first place that gives exactly one answer. Only values shaped
    like a name count, since a short variable in minified code is often reused
    for ordinary text. No unique answer returns None."""
    own = [file]
    imported = [k for k in consts if any(k.endswith(i) for i in imports) and k != file]
    others = [k for k in consts if k != file and k not in imported]
    for tier in (own, imported, others):
        values = {v for k in tier for v in consts.get(k, {}).get(ident, []) if _NAME_LIKE.fullmatch(v)}
        if len(values) == 1:
            return values.pop()
    return None


def _alarms(sources: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    consts = _string_constants(sources)
    out: List[Dict[str, Any]] = []
    seen = set()
    for name, text in sources:
        norm = _normalise(text)
        imports = _imports_of(text)
        for match in _ALARM_RE.finditer(norm):
            literal, ident, opts = match.group(2), match.group(3), match.group(4) or ""
            # An unresolved name keeps only its last part: `r.SyncUpAlarm` is a property of some
            # object in scope, and the property is the part a reader can use.
            label = literal or _resolve_name(ident or "", name, consts, imports) or (
                f"(variable {ident.split('.')[-1]})" if ident else "(unnamed)")
            delay  = re.search(_NUM_FIELD.format(k="delayInMinutes"),  opts)
            period = re.search(_NUM_FIELD.format(k="periodInMinutes"), opts)
            entry = {
                "name":   label[:80],
                "delay_minutes":  float(delay.group(1))  if delay  else None,
                "period_minutes": float(period.group(1)) if period else None,
                "file":   name,
            }
            key = (entry["name"], entry["delay_minutes"], entry["period_minutes"])
            if key not in seen:
                seen.add(key)
                out.append(entry)
    return out[:12]


def _registered_domain(host: str) -> str:
    """Last two labels, or three for the common two-part public suffixes.
    Good enough to group `cdn.x.com` and `api.x.com` for a report; not a full
    public-suffix lookup."""
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_noise(host: str) -> bool:
    return any(host == n or host.endswith("." + n) for n in _NOISE_HOSTS)


def _endpoints(sources: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """Hosts the code mentions, grouped, with a few example URLs and the file
    each was found in. Documentation and licence links are dropped."""
    hosts: Dict[str, Dict[str, Any]] = {}
    for name, text in sources:
        for match in _URL_RE.finditer(text):
            url = match.group(0).rstrip(".,;:")
            host = (urlparse(url).hostname or "").lower()
            if not host or _is_noise(host) or "." not in host and not host.replace(".", "").isdigit():
                continue
            entry = hosts.setdefault(host, {"host": host, "count": 0, "samples": [], "files": [],
                                            "ip_literal": bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host)),
                                            "cleartext": False})
            entry["count"] += 1
            if url.lower().startswith("http://"):
                entry["cleartext"] = True
            if len(entry["samples"]) < _MAX_SAMPLES and url[:140] not in entry["samples"]:
                entry["samples"].append(url[:140])
            if name not in entry["files"] and len(entry["files"]) < 3:
                entry["files"].append(name)
    ordered = sorted(hosts.values(), key=lambda h: (-h["count"], h["host"]))
    return ordered[:_MAX_HOSTS]


def _uninstall(sources: List[Tuple[str, str]], endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Whether the code sets an uninstall URL, and the likeliest target.

    The argument is usually built at runtime, so the target is a hint taken from
    a URL in the code whose path says uninstall; it is labelled as such."""
    sets_it = any(_UNINSTALL_RE.search(_normalise(text)) for _n, text in sources)
    hint = ""
    if sets_it:
        for ep in endpoints:
            for sample in ep["samples"]:
                if re.search(r"uninstall|unregister|goodbye|bye|feedback|survey|removed", sample, re.IGNORECASE):
                    hint = sample
                    break
            if hint:
                break
    return {"set": sets_it, "hint": hint}


def _code_stats(sources: List[Tuple[str, str]]) -> Dict[str, Any]:
    evals = funcs = atobs = hex_ids = 0
    remote_imports = remote_scripts = 0
    longest = 0
    minified = 0
    total = 0
    for _name, text in sources:
        total += len(text)
        evals   += len(_EVAL_RE.findall(text))
        funcs   += len(_NEW_FUNC_RE.findall(text))
        atobs   += len(_ATOB_RE.findall(text))
        hex_ids += len(_HEX_IDENT_RE.findall(text))
        remote_imports += len(_REMOTE_IMPORT.findall(text))
        remote_scripts += len(_REMOTE_SCRIPT.findall(text))
        lines = text.count("\n") + 1
        if len(text) / max(lines, 1) > 300:
            minified += 1
        longest = max(longest, max((len(line) for line in text.split("\n", 2000)[:2000]), default=0))
    return {
        "js_files":        len(sources),
        "js_bytes":        total,
        "eval_calls":      evals,
        "new_function":    funcs,
        "atob_calls":      atobs,
        "remote_scripts":  remote_imports + remote_scripts,
        "obfuscated_names": hex_ids,
        "minified_files":  minified,
        "longest_line":    longest,
    }


def _api_usage(sources: List[Tuple[str, str]]) -> Dict[str, Dict[str, int]]:
    browser: Dict[str, int] = {}
    network: Dict[str, int] = {}
    for _name, text in sources:
        norm = _normalise(text)
        for label, rx in _COMPILED_API:
            n = len(rx.findall(norm))
            if n:
                browser[label] = browser.get(label, 0) + n
        for label, rx in _COMPILED_NET:
            n = len(rx.findall(norm))
            if n:
                network[label] = network.get(label, 0) + n
    return {"browser": browser, "data": network}


def _runtime_content_scripts(sources: List[Tuple[str, str]]) -> Dict[str, Any]:
    """Content scripts registered by code instead of declared in the manifest.

    These never appear in the manifest's content_scripts, so a reviewer who
    only reads the manifest sees an extension with "no content scripts" that
    in fact injects into every page. Worlds and match patterns are read from
    the neighbourhood of each registerContentScripts call."""
    worlds: List[str] = []
    all_sites = False
    registered = False
    injects = 0
    for _name, text in sources:
        norm = _normalise(text)
        injects += len(_EXEC_SCRIPT_RE.findall(norm))
        for match in _REGISTER_CS_RE.finditer(norm):
            registered = True
            window = norm[match.end(): match.end() + 900]
            # Minified code often keeps the options in a helper defined just
            # above the call, so look behind it as well.
            behind = norm[max(0, match.start() - 600): match.start()]
            for chunk in (window, behind):
                for world in re.findall(r"""world\s*:\s*["'](MAIN|ISOLATED)["']""", chunk):
                    if world not in worlds:
                        worlds.append(world)
                if re.search(r"""matches\s*:\s*\[[^\]]*(<all_urls>|\*://\*/\*|https?://\*/\*)""", chunk):
                    all_sites = True
    return {"registered_in_code": registered, "worlds": worlds,
            "all_sites": all_sites, "execute_script_calls": injects}


# ══════════════════════════════════════════════════════════════════════════════
#  Package facts (needs the unpacked folder)
# ══════════════════════════════════════════════════════════════════════════════

def _package(ext_path: str) -> Dict[str, Any]:
    if not ext_path or not os.path.isdir(ext_path):
        return {}
    by_type: Dict[str, int] = {}
    binaries: List[str] = []
    biggest: List[Tuple[int, str]] = []
    count = size = 0
    for root, _dirs, files in os.walk(ext_path):
        for name in files:
            full = os.path.join(root, name)
            try:
                bytes_ = os.path.getsize(full)
            except OSError:
                continue
            rel = os.path.relpath(full, ext_path).replace("\\", "/")
            ext = os.path.splitext(name)[1].lower() or "(none)"
            count += 1
            size += bytes_
            by_type[ext] = by_type.get(ext, 0) + 1
            biggest.append((bytes_, rel))
            if ext in _BINARY_EXTS and len(binaries) < 8:
                binaries.append(rel)
    biggest.sort(reverse=True)
    top_types = dict(sorted(by_type.items(), key=lambda kv: -kv[1])[:8])
    return {"files": count, "bytes": size, "by_type": top_types, "binaries": binaries,
            "largest": [{"file": f, "bytes": b} for b, f in biggest[:3]]}


def _network_rules(manifest: dict, ext_path: str) -> Dict[str, Any]:
    """Size and action mix of the declarativeNetRequest rule sets. A content
    blocker ships tens of thousands of block rules; redirect and
    modifyHeaders rules are the ones that change what a site receives."""
    dnr = manifest.get("declarative_net_request")
    resources = dnr.get("rule_resources") if isinstance(dnr, dict) else None
    if not resources or not ext_path:
        return {}
    total = 0
    actions: Dict[str, int] = {}
    files = 0
    for item in resources:
        rel = str(item.get("path") or "") if isinstance(item, dict) else ""
        full = os.path.join(ext_path, rel)
        if not rel or not os.path.isfile(full) or os.path.getsize(full) > _MAX_RULE_BYTES:
            continue
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as handle:
                rules = json.load(handle)
        except (OSError, ValueError):
            continue
        if not isinstance(rules, list):
            continue
        files += 1
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            kind = str((rule.get("action") or {}).get("type") or "unknown")
            actions[kind] = actions.get(kind, 0) + 1
            total += 1
    return {"rule_files": files, "total": total, "by_action": actions} if files else {}


# ══════════════════════════════════════════════════════════════════════════════
#  Plain-language observations
# ══════════════════════════════════════════════════════════════════════════════

def _minutes(value: float) -> str:
    return f"{int(value)} min" if float(value).is_integer() else f"{value:g} min"


def _notes(profile: Dict[str, Any]) -> List[str]:
    """Short factual statements a reviewer would otherwise dig out by hand.
    Each one restates something measured above; none is a verdict."""
    out: List[str] = []
    rt = profile["content_scripts"]["runtime"]
    if rt["registered_in_code"] and not profile["content_scripts"]["declared"]:
        where = "every website" if rt["all_sites"] else "websites"
        world = (" in the page's own JavaScript world" if "MAIN" in rt["worlds"] else "")
        out.append(f"Registers its content scripts from code, not the manifest, so the manifest shows none. "
                   f"They run on {where}{world}.")
    elif rt["registered_in_code"]:
        out.append("Registers additional content scripts from code, beyond the ones in the manifest.")

    for alarm in profile["alarms"]:
        every = alarm["period_minutes"] or alarm["delay_minutes"]
        if every:
            out.append(f"Wakes itself on a schedule: alarm \"{alarm['name']}\" every {_minutes(every)}.")

    if profile["uninstall"]["set"]:
        target = profile["uninstall"]["hint"]
        out.append("Sets a page to open when it is uninstalled"
                   + (f" (likely {target.split('?')[0]})." if target else "."))

    code = profile["code"]
    if code["remote_scripts"]:
        out.append(f"Loads script from a remote URL in {code['remote_scripts']} place(s), so its behaviour can change after review.")
    if code["eval_calls"] or code["new_function"]:
        out.append(f"Builds code at runtime: eval {code['eval_calls']}, new Function {code['new_function']}.")
    if code["obfuscated_names"] >= 20:
        out.append(f"Uses machine-generated names ({code['obfuscated_names']} hex identifiers), a sign of an obfuscator.")

    for ep in profile["endpoints"]:
        if ep["ip_literal"]:
            out.append(f"Contains a hard-coded IP address: {ep['host']}.")
            break
    if any(ep["cleartext"] and not ep["ip_literal"] for ep in profile["endpoints"]):
        out.append("Refers to at least one endpoint over plain http, which can be read or altered on the network.")

    rules = profile.get("network_rules") or {}
    redirect = rules.get("by_action", {}).get("redirect", 0)
    headers = rules.get("by_action", {}).get("modifyHeaders", 0)
    if redirect or headers:
        out.append(f"Its network rules include {redirect:,} redirect and {headers:,} header-changing rules.")

    pkg = profile.get("package") or {}
    if pkg.get("binaries"):
        out.append("Ships native or executable files: " + ", ".join(pkg["binaries"][:4]) + ".")

    if profile["web_accessible"]["any_site"]:
        out.append("Exposes some of its files to every website, which lets a site detect that it is installed.")
    return out


# ══════════════════════════════════════════════════════════════════════════════
#  Public entry point
# ══════════════════════════════════════════════════════════════════════════════

def build_profile(manifest: Dict[str, Any], source_code: str = "", ext_path: str = "") -> Dict[str, Any]:
    """Static profile of one extension. Pure and offline; never raises.

    `ext_path` is optional. With it the profile reads the real files (complete
    code, rule sets, package inventory); without it, only the manifest and the
    concatenated source the classifier saw.
    """
    manifest = manifest if isinstance(manifest, dict) else {}
    try:
        sources = _js_sources(source_code or "", ext_path or "")
        runtime = _runtime_content_scripts(sources)
        endpoints = _endpoints(sources)
        profile: Dict[str, Any] = {
            "manifest": {
                "manifest_version": manifest.get("manifest_version"),
                "update_source":    _update_source(manifest),
                "minimum_chrome":   manifest.get("minimum_chrome_version") or "",
                "homepage":         str(manifest.get("homepage_url") or "")[:200],
                "csp":              _csp(manifest),
                "externally_connectable": bool(manifest.get("externally_connectable")),
            },
            "site_access":    _site_access(manifest, runtime["all_sites"]),
            "background":     _background(manifest),
            "content_scripts": {"declared": _declared_content_scripts(manifest), "runtime": runtime},
            "alarms":         _alarms(sources),
            "endpoints":      endpoints,
            "uninstall":      _uninstall(sources, endpoints),
            "api_usage":      _api_usage(sources),
            "code":           _code_stats(sources),
            "web_accessible": _web_accessible(manifest),
        }
        rules = _network_rules(manifest, ext_path or "")
        if rules:
            profile["network_rules"] = rules
        package = _package(ext_path or "")
        if package:
            profile["package"] = package
        profile["notes"] = _notes(profile)
        return profile
    except Exception as exc:            # a profile is evidence, never a reason to fail an analysis
        return {"error": str(exc)[:200], "notes": []}


def _csp(manifest: dict) -> str:
    csp = manifest.get("content_security_policy")
    if isinstance(csp, dict):
        csp = csp.get("extension_pages") or ""
    return str(csp or "")[:300]
