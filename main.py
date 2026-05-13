import discord
from discord.ext import commands
import requests
import os
import io
import json
import tempfile
import sys
import urllib.parse
import subprocess
import uuid
import time
import re
import asyncio
import functools
import ipaddress
import socket
import random
import string
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from flask import Flask, send_from_directory
import threading

app = Flask(__name__)

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

def run_flask():
    app.run(host="0.0.0.0", port=5000)

flask_thread = threading.Thread(target=run_flask)
flask_thread.daemon = True
flask_thread.start()

load_dotenv()

# ---------------- LOGGING ----------------
import logging
from logging.handlers import RotatingFileHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("catmio")
_fh = RotatingFileHandler("catmio_bot.log", maxBytes=5*1024*1024, backupCount=5)
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
log.addHandler(_fh)

# ---------------- CONFIG ----------------
TOKEN = os.getenv("DISCORD_TOKEN") or "your token :>"
PREFIX = "."
CATMIO_INVITE = "https://discord.gg/JzUgsbUFNp"
DUMPER_PATH = "asenv_dump.lua"
MAX_FILE_SIZE = 5 * 1024 * 1024
DUMP_TIMEOUT = 130
LUA_INTERPRETERS = ["lua5.4", ["luajit], ["lua5.1"], [lua5.5], ["lua5.3"]
DISCORD_RETRY_ATTEMPTS = 3
DISCORD_RETRY_DELAY = 2.0

# ---------------- EMBED COLORS ----------------
_COLOR_OK = 0x57F287
_COLOR_FAIL = 0xED4245
_COLOR_INFO = 0x5865F2
_COLOR_WARN = 0xFEE75C
_COLOR_CAT = 0xF5A623

# ---------------- RATE LIMITING ----------------
_RATE_LIMIT_SECONDS = 5
_user_last_use: dict[int, float] = defaultdict(float)

def generate_random_name(length=6):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def _check_rate_limit(user_id: int) -> float:
    now = time.time()
    elapsed = now - _user_last_use[user_id]
    if elapsed < _RATE_LIMIT_SECONDS:
        return _RATE_LIMIT_SECONDS - elapsed
    _user_last_use[user_id] = now
    return 0.0

async def _send_with_retry(coro_factory):
    for attempt in range(DISCORD_RETRY_ATTEMPTS):
        try:
            return await coro_factory()
        except discord.errors.DiscordServerError:
            if attempt < DISCORD_RETRY_ATTEMPTS - 1:
                await asyncio.sleep(DISCORD_RETRY_DELAY * (attempt + 1))
            else:
                raise

class _FailedResponse:
    status_code = 0
    content = b""

# ---------------- SECURITY ----------------
_BLOCKED_HOSTS = re.compile(r"^(localhost|.*\.local|.*\.internal|.*\.intranet|169\.254\.169\.254|fd00:ec2::254)$", re.IGNORECASE)
_ALLOWED_SCHEMES = {"http", "https"}
_SENSITIVE_STRINGS = [
    DUMPER_PATH, "@" + DUMPER_PATH, os.path.splitext(DUMPER_PATH)[0],
    "path getter", "attempting to get path", "paths if found",
    "catmio", "catlogger", "envlogger", "sandbox_e", "_sandbox_eR",
]

def _is_safe_url(url: str) -> tuple[bool, str]:
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "invalid URL"
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return False, f"scheme '{parsed.scheme}' not allowed"
    hostname = parsed.hostname or ""
    if not hostname:
        return False, "no hostname"
    if _BLOCKED_HOSTS.match(hostname):
        return False, "internal hostname"
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            ip_str = addr[4][0]
            try:
                ip = ipaddress.ip_address(ip_str)
                if (ip.is_loopback or ip.is_private or ip.is_link_local or 
                    ip.is_multicast or ip.is_reserved or ip.is_unspecified):
                    return False, f"IP {ip_str} is not public"
            except ValueError:
                pass
    except socket.gaierror:
        pass
    return True, ""

def _redact_sensitive_output(code: str) -> str:
    result: list[str] = []
    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith("print("):
            m = re.match(r'^print\s*\(\s*["\'](.+?)["\']\s*\)', stripped)
            if m:
                inner = m.group(1).lower()
                if any(s.lower() in inner for s in _SENSITIVE_STRINGS):
                    continue
        if stripped.startswith("--"):
            inner = stripped[2:].strip().lower()
            if any(s.lower() in inner for s in _SENSITIVE_STRINGS):
                continue
        if DUMPER_PATH in line:
            continue
        result.append(line)
    return "\n".join(result)

def _requests_get(url, **kwargs):
    kwargs.setdefault("timeout", 8)
    safe, reason = _is_safe_url(url)
    if not safe:
        print(f"[security] blocked request to {url!r}: {reason}")
        return _FailedResponse()
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if "headers" in kwargs:
        merged = dict(default_headers)
        merged.update(kwargs["headers"])
        kwargs["headers"] = merged
    else:
        kwargs["headers"] = default_headers
    try:
        return requests.get(url, **kwargs)
    except requests.exceptions.RequestException as e:
        print(f"Warning: request to {url!r} failed: {e}")
        return _FailedResponse()

# ---------------- BOT ----------------
intents = discord.Intents.default()
intents.message_content = True
active_processes = {}
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

# --- ENHANCEMENTS ---
import sqlite3
import psutil
import datetime

db_conn = sqlite3.connect("jobs.db", check_same_thread=False)
db_conn.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, command TEXT, user_id INTEGER, status TEXT, created_at TIMESTAMP, error TEXT)')
db_conn.execute('CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY, total_dumps INTEGER, total_files INTEGER, total_time_ms REAL)')
db_conn.commit()
if not db_conn.execute("SELECT id FROM stats").fetchone():
    db_conn.execute("INSERT INTO stats (id, total_dumps, total_files, total_time_ms) VALUES (1, 0, 0, 0)")
    db_conn.commit()

def _update_stats(time_ms):
    db_conn.execute("UPDATE stats SET total_dumps = total_dumps + 1, total_files = total_files + 1, total_time_ms = total_time_ms + ? WHERE id=1", (time_ms,))
    db_conn.commit()

class CancelJobView(discord.ui.View):
    def __init__(self, author_id, job_id, timeout=300):
        super().__init__(timeout=timeout)
        self.author_id = author_id
        self.job_id = job_id
        btn = discord.ui.Button(
            style=discord.ButtonStyle.secondary,
            label="Cancel",
            emoji="❌",
            custom_id=f"cancel_{author_id}_{job_id}"
        )
        btn.callback = self.cancel_callback
        self.add_item(btn)

    async def cancel_callback(self, interaction: discord.Interaction):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message("You can't cancel someone else's job.", ephemeral=True)
            return
        for child in self.children:
            child.disabled = True
        try:
            await interaction.message.edit(content="❌ Cancelled.", view=self)
        except:
            pass
        await interaction.response.defer()
        proc = active_processes.get(self.job_id)
        if proc:
            try:
                proc.kill()
            except:
                pass
        db_conn.execute("UPDATE jobs SET status='cancelled' WHERE id=?", (self.job_id,))
        db_conn.commit()

_executor = ThreadPoolExecutor(max_workers=32)

# ---------------- LUA DETECTION ----------------
def _find_lua() -> str:
    for interp in LUA_INTERPRETERS:
        try:
            r = subprocess.run([interp, "-v"], capture_output=True, timeout=3)
            if r.returncode == 0:
                return interp
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return LUA_INTERPRETERS[0]

def _check_lua_has_E(interp: str) -> bool:
    try:
        r = subprocess.run([interp, "-E", "-v"], capture_output=True, timeout=3)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

_lua_interp = _find_lua()
_lua_has_E = _check_lua_has_E(_lua_interp)

# ---------------- HELPERS ----------------
def extract_first_url(text):
    m = re.search(r"https?://[^\s\"')]+", text)
    if not m:
        return None
    url = m.group(0)
    url = url.rstrip("')])")
    if url.endswith(") )()"):
        url = url[:-4]
    return url

def get_filename_from_url(url):
    filename = url.split("/")[-1].split("?")[0]
    filename = urllib.parse.unquote(filename)
    if filename and "." in filename:
        return filename
    return "script.lua"

def _strip_loop_markers(code: str) -> str:
    _LOOP_MARKER_RE = re.compile(r"^\s*--\s*Detected loops\s+\d+\s*$")
    cleaned = [line for line in code.splitlines() if not _LOOP_MARKER_RE.match(line)]
    return "\n".join(cleaned)

_COUNTER_SUFFIX_RE = re.compile(r'\b([a-z][A-Za-z_]*)\d+\b')
_MAX_UNROLLED_REPS = 3

def _normalize_counters(line: str) -> str:
    return _COUNTER_SUFFIX_RE.sub(r'\1', line)

def _collapse_loop_unrolls(code: str, max_reps: int = _MAX_UNROLLED_REPS) -> str:
    lines = code.splitlines()
    n = len(lines)
    if n == 0:
        return code
    norm_lines = [_normalize_counters(ln) for ln in lines]
    result: list[str] = []
    i = 0
    while i < n:
        best_block_size = 0
        best_reps = 0
        for block_size in range(1, min(51, n - i + 1)):
            if i + block_size > n:
                break
            norm_block = norm_lines[i:i + block_size]
            if block_size == 1:
                stripped = norm_block[0].strip()
                if not stripped or stripped in ("end", "do", "then"):
                    continue
            reps = 1
            j = i + block_size
            while j + block_size <= n:
                if norm_lines[j:j + block_size] == norm_block:
                    reps += 1
                    j += block_size
                else:
                    break
            if reps > max_reps and reps > best_reps:
                best_reps = reps
                best_block_size = block_size
        if best_block_size and best_reps > max_reps:
            first_nonempty = next((ln for ln in lines[i:i + best_block_size] if ln.strip()), "")
            indent_str = " " * (len(first_nonempty) - len(first_nonempty.lstrip()))
            for rep in range(max_reps):
                result.extend(lines[i + rep * best_block_size:i + (rep + 1) * best_block_size])
            omitted = best_reps - max_reps
            i += best_reps * best_block_size
            partial = 0
            while partial < best_block_size and i + partial < n:
                if norm_lines[i + partial] == norm_block[partial]:
                    partial += 1
                else:
                    break
            if partial > 0:
                omitted += 1
                i += partial
            result.append(f"{indent_str}-- [similar block repeated {omitted} more time(s), omitted for clarity]")
        else:
            result.append(lines[i])
            i += 1
    return "\n".join(result)

def _remove_trailing_whitespace(code: str) -> str:
    return "\n".join(line.rstrip() for line in code.splitlines())

def _collapse_blank_lines(code: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", code)

def _normalize_all_counters(code: str) -> str:
    return "\n".join(_normalize_counters(ln) for ln in code.splitlines())

def _strip_comments(code: str) -> str:
    result: list[str] = []
    for line in code.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("--"):
            continue
        result.append(line)
    return "\n".join(result)

_STR_CONCAT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"')

def _fold_string_concat(code: str) -> str:
    prev = None
    while prev != code:
        prev = code
        code = _STR_CONCAT_RE.sub(lambda m: '"' + m.group(1) + m.group(2) + '"', code)
    return code

_LUA_STR_VAL = r'"(?:[^"\\]|\\.)*"'
_RUNTIME_CONST_RE = re.compile(
    r"^[ 	]*local\s+(_ref_\d+|_url_\d+|_webhook_\d+)\s*=\s*(\"(?:[^\"\\]|\\.)*\")\s*$",
    re.MULTILINE,
)

def _inline_single_use_constants(code: str) -> str:
    constants: dict[str, str] = {}
    for m in _RUNTIME_CONST_RE.finditer(code):
        constants[m.group(1)] = m.group(2)
    if not constants:
        return code
    result = code
    for name, value in constants.items():
        pat = re.compile(r"\b" + re.escape(name) + r"\b")
        total = len(pat.findall(result))
        uses = total - 1
        if uses == 0:
            result = re.sub(
                r"^[ 	]*local\s+" + re.escape(name) + r"\s*=\s*" + _LUA_STR_VAL + r"[ \t]*\n?",
                "", result, flags=re.MULTILINE,
            )
        elif uses == 1:
            decl_re = re.compile(r"^[ 	]*local\s+" + re.escape(name) + r"\s*=\s*(" + _LUA_STR_VAL + r")[ 	]*$", re.MULTILINE)
            decl_m = decl_re.search(result)
            if decl_m:
                after = result[decl_m.end():]
                repl = value
                after = pat.sub(lambda _: repl, after, count=1)
                result = result[:decl_m.end()] + after
            result = re.sub(r"^[ 	]*local\s+" + re.escape(name) + r"\s*=\s*" + _LUA_STR_VAL + r"[ \t]*\n?", "", result, flags=re.MULTILINE)
    return result

_LUA_KEYWORDS = frozenset({
    "and", "break", "do", "else", "elseif", "end", "false", "for",
    "function", "goto", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while",
})

_LUA_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')

def _sub_identifier_outside_strings(old: str, new: str, code: str) -> str:
    pat = re.compile(r"(?<![a-zA-Z0-9_])" + re.escape(old) + r"(?![a-zA-Z0-9_])")
    segments: list[str] = []
    pos = 0
    for m in _LUA_STRING_LITERAL_RE.finditer(code):
        segments.append(pat.sub(new, code[pos:m.start()]))
        segments.append(m.group(0))
        pos = m.end()
    segments.append(pat.sub(new, code[pos:]))
    return "".join(segments)

def _name_to_camel_id(raw: str) -> str:
    parts = [p for p in re.sub(r"[^a-zA-Z0-9]+", " ", raw).split() if p]
    if not parts:
        return ""
    first = parts[0]
    result = first[0].lower() + first[1:] + "".join(p.capitalize() for p in parts[1:])
    if result and result[0].isdigit():
        result = "_" + result
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", result):
        return ""
    if result in _LUA_KEYWORDS:
        return ""
    return result

def _rename_by_name_property(code: str) -> str:
    lines = code.splitlines()
    n = len(lines)
    existing: set[str] = set()
    for line in lines:
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", line):
            existing.add(m.group(1))
    renames: dict[str, str] = {}
    _INSTANCE_NEW_RE = re.compile(r'Instance\.new\s*\(\s*"([A-Za-z][A-Za-z0-9]*)"\s*\)')
    for i, line in enumerate(lines):
        m = re.match(r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
        if not m:
            continue
        var = m.group(1)
        if var in renames:
            continue
        found_name = False
        for j in range(i + 1, n):
            nm = re.match(r"^\s*" + re.escape(var) + r"\s*\.\s*Name\s*=\s*\"([^\"]+)\"", lines[j])
            if nm:
                new_name = _name_to_camel_id(nm.group(1))
                if (new_name and new_name != var and new_name not in renames.values() and new_name not in existing):
                    renames[var] = new_name
                found_name = True
                break
        if not found_name:
            suffix_m = re.match(r"^([a-zA-Z_][a-zA-Z_]*)(\d+)$", var)
            inst_m = _INSTANCE_NEW_RE.search(line)
            if suffix_m and inst_m:
                type_name = inst_m.group(1)
                suffix = suffix_m.group(2)
                base = _name_to_camel_id(type_name)
                if base:
                    candidate = base + "_" + suffix
                    if (candidate not in renames.values() and candidate not in existing):
                        renames[var] = candidate
    if not renames:
        return code
    result = "\n".join(lines)
    for old, new in sorted(renames.items(), key=lambda kv: -len(kv[0])):
        result = re.sub(r"(?<![a-zA-Z0-9_])" + re.escape(old) + r"(?![a-zA-Z0-9_])", new, result)
    return result

_CONN_OPEN_RE = re.compile(r"^\s*(\w[\w.]*\.\w+):Connect\s*\(")

def _dedup_connections(code: str) -> str:
    lines = code.splitlines()
    seen: set[str] = set()
    result: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _CONN_OPEN_RE.match(line)
        if m:
            conn_key = m.group(1)
            if conn_key in seen:
                depth = line.count("(") - line.count(")")
                i += 1
                while i < len(lines) and depth > 0:
                    depth += lines[i].count("(") - lines[i].count(")")
                    i += 1
                continue
            seen.add(conn_key)
        result.append(line)
        i += 1
    return "\n".join(result)

_LUA_BLOCK_OPEN_RE = re.compile(r"\b(function|do|repeat)\b")
_LUA_COND_OPEN_RE = re.compile(r"\b(if|for|while)\b")
_LUA_COND_CLOSE_RE = re.compile(r"\b(then|do)\s*(?:--.*)?$")

def _fix_lua_do_end(code: str) -> str:
    depth = 0
    for raw_line in code.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("--"):
            continue
        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""
        if first_kw in ("end", "until"):
            depth = max(0, depth - 1)
        if first_kw in ("function", "do", "repeat"):
            depth += 1
        elif first_kw in ("if", "for", "while"):
            if _LUA_COND_CLOSE_RE.search(line):
                depth += 1
        elif first_kw == "then":
            depth += 1
        elif re.search(r"\bfunction\b", line) and not re.search(r"\bend\b\s*(?:--.*)?$", line):
            depth += 1
    if depth > 0:
        code = code.rstrip() + "\n" + "end\n" * depth
    return code

def _remove_useless_do_blocks(code: str) -> str:
    lines = code.splitlines()
    result: list[str] = []
    i = 0
    n = len(lines)
    _STANDALONE_DO_RE = re.compile(r"^\s*do\s*(?:--.*)?$")
    def _dedent_line(line: str) -> str:
        if line.startswith("\t"):
            return line[1:]
        if line.startswith("    "):
            return line[4:]
        return line
    while i < n:
        line = lines[i]
        if not _STANDALONE_DO_RE.match(line):
            result.append(line)
            i += 1
            continue
        depth = 1
        j = i + 1
        _INNER_OPEN_RE = re.compile(r"\b(function|do|repeat)\b")
        _INNER_COND_RE = re.compile(r"^\s*(if|for|while)\b.*\b(then|do)\s*(?:--.*)?$")
        _INNER_CLOSE_RE = re.compile(r"^\s*(end|until)\b")
        while j < n and depth > 0:
            inner = lines[j].strip()
            if not inner or inner.startswith("--"):
                j += 1
                continue
            if _INNER_CLOSE_RE.match(lines[j]):
                depth -= 1
                if depth == 0:
                    break
            m_cond = _INNER_COND_RE.match(lines[j])
            if m_cond:
                depth += 1
            elif _INNER_OPEN_RE.search(lines[j]):
                depth += 1
            j += 1
        end_idx = j
        body = lines[i + 1:end_idx]
        non_empty_body = [l for l in body if l.strip() and not l.strip().startswith("--")]
        def _is_single_simple_statement(bl: list) -> bool:
            if len(bl) != 1:
                return False
            t = bl[0].strip()
            return not re.match(r"\b(function|do|repeat|if|for|while)\b", t)
        is_useless = (not non_empty_body or all(l.strip().startswith("local ") for l in non_empty_body) or _is_single_simple_statement(non_empty_body))
        if is_useless:
            for bl in body:
                result.append(_dedent_line(bl))
            i = end_idx + 1
        else:
            result.append(line)
            i += 1
    return "\n".join(result)

# ---------------- REFERENCE MESSAGE HELPER ----------------
async def _fetch_reference_content(ctx):
    ref = ctx.message.reference
    if not ref:
        return None, None
    try:
        ref_msg = await ctx.channel.fetch_message(ref.message_id)
    except Exception:
        return None, None
    if ref_msg.attachments:
        att = ref_msg.attachments[0]
        if att.size > MAX_FILE_SIZE:
            return None, None
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200 and r.content:
            return r.content, att.filename
        return None, None
    url = extract_first_url(ref_msg.content or "")
    if url:
        filename = get_filename_from_url(url)
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, url))
        if r.status_code == 200 and r.content:
            if len(r.content) > MAX_FILE_SIZE:
                return None, None
            return r.content, filename
    return None, None

def _extract_codeblock(text: str):
    if not text:
        return None, None
    pattern = r"```(\w*)\n(.*?)\n```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        lang = match.group(1) or "lua"
        code = match.group(2)
        return code, lang
    pattern = r"```(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        code = match.group(1).strip()
        return code, "lua"
    return None, None

def _looks_like_raw_code_snippet(text: str) -> bool:
    if not text or re.search(r'https?://', text, re.IGNORECASE):
        return False
    return bool(re.search(r'\b(local|function|print|repeat|if|for|while|return|end)\b', text))

async def _get_content(ctx, link=None):
    loop = asyncio.get_event_loop()
    
    # 0. Codeblock in the current message
    codeblock, lang = _extract_codeblock(ctx.message.content)
    if codeblock:
        filename = f"codeblock.{lang if lang != 'lua' else 'lua'}"
        return codeblock.encode("utf-8"), filename, None
    
    # 0.5. Raw code snippet passed directly as argument
    if link:
        stripped_link = link.strip()
        if _looks_like_raw_code_snippet(stripped_link):
            return stripped_link.encode("utf-8"), "snippet.lua", None
    
    # 1. Attachment in the current message
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if att.size > MAX_FILE_SIZE:
            return None, att.filename, "File too large"
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200 and r.content:
            return r.content, att.filename, None
        return None, att.filename, f"Failed to fetch attachment (HTTP {r.status_code})"
    
    # 2. Explicit URL provided in the command argument
    if link:
        url = extract_first_url(link) or link
        safe, reason = _is_safe_url(url)
        if not safe:
            return None, "file", f"Blocked URL: {reason}"
        filename = get_filename_from_url(url)
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, url))
        if r.status_code == 200 and r.content:
            if len(r.content) > MAX_FILE_SIZE:
                return None, filename, "File too large"
            return r.content, filename, None
        url_err = f"HTTP {r.status_code}" if r.status_code != 0 else "network error"
        ref_content, ref_filename = await _fetch_reference_content(ctx)
        if ref_content:
            return ref_content, ref_filename or filename, None
        return None, filename, f"Failed to get content ({url_err})"
    
    # 3. Reply to another message
    ref_content, ref_filename = await _fetch_reference_content(ctx)
    if ref_content:
        return ref_content, ref_filename or "file", None
    
    return None, "file", "Provide a codeblock, link, file, or reply to a message that contains one."

# ---------------- PASTEFY ----------------
def upload_to_pastefy(content, title="Dumped Script"):
    payload = {
        "title": title,
        "content": content,
        "visibility": "PUBLIC"
    }
    try:
        resp = requests.post("https://pastefy.app/api/v2/paste", json=payload, timeout=10)
        if resp.status_code in (200, 201):
            data = resp.json()
            pid = (data.get("paste") or {}).get("id") or data.get("id")
            return (f"https://pastefy.app/{pid}", f"https://pastefy.app/{pid}/raw")
    except Exception as e:
        print(f"[pastefy] upload failed: {e}")
    return None, None

# ---------------- DUMPER ----------------
async def run_dumper(lua_content, job_id=None):
    uid = str(uuid.uuid4())
    input_file = f"input_{uid}.lua"
    output_file = f"output_{uid}.lua"
    try:
        def write_input():
            with open(input_file, "wb") as f:
                f.write(lua_content)
        await asyncio.to_thread(write_input)
        start = time.time()
        cmd = [_lua_interp]
        if _lua_has_E:
            cmd.append("-E")
        cmd.extend([DUMPER_PATH, input_file, output_file])
        process = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        if job_id:
            active_processes[job_id] = process
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=DUMP_TIMEOUT)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return None, 0, 0, 0, "Dump timeout"
        exec_ms = (time.time() - start) * 1000
        stdout = stdout_bytes.decode(errors="ignore")
        loops = 0
        lines = 0
        m = re.search(r"Loops:\s*(\d+)", stdout)
        if m:
            loops = int(m.group(1))
        m = re.search(r"Lines:\s*(\d+)", stdout)
        if m:
            lines = int(m.group(1))
        if os.path.exists(output_file):
            def read_output():
                with open(output_file, "rb") as f:
                    return f.read()
            dumped = await asyncio.to_thread(read_output)
            def update_stats():
                _update_stats(exec_ms)
            await asyncio.to_thread(update_stats)
            return dumped, exec_ms, loops, lines, None
        stderr = stderr_bytes.decode(errors="ignore").strip()
        lua_err = re.search(r"\[LUA_LOAD_FAIL\][^\n]*", stdout)
        if lua_err:
            detail = lua_err.group(0).replace("[LUA_LOAD_FAIL] ", "", 1).strip()
        elif stderr:
            detail = stderr.splitlines()[-1].strip()
        else:
            detail = ""
        msg = "Output not generated"
        if detail:
            msg = f"Output not generated: {detail}"
        return None, 0, 0, 0, msg
    except Exception as e:
        return None, 0, 0, 0, str(e)
    finally:
        if job_id and job_id in active_processes:
            del active_processes[job_id]
        for p in (input_file, output_file):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except:
                pass

# ---------------- LUA COMPATIBILITY FIXER ----------------
_FLOORDIV_ASSIGN_RE = re.compile(r'^([ 	]*)((?:[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)*))[ 	]*//=[ 	]*(.+)$', re.MULTILINE)
_CONCAT_ASSIGN_RE = re.compile(r'^([ 	]*)((?:[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)*))[ 	]*\.\.=[ 	]*(.+)$', re.MULTILINE)
_COMPOUND_ASSIGN_RE = re.compile(r'^([ 	]*)((?:[a-zA-Z_][\w]*(?:\.[a-zA-Z_][\w]*)*))[ 	]*([+\-*/%^])=[ 	]*(.+)$', re.MULTILINE)
_AND_OP_RE = re.compile(r"\s*&&\s*")
_OR_OP_RE = re.compile(r"\s*\|\|\s*")
_NOT_OP_RE = re.compile(r"(?<!\w)!(?=[a-zA-Z_(])")
_NULL_KW_RE = re.compile(r"\bnull\b")
_END_ELSE_IF_RE = re.compile(r"\bend([ 	]+)else([ 	]+)if\b")
_ELSE_IF_RE = re.compile(r"\belse[ 	]+if\b")
_PROTECTED_ELSEIF = "\x00CATMIO_ELSEIF\x00"

def _convert_luau_backtick_strings(code: str) -> str:
    result: list[str] = []
    i = 0
    n = len(code)
    while i < n:
        ch = code[i]
        if ch == '[' and i + 1 < n and code[i + 1] in ('[', '='):
            j = i + 1
            lvl = 0
            while j < n and code[j] == '=':
                lvl += 1
                j += 1
            if j < n and code[j] == '[':
                close = ']' + '=' * lvl + ']'
                end = code.find(close, j + 1)
                if end != -1:
                    result.append(code[i:end + len(close)])
                    i = end + len(close)
                    continue
        if ch == '-' and i + 1 < n and code[i + 1] == '-':
            if i + 2 < n and code[i + 2] == '[':
                j = i + 3
                lvl = 0
                while j < n and code[j] == '=':
                    lvl += 1
                    j += 1
                if j < n and code[j] == '[':
                    close = ']' + '=' * lvl + ']'
                    end = code.find(close, j + 1)
                    if end != -1:
                        result.append(code[i:end + len(close)])
                        i = end + len(close)
                        continue
            end = code.find('\n', i)
            if end == -1:
                result.append(code[i:])
                i = n
            else:
                result.append(code[i:end + 1])
                i = end + 1
            continue
        if ch in ('"', "'"):
            quote = ch
            j = i + 1
            while j < n:
                c2 = code[j]
                if c2 == '\\':
                    j += 2
                elif c2 == quote:
                    j += 1
                    break
                elif c2 == '\n':
                    break
                else:
                    j += 1
            result.append(code[i:j])
            i = j
            continue
        if ch == '`':
            j = i + 1
            buf: list[str] = []
            while j < n and code[j] != '`':
                c2 = code[j]
                if c2 == '\\' and j + 1 < n:
                    buf.append('\\')
                    buf.append(code[j + 1])
                    j += 2
                elif c2 == '"':
                    buf.append('\\"')
                    j += 1
                elif c2 == '\n':
                    buf.append('\\n')
                    j += 1
                elif c2 == '\r':
                    buf.append('\\r')
                    j += 1
                else:
                    buf.append(c2)
                    j += 1
            if j < n:
                j += 1
            result.append('"' + ''.join(buf) + '"')
            i = j
            continue
        result.append(ch)
        i += 1
    return ''.join(result)

def _fix_lua_compat(code: str) -> str:
    code = _convert_luau_backtick_strings(code)
    code = _FLOORDIV_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)} = {m.group(2)} // {m.group(3)}", code)
    code = _CONCAT_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)} = {m.group(2)} .. {m.group(3)}", code)
    code = _COMPOUND_ASSIGN_RE.sub(lambda m: f"{m.group(1)}{m.group(2)} = {m.group(2)} {m.group(3)} {m.group(4)}", code)
    code = code.replace("!=", "~=")
    code = _AND_OP_RE.sub(" and ", code)
    code = _OR_OP_RE.sub(" or ", code)
    code = _NOT_OP_RE.sub("not ", code)
    code = _NULL_KW_RE.sub("nil", code)
    code = _END_ELSE_IF_RE.sub(lambda m: f"end{m.group(1)}else{m.group(2)}{_PROTECTED_ELSEIF}", code)
    code = _ELSE_IF_RE.sub("elseif", code)
    code = code.replace(_PROTECTED_ELSEIF, "if")
    return code

def _fix_wearedevs_compat(code: str) -> str:
    code = code.replace("end else if", "end\nelse if")
    code = re.sub(r"repeat\s+([^\n]+)\s+until\s+([^\n]+)", r"repeat\n    \1\nuntil \2", code)
    code = code.replace(")\"))()", "\"")
    return code

def _beautify_lua(code: str) -> str:
    for cmd in (["lua-format", "--stdin"], ["luafmt", "-"]):
        try:
            proc = subprocess.run(cmd, input=code.encode(), capture_output=True, timeout=15)
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.decode("utf-8", errors="ignore")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    output = []
    indent = 0
    for raw_line in code.splitlines():
        line = raw_line.strip()
        if not line:
            output.append("")
            continue
        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""
        if first_kw in ("end", "until"):
            indent = max(0, indent - 1)
        elif first_kw in ("else", "elseif"):
            indent = max(0, indent - 1)
        output.append("    " * indent + line)
        if first_kw in ("else", "elseif"):
            indent += 1
        elif first_kw in ("function", "do", "repeat"):
            indent += 1
        elif first_kw in ("if", "for", "while"):
            if re.search(r"\b(then|do)\s*(?:--.*)?$", line):
                indent += 1
        elif first_kw == "then":
            indent += 1
        elif re.search(r"\bfunction\b", line) and not re.search(r"\bend\b\s*(?:--.*)?$", line):
            indent += 1
    return "\n".join(output)

_LUNR_HEADER_RE = re.compile(r"--\s*This file was protected using Lunr\b", re.IGNORECASE)

def _detect_lunr(code: str) -> str | None:
    if not _LUNR_HEADER_RE.search(code[:1000]):
        return None
    m = re.search(r"Lunr\s+v([\d.]+)", code[:1000], re.IGNORECASE)
    return m.group(1) if m else "unknown"

_LUA_BLOCK_KEYWORDS_RE = re.compile(r'\b(end|until|function|do|repeat|if|for|while)\b')

def _lua_find_block_end(code: str, start: int) -> int:
    n = len(code)
    depth = 1
    i = start
    while i < n and depth > 0:
        ch = code[i]
        if ch == '[' and i + 1 < n and code[i + 1] in ('[', '='):
            j = i + 1
            lvl = 0
            while j < n and code[j] == '=':
                lvl += 1
                j += 1
            if j < n and code[j] == '[':
                close = ']' + '=' * lvl + ']'
                end = code.find(close, j + 1)
                i = (end + len(close)) if end != -1 else n
                continue
        if ch == '-' and i + 1 < n and code[i + 1] == '-':
            if i + 2 < n and code[i + 2] == '[':
                j = i + 3
                lvl = 0
                while j < n and code[j] == '=':
                    lvl += 1
                    j += 1
                if j < n and code[j] == '[':
                    close = ']' + '=' * lvl + ']'
                    end = code.find(close, j + 1)
                    i = (end + len(close)) if end != -1 else n
                    continue
            nl = code.find('\n', i)
            i = (nl + 1) if nl != -1 else n
            continue
        if ch in ('"', "'", '`'):
            j = i + 1
            while j < n:
                c2 = code[j]
                if c2 == '\\':
                    j += 2
                elif c2 == ch:
                    j += 1
                    break
                elif c2 == '\n' and ch != '`':
                    break
                else:
                    j += 1
            i = j
            continue
        m = _LUA_BLOCK_KEYWORDS_RE.match(code, i)
        if m:
            kw = m.group(1)
            if kw in ('end', 'until'):
                depth -= 1
                if depth == 0:
                    return m.end()
            elif kw in ('function', 'do', 'repeat', 'if', 'for', 'while'):
                depth += 1
            i = m.end()
            continue
        i += 1
    return n

def _eval_const_cmp(lhs: str, op: str, rhs: str) -> bool | None:
    try:
        l_val = float(lhs)
        r_val = float(rhs)
        if op == '>':
            return l_val > r_val
        if op == '<':
            return l_val < r_val
        if op == '>=':
            return l_val >= r_val
        if op == '<=':
            return l_val <= r_val
        if op == '==':
            return l_val == r_val
        if op == '~=':
            return l_val != r_val
    except (ValueError, OverflowError):
        pass
    return None

_LUNR_WHILE_FALSE_RE = re.compile(r'\bwhile\s+false\s+do\b')
_LUNR_CONST_IF_RE = re.compile(r'\bif\s+(-?\d+(?:\.\d+)?)\s*(>|<|>=|<=|==|~=)\s*(-?\d+(?:\.\d+)?)\s+then\b')

def _strip_lunr_dead_blocks(code: str) -> str:
    n = len(code)
    result: list[str] = []
    i = 0
    while i < n:
        ch = code[i]
        if ch == '[' and i + 1 < n and code[i + 1] in ('[', '='):
            j = i + 1
            lvl = 0
            while j < n and code[j] == '=':
                lvl += 1
                j += 1
            if j < n and code[j] == '[':
                close = ']' + '=' * lvl + ']'
                end = code.find(close, j + 1)
                if end != -1:
                    result.append(code[i:end + len(close)])
                    i = end + len(close)
                    continue
        if ch == '-' and i + 1 < n and code[i + 1] == '-':
            if i + 2 < n and code[i + 2] == '[':
                j = i + 3
                lvl = 0
                while j < n and code[j] == '=':
                    lvl += 1
                    j += 1
                if j < n and code[j] == '[':
                    close = ']' + '=' * lvl + ']'
                    end = code.find(close, j + 1)
                    if end != -1:
                        result.append(code[i:end + len(close)])
                        i = end + len(close)
                        continue
            nl = code.find('\n', i)
            end_pos = (nl + 1) if nl != -1 else n
            result.append(code[i:end_pos])
            i = end_pos
            continue
        if ch in ('"', "'", '`'):
            j = i + 1
            while j < n:
                c2 = code[j]
                if c2 == '\\':
                    j += 2
                elif c2 == ch:
                    j += 1
                    break
                elif c2 == '\n' and ch != '`':
                    break
                else:
                    j += 1
            result.append(code[i:j])
            i = j
            continue
        m_wf = _LUNR_WHILE_FALSE_RE.match(code, i)
        if m_wf:
            block_end = _lua_find_block_end(code, m_wf.end())
            i = block_end
            continue
        m_if = _LUNR_CONST_IF_RE.match(code, i)
        if m_if:
            cmp = _eval_const_cmp(m_if.group(1), m_if.group(2), m_if.group(3))
            if cmp is False:
                block_end = _lua_find_block_end(code, m_if.end())
                i = block_end
                continue
        result.append(ch)
        i += 1
    return ''.join(result)

_LUNR_JUNK_QUOTE_RE = re.compile(
    r'"(?:'
    r'All warfare is based on deception|'
    r'Opportunities multiply as they are seized|'
    r'In the midst of chaos|'
    r'The supreme art of war|'
    r'There is no instance of a nation benefiting|'
    r'To know your Enemy|'
    r'Engage people with what they expect|'
    r'Let your plans be dark and impenetrable|'
    r'If you know the enemy and know yourself|'
    r'Supreme excellence consists in breaking'
    r')[^"]*"',
    re.IGNORECASE,
)

_LUNR_JUNK_LOCAL_RE = re.compile(
    r'^[ 	]*local\s+[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*'
    r'(?:'
    r'(?:[-()\d.^, 	]*[\+\-\*\/\^][-()\d+\-*/.^, 	]+)'
    r'|(?:true|false|nil)'
    r'|"(?:'
    r'All warfare is based on deception|'
    r'Opportunities multiply as they are seized|'
    r'In the midst of chaos|'
    r'The supreme art of war|'
    r'There is no instance of a nation benefiting|'
    r'To know your Enemy|'
    r'Engage people with what they expect|'
    r'Let your plans be dark and impenetrable|'
    r'If you know the enemy and know yourself|'
    r'Supreme excellence consists in breaking'
    r')[^"]*"'
    r')\s*;?[ 	]*$',
    re.MULTILINE | re.IGNORECASE,
)

def _strip_lunr_junk_locals(code: str) -> str:
    return _LUNR_JUNK_LOCAL_RE.sub("", code)

def _apply_lunr_preprocessing(code: str) -> str:
    code = _convert_luau_backtick_strings(code)
    code = _strip_lunr_dead_blocks(code)
    code = _strip_lunr_junk_locals(code)
    code = _collapse_blank_lines(code)
    return code

def _fix_else_end_elseif(code: str) -> str:
    OPENERS = ("if", "for", "while", "function", "do", "repeat")
    def _tokenize(s: str):
        kws = ["elseif", "else", "end", "until"] + list(OPENERS)
        toks: list[tuple[int, str]] = []
        i = 0
        n = len(s)
        while i < n:
            ch = s[i]
            if ch in ('"', "'"):
                q = ch
                i += 1
                while i < n and s[i] != q:
                    if s[i] == "\\":
                        i += 1
                    i += 1
                i += 1
                continue
            if s[i:i+2] == "[[":
                e = s.find("]]", i + 2)
                i = (e + 2) if e != -1 else n
                continue
            if s[i:i+2] == "--":
                if s[i+2:i+4] == "[[":
                    e = s.find("]]", i + 4)
                    i = (e + 2) if e != -1 else n
                else:
                    e = s.find("\n", i)
                    i = (e + 1) if e != -1 else n
                continue
            for kw in kws:
                if s[i:i+len(kw)] == kw:
                    nxt = s[i+len(kw)] if i+len(kw) < n else " "
                    prev = s[i-1] if i > 0 else " "
                    if not (nxt.isalnum() or nxt == "_") and not (prev.isalnum() or prev == "_"):
                        toks.append((i, kw))
                        break
            i += 1
        return toks
    def _elseif_has_open_if(toks: list, ei: int) -> bool:
        b_depth = 0
        for k in range(ei - 1, -1, -1):
            _, kw = toks[k]
            if kw in ("end", "until"):
                b_depth += 1
            elif kw in OPENERS:
                b_depth -= 1
                if b_depth == -1:
                    return kw == "if"
        return False
    MAX_PASSES = 15
    for _ in range(MAX_PASSES):
        toks = _tokenize(code)
        removals: set[tuple[int, int]] = set()
        for ti, (pos, kw) in enumerate(toks):
            if kw != "else":
                continue
            depth = 0
            end_pos: int | None = None
            end_ti: int | None = None
            for j in range(ti + 1, len(toks)):
                jpos, jkw = toks[j]
                if jkw in OPENERS:
                    depth += 1
                elif jkw in ("end", "until"):
                    if depth == 0:
                        end_pos = jpos
                        end_ti = j
                        break
                    depth -= 1
            if end_pos is None:
                continue
            after = code[end_pos + 3:].lstrip("; \t\r\n")
            if not re.match(r"elseif\b", after):
                continue
            elseif_ti: int | None = None
            for j in range(end_ti + 1, len(toks)):
                if toks[j][1] == "elseif":
                    elseif_ti = j
                    break
            if elseif_ti is None:
                continue
            if not _elseif_has_open_if(toks, elseif_ti):
                removals.add((pos, 4))
                removals.add((end_pos, 3))
        if not removals:
            break
        for pos, kw_len in sorted(removals, key=lambda x: -x[0]):
            code = code[:pos] + code[pos + kw_len:]
    return code

def _fix_control_structure_too_long(code: str) -> str:
    SPLIT_SIZE = 80
    MAX_PASSES = 10
    for _pass in range(MAX_PASSES):
        lines = code.splitlines()
        n = len(lines)
        by_indent: dict[str, list[int]] = {}
        for i, line in enumerate(lines):
            m = re.match(r'^(\s*)elseif\b', line)
            if m:
                by_indent.setdefault(m.group(1), []).append(i)
        if not by_indent:
            break
        ind = max(by_indent, key=lambda k: len(by_indent[k]))
        elseif_idxs = by_indent[ind]
        if len(elseif_idxs) <= SPLIT_SIZE:
            break
        ind_len = len(ind)
        if_idx = None
        for i in range(elseif_idxs[0] - 1, -1, -1):
            if re.match(r'^' + re.escape(ind) + r'if\b', lines[i]):
                if_idx = i
                break
        if if_idx is None:
            break
        end_idx = None
        depth = 0
        for i in range(if_idx + 1, n):
            raw = lines[i]
            cur_len = len(raw) - len(raw.lstrip())
            stripped = raw.strip()
            if cur_len > ind_len:
                if re.match(r'(?:if\b.*\bthen|for\b.*\bdo|while\b.*\bdo|repeat\b|function\b)\s*(?:--.*)?$', stripped):
                    depth += 1
                elif re.match(r'do\s*(?:--.*)?$', stripped):
                    depth += 1
                elif re.match(r'(?:end|until)\b', stripped):
                    depth = max(0, depth - 1)
            elif cur_len == ind_len and depth == 0:
                if re.match(r'^' + re.escape(ind) + r'end\b', raw):
                    end_idx = i
                    break
        if end_idx is None:
            break
        split_set: set[int] = set()
        for k in range(SPLIT_SIZE, len(elseif_idxs), SPLIT_SIZE):
            split_set.add(elseif_idxs[k])
        num_splits = len(split_set)
        flag = f"_c_done_{if_idx}"
        hdr_re = re.compile(r'^' + re.escape(ind) + r'(?:if|elseif)\b.*\bthen\b\s*(?:--.*)?$')
        result: list[str] = []
        i = 0
        while i < n:
            raw = lines[i]
            if i == if_idx:
                result.append(f"{ind}local {flag} = false")
                result.append(raw)
                result.append(f"{ind}    {flag} = true")
                i += 1
                continue
            if i in split_set:
                result.append(f"{ind}end")
                result.append(f"{ind}if not {flag} then")
                new_hdr = re.sub(r'^(\s*)elseif\b', r'\1if', raw)
                result.append(new_hdr)
                result.append(f"{ind}    {flag} = true")
                i += 1
                continue
            if i == end_idx:
                result.append(raw)
                for _ in range(num_splits):
                    result.append(f"{ind}end")
                i += 1
                continue
            if (if_idx < i < end_idx and i not in split_set and hdr_re.match(raw)):
                result.append(raw)
                result.append(f"{ind}    {flag} = true")
                i += 1
                continue
            result.append(raw)
            i += 1
        code = "\n".join(result)
    return code

_OBFUSCATION_INDICATOR_RE = re.compile(
    r"(loadstring\s*\(\s*game:HttpGet|getfenv\s*\(|setfenv\s*\(|newcclosure|hookmetamethod|"
    r"while\s+true\s+do|while\s+false\s+do|_0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2}|"
    r"bit32?\.(?:bxor|band|bor)|elseif\s+[^\n]{120,}|function\s*\(\s*\.\.\.\s*\)\s*return\s+function)",
    re.IGNORECASE,
)

def _should_use_aggressive_heuristics(code: str) -> bool:
    if not code:
        return False
    if _OBFUSCATION_INDICATOR_RE.search(code):
        return True
    lines = code.splitlines()
    if not lines:
        return False
    very_long = sum(1 for ln in lines if len(ln) > 260)
    dense_names = sum(1 for ln in lines if len(ln) > 120 and re.search(r"[A-Za-z_][A-Za-z0-9_]*\d{3,}", ln))
    compact_noise = sum(1 for ln in lines if ln and (ln.count(";") >= 4 or ln.count("\\") >= 4))
    return very_long >= 8 or dense_names >= 12 or compact_noise >= 20

def _run_heuristic_fix_pipeline(code: str) -> str:
    code = _fix_lua_compat(code)
    code = _fix_wearedevs_compat(code)
    if _should_use_aggressive_heuristics(code):
        code = _fix_else_end_elseif(code)
        code = _fix_control_structure_too_long(code)
        code = _fix_lua_do_end(code)
        code = _remove_useless_do_blocks(code)
        code = _dedup_connections(code)
        code = _fold_string_concat(code)
        code = _collapse_loop_unrolls(code)
    code = _beautify_lua(code)
    code = _collapse_blank_lines(code)
    code = _remove_trailing_whitespace(code)
    return code

# ---------------- COMMANDS ----------------
@bot.command(name="status")
async def _status(ctx):
    try:
        process = psutil.Process(os.getpid())
        mem = process.memory_info().rss / 1024 / 1024
    except:
        mem = 0
    active_jobs = db_conn.execute("SELECT COUNT(*) FROM jobs WHERE status='active'").fetchone()[0]
    await ctx.send(f"❄️ **Status**\nActive Jobs: {active_jobs}\nLua: {_lua_interp}\nMemory: {mem:.2f} MB")

@bot.command(name="stats")
async def _stats(ctx):
    s = db_conn.execute("SELECT total_dumps, total_files, total_time_ms FROM stats").fetchone()
    avg = s[2]/s[0] if s[0] > 0 else 0
    embed = discord.Embed(title="Bot Statistics", color=_COLOR_INFO)
    embed.add_field(name="Total Dumps", value=str(s[0]))
    embed.add_field(name="Total Files", value=str(s[1]))
    embed.add_field(name="Average Time", value=f"{avg:.2f} ms")
    await ctx.send(embed=embed)

@bot.command(name="cancel")
async def _cancel(ctx, job_id: str):
    db_conn.execute("UPDATE jobs SET status='cancelled' WHERE id=?", (job_id,))
    db_conn.commit()
    await ctx.send(f"Job {job_id} marked as cancelled in queue.")

@bot.command(name="de")
async def obfuscator_detect(ctx, *, link=None):
    job_id = str(uuid.uuid4())
    db_conn.execute("INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?)", (job_id, "de", ctx.author.id, "active", datetime.datetime.now(), ""))
    db_conn.commit()
    msg = await ctx.send("🔍 Processing ...", view=CancelJobView(ctx.author.id, job_id))
    content, filename, err = await _get_content(ctx, link)
    if err:
        await msg.edit(content=err, view=None)
        db_conn.execute("UPDATE jobs SET status='error', error=? WHERE id=?", (err, job_id))
        db_conn.commit()
        return
    text = content.decode('utf-8', errors='ignore')
    detected = "Unknown/Custom"
    conf = 10
    evidence = []
    if "Luraph" in text or "LPH_" in text:
        detected, conf = "Luraph", 95
        evidence.append("Found Luraph watermarks/constants")
    elif "Ironbrew" in text or "PSU" in text or "Illusion" in text:
        detected, conf = "Ironbrew 2 / PSU", 90
        evidence.append("Found Ironbrew opcode tables")
    elif "Moonsec" in text:
        detected, conf = "Moonsec", 85
        evidence.append("Found Moonsec strings")
    elif "Synapse XORM" in text:
        detected, conf = "Synapse XORM", 80
        evidence.append("Found XORM headers")
    embed = discord.Embed(title="Obfuscator Detector", color=_COLOR_INFO)
    embed.add_field(name="Verdict", value=detected, inline=False)
    embed.add_field(name="Confidence", value=f"{conf}%", inline=False)
    if evidence:
        embed.add_field(name="Evidence", value="\n".join(evidence), inline=False)
    await msg.edit(content=None, embed=embed, view=None)
    db_conn.execute("UPDATE jobs SET status='done' WHERE id=?", (job_id,))
    db_conn.commit()

@bot.command(name="get")
async def get_cmd(ctx, *, link=None):
    remaining = _check_rate_limit(ctx.author.id)
    if remaining > 0:
        await ctx.send(f"slow down, wait {remaining:.1f}s")
        return
    job_id = str(uuid.uuid4())
    status_msg = await ctx.send("📥 Fetching content...", view=CancelJobView(ctx.author.id, job_id))
    content, filename, err = await _get_content(ctx, link)
    if err:
        await status_msg.edit(content=err)
        return
    if not content:
        await status_msg.edit(content="❌ No content found to fetch.")
        return
    try:
        text_content = content.decode('utf-8', errors='ignore')
    except Exception:
        await status_msg.edit(content="❌ Failed to decode content as text.")
        return
    text_content = _redact_sensitive_output(text_content)
    rand_name = generate_random_name() + ".lua"
    loop = asyncio.get_event_loop()
    paste_url, raw_url = await loop.run_in_executor(_executor, functools.partial(upload_to_pastefy, text_content, title=filename))
    try:
        await status_msg.delete()
    except:
        pass
    embed = discord.Embed(title="📄 Fetched Content", description=f"Successfully fetched **{filename}**", color=_COLOR_OK)
    if raw_url:
        embed.add_field(name="🔗 Links", value=f"[Raw Link]({raw_url})\n[Pastefy Link]({paste_url})", inline=False)
    else:
        embed.add_field(name="⚠️ Note", value="Pastefy upload failed, but file is attached below.", inline=False)
    embed.set_footer(text=f"Requested by {ctx.author.name}")
    try:
        await ctx.send(embed=embed, file=discord.File(io.BytesIO(text_content.encode("utf-8")), filename=rand_name))
    except discord.errors.DiscordServerError as e:
        await status_msg.edit(content=f"Discord error, please retry: {e}")

@bot.command(name="l")
async def l(ctx, *, link=None):
    log.info(".l user=%s guild=%s", ctx.author, ctx.guild.id if ctx.guild else "DM")
    remaining = _check_rate_limit(ctx.author.id)
    if remaining > 0:
        await ctx.send(f"slow down bro, wait {remaining:.1f}s")
        return
    job_id = str(uuid.uuid4())
    status = await ctx.send("🔄 Processing...", view=CancelJobView(ctx.author.id, job_id))
    content, original_filename, err = await _get_content(ctx, link)
    if err:
        await status.edit(content=err)
        return
    try:
        _pre = content.decode('utf-8', errors='ignore')
        _pre_fixed = _fix_lua_compat(_pre)
        if _pre_fixed != _pre:
            content = _pre_fixed.encode('utf-8')
    except Exception:
        pass
    try:
        _lunr_src = content.decode('utf-8', errors='ignore')
        _lunr_ver = _detect_lunr(_lunr_src)
        if _lunr_ver:
            await status.edit(content=f"🛡️ Lunr v{_lunr_ver} detected - applying preprocessing...")
            _lunr_cleaned = _apply_lunr_preprocessing(_lunr_src)
            if _lunr_cleaned != _lunr_src:
                content = _lunr_cleaned.encode('utf-8')
    except Exception:
        pass
    dumped, exec_ms, loops, lines, error = await run_dumper(content, job_id=job_id)
    if error and content is not None:
        try:
            text_source = content.decode("utf-8", errors="ignore")
            fixed_text = _run_heuristic_fix_pipeline(text_source)
            if fixed_text and fixed_text != text_source:
                fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, fixed_error = await run_dumper(fixed_text.encode("utf-8"))
                if not fixed_error and fixed_dumped:
                    dumped, exec_ms, loops, lines, error = fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, None
                    content = fixed_text.encode("utf-8")
        except Exception:
            pass
    if error and "'end' expected" in error.lower() and "elseif" in error.lower() and content is not None:
        try:
            await status.edit(content="🔧 Fixing 'end expected near elseif'...")
            text_source = content.decode("utf-8", errors="ignore")
            fixed_text = _fix_else_end_elseif(text_source)
            if fixed_text != text_source:
                fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, fixed_error = await run_dumper(fixed_text.encode("utf-8"))
                if not fixed_error and fixed_dumped:
                    dumped, exec_ms, loops, lines, error = fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, None
                    content = fixed_text.encode("utf-8")
        except Exception:
            pass
    if error and "control structure too long" in error.lower() and content is not None:
        try:
            await status.edit(content="🔧 Fixing control structure too long...")
            text_source = content.decode("utf-8", errors="ignore")
            fixed_text = _fix_control_structure_too_long(text_source)
            if fixed_text != text_source:
                fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, fixed_error = await run_dumper(fixed_text.encode("utf-8"))
                if not fixed_error and fixed_dumped:
                    dumped, exec_ms, loops, lines, error = fixed_dumped, fixed_exec_ms, fixed_loops, fixed_lines, None
                    content = fixed_text.encode("utf-8")
                elif fixed_error and "control structure too long" in (fixed_error or "").lower():
                    fixed_text2 = _fix_control_structure_too_long(fixed_text)
                    if fixed_text2 != fixed_text:
                        fd2, fms2, fl2, fl2b, fe2 = await run_dumper(fixed_text2.encode("utf-8"))
                        if not fe2 and fd2:
                            dumped, exec_ms, loops, lines, error = fd2, fms2, fl2, fl2b, None
                            content = fixed_text2.encode("utf-8")
        except Exception:
            pass
    if error:
        log.warning(".l dump failed user=%s: %s", ctx.author, error)
        await status.edit(content=f"sorry i cant {error}")
        return
    dumped_text = dumped.decode("utf-8", errors="ignore")
    dumped_text = _strip_loop_markers(dumped_text)
    dumped_text = _redact_sensitive_output(dumped_text)
    dumped_text = _collapse_loop_unrolls(dumped_text)
    dumped_text = _fold_string_concat(dumped_text)
    dumped_text = _inline_single_use_constants(dumped_text)
    dumped_text = _rename_by_name_property(dumped_text)
    dumped_text = _dedup_connections(dumped_text)
    dumped_text = _fix_lua_do_end(dumped_text)
    dumped_text = _normalize_all_counters(dumped_text)
    dumped_text = _collapse_loop_unrolls(dumped_text)
    dumped_text = _remove_useless_do_blocks(dumped_text)
    dumped_text = _strip_comments(dumped_text)
    dumped_text = _collapse_blank_lines(dumped_text)
    dumped_text = _remove_trailing_whitespace(dumped_text)
    dumped_text = _redact_sensitive_output(dumped_text)
    loop = asyncio.get_event_loop()
    paste, raw = await loop.run_in_executor(_executor, functools.partial(upload_to_pastefy, dumped_text, title=original_filename))
    try:
        await status.delete()
    except:
        pass
    log.info(".l done user=%s file=%s size=%d exec=%.0fms", ctx.author, original_filename, len(dumped_text), exec_ms)
    bot_name = bot.user.display_name if bot.user else "me"
    if raw:
        msg_content = f"here ur script has been dump {exec_ms:.2f}ms by {bot_name} | {raw}"
    else:
        msg_content = f"here ur script has been dump {exec_ms:.2f}ms by {bot_name} | paste upload failed"
    rand_name = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + ".lua"
    try:
        await ctx.send(content=msg_content, file=discord.File(io.BytesIO(dumped_text.encode("utf-8")), filename=rand_name))
    except discord.errors.DiscordServerError as e:
        await status.edit(content=f"Discord error, please retry: {e}")

@bot.command(name="bf")
async def beautify(ctx, *, link=None):
    remaining = _check_rate_limit(ctx.author.id)
    if remaining > 0:
        await ctx.send(f"slow down, wait {remaining:.1f}s")
        return
    job_id = str(uuid.uuid4())
    status = await ctx.send("🎨 Beautifying...", view=CancelJobView(ctx.author.id, job_id))
    content, original_filename, err = await _get_content(ctx, link)
    if err:
        await status.edit(content=err)
        return
    lua_text = content.decode("utf-8", errors="ignore")
    loop = asyncio.get_event_loop()
    beautified = await loop.run_in_executor(_executor, functools.partial(_beautify_lua, lua_text))
    paste, raw = await loop.run_in_executor(_executor, functools.partial(upload_to_pastefy, beautified, title=f"[BF] {original_filename}"))
    try:
        await status.delete()
    except:
        pass
    msg_content = "beautified" + (f" | {raw}" if raw else "")
    try:
        await ctx.send(content=msg_content, file=discord.File(io.BytesIO(beautified.encode("utf-8")), filename=os.path.splitext(original_filename)[0] + "_bf.lua"))
    except discord.errors.DiscordServerError as e:
        await status.edit(content=f"Discord error, please retry: {e}")

# ---------------- COMMAND .darklua ----------------

_DARKLUA_TRANSFORM_ORDER = [
    "strip_comments",
    "fix_syntax",
    "rename_vars",
    "fold_strings",
    "inline_constants",
    "beautify",
]

_DARKLUA_OPTIONS = [
    discord.SelectOption(
        label="Remove Comments",
        value="strip_comments",
        description="Remove all Lua comments from the code",
    ),
    discord.SelectOption(
        label="Rename Variables",
        value="rename_vars",
        description="Intelligently rename Instance.new() variables",
    ),
    discord.SelectOption(
        label="Fold String Concatenations",
        value="fold_strings",
        description='Collapse "a" .. "b" into "ab"',
    ),
    discord.SelectOption(
        label="Inline Single-Use Constants",
        value="inline_constants",
        description="Inline constants that are referenced only once",
    ),
    discord.SelectOption(
        label="Beautify / Reformat",
        value="beautify",
        description="Normalize indentation and formatting",
    ),
    discord.SelectOption(
        label="Fix Syntax Errors",
        value="fix_syntax",
        description="Apply heuristic Lua syntax repair pipeline",
    ),
]

class _DarkluaView(discord.ui.View):
    def __init__(self, code: str, filename: str, author_id: int):
        super().__init__(timeout=120)
        self.code = code
        self.filename = filename
        self.author_id = author_id
        self.selected: list[str] = []
        self.message = None

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except discord.errors.HTTPException:
                pass

    @discord.ui.select(
        placeholder="Choose transformations…",
        min_values=1,
        max_values=len(_DARKLUA_OPTIONS),
        options=_DARKLUA_OPTIONS,
    )
    async def select_transforms(
        self,
        interaction: discord.Interaction,
        select: discord.ui.Select,
    ):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "Only the command author can use this menu.", ephemeral=True
            )
            return
        self.selected = select.values
        await interaction.response.defer()

    @discord.ui.button(label="Apply", style=discord.ButtonStyle.primary)
    async def apply_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "Only the command author can use this menu.", ephemeral=True
            )
            return
        if not self.selected:
            await interaction.response.send_message(
                "Please select at least one transformation first.", ephemeral=True
            )
            return
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(content="Processing...", view=self)
        self.stop()
        code = self.code
        loop = asyncio.get_event_loop()
        selected_set = set(self.selected)
        for key in _DARKLUA_TRANSFORM_ORDER:
            if key not in selected_set:
                continue
            if key == "strip_comments":
                code = _strip_comments(code)
            elif key == "fix_syntax":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_run_heuristic_fix_pipeline, code)
                )
            elif key == "rename_vars":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_smart_rename_variables, code)
                )
            elif key == "fold_strings":
                code = _fold_string_concat(code)
            elif key == "inline_constants":
                code = _inline_single_use_constants(code)
            elif key == "beautify":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_beautify_lua, code)
                )
        paste, raw = await loop.run_in_executor(
            _executor,
            functools.partial(
                upload_to_pastefy, code, title=f"[darklua] {self.filename}"
            ),
        )
        labels = ", ".join(
            o.label for o in _DARKLUA_OPTIONS if o.value in selected_set
        )
        log.info(".darklua applied [%s] user=%s file=%s paste=%s",
                 labels, interaction.user, self.filename, raw or "none")
        out_filename = os.path.splitext(self.filename)[0] + "_darklua.lua"
        embed = discord.Embed(
            title="darklua",
            description=(
                f"Applied: **{labels}**\n"
                + (f"Paste: {raw}" if raw else "Paste upload failed")
            ),
            color=0x5865F2,
        )
        embed.set_footer(text="🐱")
        try:
            await interaction.followup.send(
                embed=embed,
                file=discord.File(
                    io.BytesIO(code.encode("utf-8")),
                    filename=out_filename,
                ),
            )
        except discord.errors.DiscordServerError as e:
            print(f"Warning: failed to send darklua result: {e}")
            try:
                await interaction.followup.send(
                    content=f"Discord error, please retry: {e}"
                )
            except discord.errors.HTTPException:
                pass

@bot.command(name="darklua")
async def darklua_cmd(ctx, *, link=None):
    remaining = _check_rate_limit(ctx.author.id)
    if remaining > 0:
        log.info("Rate limited user=%s cmd=%s remaining=%.1fs", ctx.author, ctx.command, remaining)
        try:
            await ctx.send(f"slow down, wait {remaining:.1f}s")
        except discord.errors.DiscordServerError:
            pass
        return

    try:
        job_id = str(uuid.uuid4())
        status = await ctx.send("<a:ts:1473284855939862701> Processing ...", view=CancelJobView(ctx.author.id, job_id, None))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    content, filename, err = await _get_content(ctx, link)
    if err:
        try:
            await status.edit(content=err)
        except discord.errors.HTTPException:
            pass
        return

    lua_text = content.decode("utf-8", errors="ignore")
    log.info(".darklua user=%s guild=%s file=%s size=%d", ctx.author,
             ctx.guild.id if ctx.guild else "DM", filename, len(lua_text))
    view = _DarkluaView(lua_text, filename, ctx.author.id)
    try:
        await status.delete()
    except discord.errors.HTTPException as e:
        print(f"Warning: failed to delete status message: {e}")
    embed = discord.Embed(
        title="darklua",
        description=(
            f"File: **{filename}**  •  {len(lua_text):,} chars\n"
            "Select the transformations to apply, then click **Apply**."
        ),
        color=0x5865F2,
    )
    embed.set_footer(text="☺ • Expires in 2 minutes")
    try:
        msg = await _send_with_retry(lambda: ctx.send(embed=embed, view=view))
        view.message = msg
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send darklua menu: {e}")

@bot.command(name="on")
async def isup(ctx):
    ping_ms = round(bot.latency * 1000)
    start = getattr(bot, "start_time", time.time())
    elapsed = int(time.time() - start)
    h = elapsed // 3600
    m = (elapsed % 3600) // 60
    s = elapsed % 60
    await ctx.send(f"✅ Online — uptime: {h}h {m}m {s}s — ping: {ping_ms}ms")

@bot.command(name="help")
async def show_help(ctx):
    lines = [
        f"**Commands** — prefix: `{PREFIX}`",
        "",
        f"`{PREFIX}l [link]` — Deobfuscate/dump a Lua script",
        f"`{PREFIX}get [link]` — Fetch a file from a URL and send as attachment",
        f"`{PREFIX}bf [link]` — Beautify/reformat a Lua script",
        f"`{PREFIX}darklua [link]` — Apply Lua code transformations interactively",
        f"`{PREFIX}de [link]` — Detect obfuscator type",
        f"`{PREFIX}status` — Check bot status",
        f"`{PREFIX}stats` — View bot statistics",
        f"`{PREFIX}on` — Check bot uptime and ping",
        f"`{PREFIX}up` — Upload .lua/.txt file to Pastefy",
        "",
        "Attach a file, provide a URL, reply to a message, or use a codeblock."
    ]
    await ctx.send("\n".join(lines))

@bot.command(name="up", aliases=["upload"])
async def upload_to_pastefy_cmd(ctx, *, link=None):
    job_id = str(uuid.uuid4())
    status = await ctx.send("📤 Uploading...", view=CancelJobView(ctx.author.id, job_id))
    content, original_filename, err = await _get_content(ctx, link)
    if err:
        await status.edit(content=err)
        return
    if not original_filename.lower().endswith(('.lua', '.txt')):
        await status.edit(content="❌ Only `.lua` or `.txt` files can be uploaded.")
        return
    try:
        text_content = content.decode("utf-8", errors="ignore")
    except Exception:
        await status.edit(content="❌ Failed to decode file content.")
        return
    if len(text_content) > 10 * 1024 * 1024:
        await status.edit(content="❌ File too large for Pastefy (max 10MB).")
        return
    loop = asyncio.get_event_loop()
    paste_url, raw_url = await loop.run_in_executor(_executor, functools.partial(upload_to_pastefy, text_content, title=original_filename))
    try:
        await status.delete()
    except:
        pass
    if raw_url:
        embed = discord.Embed(title="📎 File Uploaded", description=f"Successfully uploaded **{original_filename}**", color=_COLOR_OK)
        embed.add_field(name="🔗 Raw Link", value=f"[Click to copy]({raw_url})\n\n`{raw_url}`", inline=False)
        embed.add_field(name="🌐 Paste Link", value=f"[View on Pastefy]({paste_url})", inline=True)
        embed.set_footer(text=f"Uploaded by {ctx.author.name}")
        await ctx.send(embed=embed)
    else:
        await ctx.send("❌ Failed to upload to Pastefy.")

# ---------------- START ----------------
if not TOKEN:
    print("ERROR: DISCORD_TOKEN environment variable is not set.")
    exit(1)

if __name__ == "__main__":
    bot.run(TOKEN)
