"""Hack The Box CTF client backed by HTB's official CTF MCP server.

Endpoint: https://mcp.hackthebox.ai/v1/ctf/mcp/ (Streamable HTTP, Bearer token from
Profile Settings > MCP Access).

HTB does not publish the exact MCP tool names or schemas, so this client:
  * discovers tools via list_tools() and maps them to logical operations by keyword
    (override with HTB_TOOL_<OP>=<exact tool name> env vars if the guess is wrong);
  * fills tool arguments by matching our values to the tool's input-schema property names;
  * parses results tolerantly (structuredContent, then JSON text, then raw text).

Run scripts/htb_mcp_probe.py first to see the real tool names / payloads.

Sessions are opened per operation: the mcp SDK's anyio cancel scopes must be exited in
the task that entered them, so a long-lived session shared across asyncio tasks is fragile.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import re
import shutil
import subprocess
import time
import zipfile
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from backend.ctfd import SubmitResult

logger = logging.getLogger(__name__)

# Logical operation -> keyword groups (all words in one group must appear in the tool name).
TOOL_KEYWORDS: dict[str, list[list[str]]] = {
    "list_events": [["list", "event"], ["list", "ctf"], ["events"], ["ctfs"]],
    "event_details": [["ctf", "detail"], ["event", "detail"], ["retrieve", "ctf"], ["get", "ctf"]],
    "join_event": [["join"]],
    "my_teams": [["my", "team"], ["teams"]],
    "team_solves": [["team", "solve"]],
    "all_solves": [["all", "solve"], ["solves"]],
    "submit_flag": [["submit", "flag"], ["flag"]],
    "download_link": [["download"]],
    "start_container": [["start", "container"], ["spawn"], ["start", "instance"]],
    "stop_container": [["stop", "container"], ["stop", "instance"]],
    "container_status": [["container", "status"], ["instance", "status"], ["status"]],
}

CACHE_TTL_S = 30.0
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
IPPORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,})[:\s,]+(\d{2,5})\b", re.I)


def _slugify(name: str) -> str:
    slug = re.sub(r'[<>:"/\\|?*.\x00-\x1f]', "", name.lower().strip())
    slug = re.sub(r"[\s_]+", "-", slug)
    return re.sub(r"-+", "-", slug).strip("-") or "challenge"


def _first(d: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def _walk(obj: Any):
    """Yield every dict nested anywhere in obj."""
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def _find_list(obj: Any, *preferred_keys: str, needs: tuple[str, ...] = ("id",)) -> list[dict]:
    """Find a list of dicts: first under a preferred key, else the largest list whose items have `needs`."""
    for d in _walk(obj):
        for k in preferred_keys:
            v = d.get(k)
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return v
    best: list[dict] = []
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            stack.extend(cur.values())
        elif isinstance(cur, list):
            if (cur and len(cur) > len(best)
                    and all(isinstance(x, dict) and all(n in x for n in needs) for x in cur)):
                best = cur
            stack.extend(cur)
    if isinstance(obj, list) and not best and obj and all(isinstance(x, dict) for x in obj):
        return obj
    return best


@dataclass
class HTBMCPClient:
    url: str = "https://mcp.hackthebox.ai/v1/ctf/mcp/"
    token: str = ""
    event_id: str | None = None
    team_id: str | None = None
    zip_password: str = "hackthebox"
    timeout_s: float = 60.0

    _tools: dict[str, Any] = field(default_factory=dict)  # tool name -> Tool
    _resolved: dict[str, str] = field(default_factory=dict)  # logical op -> tool name
    _tools_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _details_cache: tuple[float, list[dict]] | None = None
    _details_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _ids: dict[str, Any] = field(default_factory=dict)  # challenge name -> id
    _names: dict[str, str] = field(default_factory=dict)  # str(id) -> challenge name
    _raw: dict[str, dict] = field(default_factory=dict)  # challenge name -> normalized challenge

    # ------------------------------------------------------------------ MCP plumbing

    @asynccontextmanager
    async def _session(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client

        headers = {"Authorization": f"Bearer {self.token}"}
        async with (
            streamablehttp_client(self.url, headers=headers) as (read, write, _),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            yield session

    async def _ensure_tools(self) -> None:
        if self._tools:
            return
        async with self._tools_lock:
            if self._tools:
                return
            async with self._session() as s:
                listed = await s.list_tools()
            self._tools = {t.name: t for t in listed.tools}
            logger.info("HTB MCP tools: %s", ", ".join(sorted(self._tools)))
            for op, groups in TOOL_KEYWORDS.items():
                override = os.environ.get(f"HTB_TOOL_{op.upper()}")
                if override:
                    self._resolved[op] = override
                    continue
                for group in groups:
                    match = next(
                        (n for n in sorted(self._tools, key=len)
                         if all(w in n.lower() for w in group)
                         and n not in self._resolved.values()),
                        None,
                    )
                    if match:
                        self._resolved[op] = match
                        break
            logger.info("HTB MCP tool mapping: %s", self._resolved)

    def _fill_args(self, tool_name: str, values: dict[str, Any]) -> dict[str, Any]:
        """Map our logical values (event_id, challenge_id, team_id, flag) onto schema props."""
        tool = self._tools.get(tool_name)
        schema = (getattr(tool, "inputSchema", None) or {}) if tool else {}
        props: dict[str, Any] = schema.get("properties", {}) or {}
        if not props:
            return {k: v for k, v in values.items() if v is not None}

        def kind(p: str) -> str | None:
            pl = p.lower()
            if "flag" in pl:
                return "flag"
            if "challenge" in pl:
                return "challenge_id"
            if "team" in pl:
                return "team_id"
            if "event" in pl or "ctf" in pl:
                return "event_id"
            if pl == "id":
                return "_id"
            return None

        args: dict[str, Any] = {}
        for p, spec in props.items():
            k = kind(p)
            if k == "_id":
                # Bare "id": the most specific value we were given.
                v = _first(values, "challenge_id", "team_id", "event_id")
            else:
                v = values.get(k) if k else None
            if v is None:
                continue
            if isinstance(spec, dict) and spec.get("type") == "integer":
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    pass
            elif isinstance(spec, dict) and spec.get("type") == "string":
                v = str(v)
            args[p] = v
        missing = [r for r in schema.get("required", []) if r not in args]
        if missing:
            logger.warning("HTB MCP %s: could not fill required args %s from %s", tool_name, missing, list(values))
        return args

    async def _call(self, op: str, **values: Any) -> Any:
        await self._ensure_tools()
        name = self._resolved.get(op)
        if not name:
            raise RuntimeError(
                f"No HTB MCP tool found for '{op}'. Tools: {sorted(self._tools)}. "
                f"Set HTB_TOOL_{op.upper()}=<tool name>."
            )
        args = self._fill_args(name, values)
        # Never retry a submission: a timeout after the server accepted it would double-submit.
        attempts = 1 if op == "submit_flag" else 3
        last_exc: Exception | None = None
        for attempt in range(attempts):
            try:
                async with asyncio.timeout(self.timeout_s):
                    async with self._session() as s:
                        res = await s.call_tool(name, args)
            except Exception as e:  # transport / session errors: retry with backoff
                last_exc = e
                logger.debug("HTB MCP %s attempt %d failed: %s", name, attempt + 1, e)
                await asyncio.sleep(1.5 * (attempt + 1))
                continue
            parsed = self._parse(res)
            if getattr(res, "isError", False):
                # Tool-level error. For submit_flag, return it so the caller can classify it.
                if op == "submit_flag":
                    return parsed
                raise RuntimeError(f"HTB MCP {name} error: {parsed}")
            return parsed
        raise RuntimeError(f"HTB MCP {name} failed after {attempts} attempt(s): {last_exc}")

    @staticmethod
    def _parse(res: Any) -> Any:
        def decode(v: Any) -> Any:
            if isinstance(v, str):
                try:
                    return json.loads(v)
                except (json.JSONDecodeError, TypeError):
                    return v
            return v

        sc = getattr(res, "structuredContent", None)
        if sc:
            # FastMCP-style servers wrap plain returns as {"result": <value or JSON string>}
            return decode(sc["result"]) if isinstance(sc, dict) and set(sc) == {"result"} else sc
        texts = [getattr(c, "text", "") for c in (getattr(res, "content", None) or [])]
        return decode("\n".join(t for t in texts if t))

    # ------------------------------------------------------------------ event / team resolution

    async def _ensure_event(self) -> str:
        if self.event_id:
            return str(self.event_id)
        events = _find_list(await self._call("list_events"), "events", "ctfs", "data", needs=("id",))
        joined = [e for e in events if _first(e, "joined", "is_joined", "participating", "registered")]
        cands = joined or events
        if len(cands) != 1:
            names = [(e.get("id"), e.get("name")) for e in events]
            raise RuntimeError(f"Set HTB_EVENT_ID — could not pick one event from: {names}")
        self.event_id = str(cands[0]["id"])
        logger.info("HTB event auto-selected: %s (%s)", cands[0].get("name"), self.event_id)
        return self.event_id

    async def _ensure_team(self) -> str | None:
        if self.team_id:
            return str(self.team_id)
        if "my_teams" not in self._resolved:
            return None
        teams = _find_list(await self._call("my_teams", event_id=await self._ensure_event()),
                           "teams", "data", needs=("id",))
        event = str(self.event_id)
        for t in teams:
            if str(_first(t, "ctf_id", "event_id", "ctfId", default=event)) == event:
                self.team_id = str(t["id"])
                break
        if not self.team_id and len(teams) == 1:
            self.team_id = str(teams[0]["id"])
        logger.info("HTB team: %s", self.team_id)
        return self.team_id

    # ------------------------------------------------------------------ challenges

    @staticmethod
    def _normalize(ch: dict) -> dict:
        cat = _first(ch, "category", "category_name", "challenge_category", "categoryName", default="")
        if isinstance(cat, dict):
            cat = _first(cat, "name", "title", default="")
        return {
            "id": ch.get("id"),
            "name": str(_first(ch, "name", "title", default=f"challenge-{ch.get('id')}")),
            "category": str(cat),
            "description": _first(ch, "description", "desc", default="") or "",
            "value": _first(ch, "points", "value", "score", default=0),
            "solves": _first(ch, "solves", "solve_count", "solves_count", default=0),
            "difficulty": _first(ch, "difficulty", default=""),
            "has_docker": bool(_first(ch, "hasDocker", "has_docker", "docker", "docker_enabled", default=False)),
            "has_files": bool(_first(ch, "filename", "file", "hasDownload", "has_download", "download", default=False)),
            "solved": bool(_first(ch, "solved", "is_solved", "authUserSolved", default=False)),
            "raw": ch,
        }

    async def fetch_all_challenges(self) -> list[dict[str, Any]]:
        async with self._details_lock:
            if self._details_cache and time.monotonic() - self._details_cache[0] < CACHE_TTL_S:
                return self._details_cache[1]
            details = await self._call("event_details", event_id=await self._ensure_event())
            raw = _find_list(details, "challenges", "challenge_list", needs=("id", "name"))
            if not raw:
                raise RuntimeError(
                    "HTB event details contained no challenge list. "
                    "Run scripts/htb_mcp_probe.py and check the payload."
                )
            chals = [self._normalize(c) for c in raw]
            for c in chals:
                self._ids[c["name"]] = c["id"]
                self._names[str(c["id"])] = c["name"]
                self._raw[c["name"]] = c
            self._details_cache = (time.monotonic(), chals)
            return chals

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]:
        return await self.fetch_all_challenges()

    async def fetch_solved_names(self) -> set[str]:
        try:
            chals = await self.fetch_all_challenges()
            solved = {c["name"] for c in chals if c["solved"]}
            if "team_solves" in self._resolved:
                team = await self._ensure_team()
                data = await self._call("team_solves", event_id=self.event_id, team_id=team)
                for s in _find_list(data, "solves", "data", needs=()):
                    cid = _first(s, "challenge_id", "challengeId", "id")
                    name = _first(s, "challenge_name", "challenge", "name")
                    if isinstance(name, dict):
                        name = name.get("name")
                    if cid is not None and str(cid) in self._names:
                        solved.add(self._names[str(cid)])
                    elif isinstance(name, str) and name in self._ids:
                        solved.add(name)
            return solved
        except Exception:
            logger.warning("Could not fetch HTB solves", exc_info=True)
            return set()

    async def _challenge(self, name: str) -> dict:
        if name not in self._raw:
            self._details_cache = None
            await self.fetch_all_challenges()
        if name not in self._raw:
            raise RuntimeError(f'Challenge "{name}" not found in HTB event {self.event_id}')
        return self._raw[name]

    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str:
        """Download + unzip files and write metadata.yml. Does NOT start the container
        (see ensure_instance) so we never exceed HTB's per-team container cap at warm-up."""
        import yaml

        ch = challenge if "has_docker" in challenge else self._normalize(challenge)
        ch_dir = Path(output_dir) / _slugify(ch["name"])
        dist = ch_dir / "distfiles"
        ch_dir.mkdir(parents=True, exist_ok=True)

        wants_files = ch["has_files"] or not ch["has_docker"]
        already = dist.exists() and any(dist.iterdir())
        if wants_files and not already and "download_link" in self._resolved:
            try:
                await self._download(ch, dist)
            except Exception as e:
                logger.warning("HTB download failed for %s: %s", ch["name"], e)

        meta_path = ch_dir / "metadata.yml"
        old = yaml.safe_load(meta_path.read_text()) if meta_path.exists() else {}
        meta = {
            "name": ch["name"],
            "category": ch["category"],
            "description": str(ch["description"]).strip()
            + (f"\n\nDifficulty: {ch['difficulty']}" if ch["difficulty"] else ""),
            "value": ch["value"],
            "connection_info": (old or {}).get("connection_info", ""),
            "tags": ["htb"] + (["docker"] if ch["has_docker"] else []),
            "solves": ch["solves"],
            "htb_id": ch["id"],
            "has_docker": ch["has_docker"],
        }
        meta_path.write_text(yaml.dump(meta, allow_unicode=True, default_flow_style=False, sort_keys=False))
        return str(ch_dir)

    async def _download(self, ch: dict, dist: Path) -> None:
        data = await self._call("download_link", event_id=self.event_id, challenge_id=ch["id"])
        text = data if isinstance(data, str) else json.dumps(data)
        m = URL_RE.search(text)
        if not m:
            logger.info("No download link for %s (%s)", ch["name"], text[:200])
            return
        url = m.group(0).rstrip(".,)")
        dist.mkdir(parents=True, exist_ok=True)
        async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
            resp = await client.get(url)  # signed URL — no auth header
            resp.raise_for_status()
        fname = re.sub(r"[^\w.-]", "_", Path(httpx.URL(url).path).name) or "challenge.zip"
        (dist / fname).write_bytes(resp.content)
        logger.info("Downloaded %s for %s (%d bytes)", fname, ch["name"], len(resp.content))
        if zipfile.is_zipfile(io.BytesIO(resp.content)):
            self._unzip(dist / fname, dist)

    def _unzip(self, zpath: Path, dest: Path) -> None:
        out = dest / zpath.stem
        try:
            with zipfile.ZipFile(zpath) as zf:
                for member in zf.namelist():  # reject path traversal
                    if member.startswith("/") or ".." in Path(member).parts:
                        raise RuntimeError(f"unsafe zip member: {member}")
                try:
                    zf.extractall(out)
                except RuntimeError:  # encrypted (ZipCrypto)
                    zf.extractall(out, pwd=self.zip_password.encode())
            logger.info("Unzipped %s -> %s", zpath.name, out)
        except (NotImplementedError, RuntimeError, zipfile.BadZipFile) as e:
            # AES-encrypted zips aren't supported by stdlib — fall back to 7z
            if shutil.which("7z"):
                subprocess.run(["7z", "x", "-y", f"-p{self.zip_password}", f"-o{out}", str(zpath)],
                               check=False, capture_output=True, timeout=120)
                logger.info("Unzipped %s with 7z -> %s", zpath.name, out)
            else:
                logger.warning("Could not unzip %s (%s); left as-is (password: %s)",
                               zpath.name, e, self.zip_password)

    # ------------------------------------------------------------------ containers

    async def _wait_endpoint(self, ch: dict, first: Any, wait_s: float = 120.0) -> str | None:
        data = first
        deadline = time.monotonic() + wait_s
        while True:
            ep = self._endpoint_from(data)
            if ep:
                return ep
            if time.monotonic() > deadline or "container_status" not in self._resolved:
                return None
            await asyncio.sleep(3)
            data = await self._call("container_status", event_id=self.event_id, challenge_id=ch["id"])

    @staticmethod
    def _endpoint_from(data: Any) -> str | None:
        for d in _walk(data):
            host = _first(d, "ip", "host", "hostname", "address")
            port = _first(d, "port", "ports")
            if isinstance(port, list) and port:
                port = port[0]
            if host and port:
                return f"{host}:{port}"
        text = data if isinstance(data, str) else json.dumps(data)
        m = IPPORT_RE.search(text)
        return f"{m.group(1)}:{m.group(2)}" if m else None

    def _write_conn(self, ch_dir: str, ch: dict, endpoint: str) -> str:
        import yaml

        host, port = endpoint.rsplit(":", 1)
        web = any(w in ch["category"].lower() for w in ("web", "api"))
        conn = f"http://{host}:{port}/" if web else f"nc {host} {port}"
        meta_path = Path(ch_dir) / "metadata.yml"
        meta = yaml.safe_load(meta_path.read_text()) or {}
        meta["connection_info"] = conn
        desc = re.sub(r"\n\nInstance: .*$", "", meta.get("description", ""), flags=re.S)
        meta["description"] = (
            f"{desc}\n\nInstance: {host}:{port} (HTB gives only ip:port — "
            "if it isn't HTTP, try raw TCP, and vice versa)."
        )
        meta_path.write_text(yaml.dump(meta, allow_unicode=True, default_flow_style=False, sort_keys=False))
        return conn

    async def ensure_instance(self, challenge_name: str, ch_dir: str) -> str | None:
        """Start the challenge container if it has one; write ip:port into metadata.yml."""
        ch = await self._challenge(challenge_name)
        if not ch["has_docker"] or "start_container" not in self._resolved:
            return None
        if "container_status" in self._resolved:
            try:
                status = await self._call("container_status", event_id=self.event_id, challenge_id=ch["id"])
                ep = self._endpoint_from(status)
                if ep:
                    return self._write_conn(ch_dir, ch, ep)
            except Exception:
                pass  # not running yet
        started = await self._call("start_container", event_id=self.event_id, challenge_id=ch["id"])
        ep = await self._wait_endpoint(ch, started)
        if not ep:
            logger.warning("HTB instance for %s started but no ip:port found: %s", challenge_name, str(started)[:300])
            return None
        logger.info("HTB instance for %s: %s", challenge_name, ep)
        return self._write_conn(ch_dir, ch, ep)

    async def stop_instance(self, challenge_name: str) -> None:
        if "stop_container" not in self._resolved:
            return
        ch = await self._challenge(challenge_name)
        if ch["has_docker"]:
            try:
                await self._call("stop_container", event_id=self.event_id, challenge_id=ch["id"])
            except Exception as e:
                logger.warning("HTB stop container failed for %s: %s", challenge_name, e)

    async def restart_instance(self, challenge_name: str, ch_dir: str) -> str | None:
        await self.stop_instance(challenge_name)
        await asyncio.sleep(2)
        ch = await self._challenge(challenge_name)
        started = await self._call("start_container", event_id=self.event_id, challenge_id=ch["id"])
        ep = await self._wait_endpoint(ch, started)
        return self._write_conn(ch_dir, ch, ep) if ep else None

    # ------------------------------------------------------------------ flags

    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult:
        ch = await self._challenge(challenge_name)
        data = await self._call("submit_flag", event_id=self.event_id, challenge_id=ch["id"], flag=flag.strip())
        text = data if isinstance(data, str) else json.dumps(data)
        low = text.lower()
        msg = _first(data, "message", "msg", "status", default=text) if isinstance(data, dict) else text
        msg = str(msg)[:300]
        if "already" in low:
            return SubmitResult("already_solved", msg, f'ALREADY SOLVED — "{flag}" accepted. {msg}')
        if re.search(r"incorrect|wrong|invalid|not correct|\"success\":\s*false|\"correct\":\s*false", low):
            return SubmitResult("incorrect", msg, f'INCORRECT — "{flag}" rejected. {msg}')
        if re.search(r"correct|congratulations|\"success\":\s*true|solved|accepted", low):
            self._details_cache = None
            return SubmitResult("correct", msg, f'CORRECT — "{flag}" accepted. {msg}')
        return SubmitResult("unknown", msg, f"Unknown submit response: {msg}")

    async def close(self) -> None:
        return None
