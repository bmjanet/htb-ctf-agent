#!/usr/bin/env python3
"""Probe the HTB CTF MCP server: list tools + schemas, then dump read-only payloads.

Run this BEFORE the event to confirm the real tool names / fields that
backend/htb_mcp.py maps onto. It never submits flags or starts containers.

Usage:
    HTB_MCP_TOKEN=... uv run python scripts/htb_mcp_probe.py [--event-id ID] [--out DIR]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.htb_mcp import HTBMCPClient  # noqa: E402

READ_ONLY_OPS = ["list_events", "my_teams", "event_details", "team_solves", "all_solves"]


def _dump(out: Path, name: str, data) -> None:
    path = out / f"{name}.json"
    path.write_text(json.dumps(data, indent=2, default=str) if not isinstance(data, str) else data)
    preview = json.dumps(data, default=str) if not isinstance(data, str) else data
    print(f"  -> {path} ({len(preview)} chars): {preview[:300]}")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=os.environ.get("HTB_MCP_URL", "https://mcp.hackthebox.ai/v1/ctf/mcp/"))
    ap.add_argument("--event-id", default=os.environ.get("HTB_EVENT_ID") or None)
    ap.add_argument("--out", default="htb_probe")
    args = ap.parse_args()

    token = os.environ.get("HTB_MCP_TOKEN")
    if not token:
        sys.exit("Set HTB_MCP_TOKEN (Profile Settings > MCP Access).")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    client = HTBMCPClient(url=args.url, token=token, event_id=args.event_id)

    print("== Tools ==")
    await client._ensure_tools()
    tools = {
        name: {"description": t.description, "inputSchema": t.inputSchema}
        for name, t in client._tools.items()
    }
    _dump(out, "tools", tools)
    for name, t in sorted(tools.items()):
        props = list((t["inputSchema"] or {}).get("properties", {}))
        print(f"  {name}({', '.join(props)}): {(t['description'] or '').splitlines()[0][:100] if t['description'] else ''}")

    print("\n== Logical op -> tool mapping (override with HTB_TOOL_<OP>=name) ==")
    for op in sorted(set(client._resolved) | set(READ_ONLY_OPS) | {"submit_flag", "download_link", "start_container", "stop_container", "container_status"}):
        print(f"  {op:18s} -> {client._resolved.get(op, 'NOT FOUND')}")

    print("\n== Read-only calls ==")
    for op in READ_ONLY_OPS:
        if op not in client._resolved:
            continue
        try:
            if op == "list_events":
                data = await client._call(op)
            else:
                event = await client._ensure_event()
                team = await client._ensure_team() if op == "team_solves" else None
                data = await client._call(op, event_id=event, team_id=team)
            _dump(out, op, data)
        except Exception as e:
            print(f"  {op}: ERROR {e}")

    print("\n== Normalized challenges ==")
    try:
        chals = await client.fetch_all_challenges()
        for c in chals:
            print(f"  [{c['id']}] {c['name']!r} cat={c['category']!r} pts={c['value']} "
                  f"docker={c['has_docker']} files={c['has_files']} solved={c['solved']}")
        print(f"  solved: {sorted(await client.fetch_solved_names())}")
    except Exception as e:
        print(f"  ERROR: {e}")
        print("  -> fix TOOL_KEYWORDS / _normalize in backend/htb_mcp.py using the dumps above.")


if __name__ == "__main__":
    asyncio.run(main())
