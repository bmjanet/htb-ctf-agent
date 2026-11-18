"""Platform-agnostic client interface + factory (CTFd or HTB CTF MCP)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from backend.config import Settings
    from backend.ctfd import SubmitResult


@runtime_checkable
class PlatformClient(Protocol):
    """The 5 methods the coordinator, poller, swarm and tools rely on."""

    async def fetch_challenge_stubs(self) -> list[dict[str, Any]]: ...
    async def fetch_all_challenges(self) -> list[dict[str, Any]]: ...
    async def fetch_solved_names(self) -> set[str]: ...
    async def pull_challenge(self, challenge: dict[str, Any], output_dir: str) -> str: ...
    async def submit_flag(self, challenge_name: str, flag: str) -> SubmitResult: ...
    async def close(self) -> None: ...


def make_platform_client(settings: Settings) -> PlatformClient:
    """Build the client selected by settings.platform ("ctfd" | "htb")."""
    if settings.platform == "htb":
        from backend.htb_mcp import HTBMCPClient

        if not settings.htb_mcp_token:
            raise RuntimeError("HTB_MCP_TOKEN is not set (Profile Settings > MCP Access).")
        return HTBMCPClient(
            url=settings.htb_mcp_url,
            token=settings.htb_mcp_token,
            event_id=settings.htb_event_id or None,
            team_id=settings.htb_team_id or None,
            zip_password=settings.htb_zip_password,
        )

    from backend.ctfd import CTFdClient

    return CTFdClient(
        base_url=settings.ctfd_url,
        token=settings.ctfd_token,
        username=settings.ctfd_user,
        password=settings.ctfd_pass,
    )
