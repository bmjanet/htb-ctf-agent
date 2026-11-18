"""Pydantic Settings — credentials from .env file + environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Platform: "ctfd" or "htb" (Hack The Box CTF via its official MCP server)
    platform: str = "ctfd"
    poll_interval_s: float = 0  # 0 = auto (5s CTFd, 15s HTB)

    # HTB CTF MCP
    htb_mcp_url: str = "https://mcp.hackthebox.ai/v1/ctf/mcp/"
    htb_mcp_token: str = ""
    htb_event_id: str = ""  # empty = auto-detect if exactly one event is joinable/joined
    htb_team_id: str = ""  # empty = auto-detect via "my teams"
    htb_zip_password: str = "hackthebox"

    # CTFd
    ctfd_url: str = "http://localhost:8000"
    ctfd_user: str = "admin"
    ctfd_pass: str = "admin"
    ctfd_token: str = ""

    # API Keys
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""

    # Provider-specific (optional, for Bedrock/Azure/Zen fallback)
    aws_region: str = "us-east-1"
    aws_bearer_token: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    opencode_zen_api_key: str = ""

    # Infra
    sandbox_image: str = "ctf-sandbox"
    max_concurrent_challenges: int = 10
    max_attempts_per_challenge: int = 3
    container_memory_limit: str = "16g"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}
