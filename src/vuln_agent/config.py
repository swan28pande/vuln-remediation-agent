import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    github_token: str = os.environ.get("GITHUB_TOKEN", "")
    database_url: str = os.environ.get(
        "DATABASE_URL", "postgresql://agent:agent@localhost:5432/vuln_agent"
    )
    model: str = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5-5")
    check_timeout_s: int = int(os.environ.get("CHECK_TIMEOUT_S", "1200"))
    check_poll_s: int = int(os.environ.get("CHECK_POLL_S", "30"))


settings = Settings()
