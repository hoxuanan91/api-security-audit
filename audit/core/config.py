from dataclasses import dataclass, field
from typing import Optional
import yaml


@dataclass
class ScanConfig:
    base_url: str
    token: Optional[str] = None
    endpoints: list[str] = field(default_factory=list)
    rate_limit_threshold: int = 20       # requests before expecting a 429
    timeout: int = 10
    verify_ssl: bool = True
    bola_id_range: tuple[int, int] = (1, 5)  # IDs to probe for BOLA

    @classmethod
    def from_yaml(cls, path: str) -> "ScanConfig":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(
            base_url=data["base_url"].rstrip("/"),
            token=data.get("token"),
            endpoints=data.get("endpoints", []),
            rate_limit_threshold=data.get("rate_limit_threshold", 20),
            timeout=data.get("timeout", 10),
            verify_ssl=data.get("verify_ssl", True),
            bola_id_range=tuple(data.get("bola_id_range", [1, 5])),
        )
