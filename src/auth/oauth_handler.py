"""OAuth handler stub."""

from __future__ import annotations

from typing import Dict


class OAuthHandler:
    def exchange_code(self, code: str) -> Dict[str, str]:
        return {"access_token": f"token-{code}", "refresh_token": f"refresh-{code}"}


if __name__ == "__main__":
    handler = OAuthHandler()
    print(handler.exchange_code("123"))
