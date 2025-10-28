"""Snapshot handler stub."""

from __future__ import annotations

from pathlib import Path


class SnapshotHandler:
    def create_snapshot(self, path: Path) -> None:
        path.write_text("snapshot", encoding="utf-8")


if __name__ == "__main__":
    handler = SnapshotHandler()
    path = Path("/tmp/snapshot.bak")
    handler.create_snapshot(path)
    print(path.read_text())
