"""Archive helper."""

from __future__ import annotations

from pathlib import Path
import tarfile


class Archiver:
    def create_archive(self, directory: Path, output: Path) -> Path:
        with tarfile.open(output, "w:gz") as archive:
            archive.add(directory, arcname=directory.name)
        return output


if __name__ == "__main__":
    archiver = Archiver()
    print("Archive helper ready")
