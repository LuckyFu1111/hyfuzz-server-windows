"""Migration v1_initial_schema."""

from __future__ import annotations


def upgrade() -> None:
    print("Applying v1_initial_schema")


def downgrade() -> None:
    print("Reverting v1_initial_schema")


if __name__ == "__main__":
    upgrade()
