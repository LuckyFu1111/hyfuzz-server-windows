"""Migration v4_add_protocol_tables."""

from __future__ import annotations


def upgrade() -> None:
    print("Applying v4_add_protocol_tables")


def downgrade() -> None:
    print("Reverting v4_add_protocol_tables")


if __name__ == "__main__":
    upgrade()
