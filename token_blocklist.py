from datetime import datetime, timezone

from database import get_db, is_postgres


def initialize_blocklist_store():
    with get_db() as db:
        db.execute(
            """
            DELETE FROM token_blocklist
            WHERE expires_at IS NULL OR expires_at <= CURRENT_TIMESTAMP
            """
        )


def is_token_revoked(jti):
    with get_db() as db:
        row = db.execute(
            "SELECT 1 FROM token_blocklist WHERE jti = ?",
            (jti,)
        ).fetchone()
    return row is not None


def revoke_tokens(tokens):
    with get_db() as db:
        db.execute(
            """
            DELETE FROM token_blocklist
            WHERE expires_at IS NULL OR expires_at <= CURRENT_TIMESTAMP
            """
        )
        expiration_values = (
            (
                jti,
                datetime.fromtimestamp(expiration, timezone.utc)
                if is_postgres()
                else datetime.fromtimestamp(
                    expiration,
                    timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
            )
            for jti, expiration in tokens
        )
        db.executemany(
            """
            INSERT INTO token_blocklist (jti, expires_at)
            VALUES (?, ?)
            ON CONFLICT (jti) DO NOTHING
            """,
            expiration_values
        )
