"""A minimal SQLAlchemy type for pgvector's ``halfvec``.

pgvector ships its own SQLAlchemy types, but binding them through asyncpg means
registering a codec on every pooled connection — asyncpg refuses to encode a
parameter whose server-side type it does not know. Casting from text sidesteps
that entirely: the driver sends a string, Postgres parses it, and no connection
setup hook has to survive a pool recycle.

Only ever a few hundred vectors cross this boundary at a time (an embed batch,
a thread centroid), so the text encoding costs nothing that matters.
"""

from sqlalchemy import Text, cast, type_coerce
from sqlalchemy.types import UserDefinedType


class HalfVec(UserDefinedType):
    """``halfvec(dim)`` — 2 bytes per dimension, cosine-indexed via HNSW."""

    cache_ok = True

    def __init__(self, dim: int):
        self.dim = dim

    def get_col_spec(self, **kw) -> str:
        return f"halfvec({self.dim})"

    def bind_expression(self, bindvalue):
        # Renders CAST(:param AS halfvec(n)) with the parameter typed as text,
        # which is the whole point — see the module docstring.
        return cast(type_coerce(bindvalue, Text()), self)

    def bind_processor(self, dialect):
        def process(value):
            if value is None or isinstance(value, str):
                return value
            return to_literal(value)

        return process

    def result_processor(self, dialect, coltype):
        def process(value):
            if value is None or not isinstance(value, str):
                return value
            return from_literal(value)

        return process


def to_literal(values) -> str:
    """[0.1, 0.2] -> '[0.1,0.2]' — pgvector's text input format."""
    return "[" + ",".join(f"{float(v):.7g}" for v in values) + "]"


def from_literal(raw: str) -> list[float]:
    return [float(part) for part in raw.strip().strip("[]").split(",") if part]
