from pydantic import BaseModel


class PaginatedResponse[T](BaseModel):
    items: list[T]
    total: int
    limit: int
    offset: int
    has_more: bool


class CursorPaginatedResponse[T](BaseModel):
    items: list[T]
    next_cursor: str | None
    has_more: bool
