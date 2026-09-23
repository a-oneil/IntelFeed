from pydantic import BaseModel

from app.core.pagination import CursorPaginatedResponse, PaginatedResponse


class SampleItem(BaseModel):
    id: int
    name: str


def test_paginated_response_model():
    items = [SampleItem(id=1, name="a"), SampleItem(id=2, name="b")]
    page = PaginatedResponse[SampleItem](
        items=items,
        total=10,
        limit=2,
        offset=0,
        has_more=True,
    )
    assert len(page.items) == 2
    assert page.total == 10
    assert page.limit == 2
    assert page.offset == 0
    assert page.has_more is True
    assert page.items[0].id == 1
    assert page.items[1].name == "b"

    # Verify serialization round-trip
    data = page.model_dump()
    assert data["total"] == 10
    assert data["has_more"] is True
    assert len(data["items"]) == 2

    # Test with empty items
    empty = PaginatedResponse[SampleItem](
        items=[],
        total=0,
        limit=50,
        offset=0,
        has_more=False,
    )
    assert len(empty.items) == 0
    assert empty.has_more is False


def test_cursor_paginated_response_model():
    items = [SampleItem(id=1, name="first"), SampleItem(id=2, name="second")]
    page = CursorPaginatedResponse[SampleItem](
        items=items,
        next_cursor="abc123",
        has_more=True,
    )
    assert len(page.items) == 2
    assert page.next_cursor == "abc123"
    assert page.has_more is True
    assert page.items[0].name == "first"

    # Verify serialization round-trip
    data = page.model_dump()
    assert data["next_cursor"] == "abc123"
    assert data["has_more"] is True
    assert len(data["items"]) == 2

    # Test last page (no next cursor)
    last_page = CursorPaginatedResponse[SampleItem](
        items=[SampleItem(id=3, name="last")],
        next_cursor=None,
        has_more=False,
    )
    assert last_page.next_cursor is None
    assert last_page.has_more is False
    assert len(last_page.items) == 1
