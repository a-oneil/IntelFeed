"""The entry-ID constraint must not scale with the number of IDs.

`IN (...)` sends one bind parameter per element and asyncpg rejects a statement
carrying more than 32767 of them. Filters routinely match more entries than
that — `is:translated OR is:image` matched 36,085 on a live instance — so the
constraint is built as a single array parameter instead.
"""

import uuid

from sqlalchemy.dialects import postgresql

from app.api.search import entry_id_condition

ASYNCPG_PARAM_LIMIT = 32767


def compiled(ids):
    return entry_id_condition(ids).compile(dialect=postgresql.dialect())


def test_uses_an_array_comparison_not_an_in_list():
    sql = str(compiled([str(uuid.uuid4()) for _ in range(3)]))
    assert "ANY" in sql.upper()
    assert " IN " not in sql.upper()


def test_parameter_count_is_constant_regardless_of_id_count():
    small = compiled([str(uuid.uuid4()) for _ in range(2)])
    large = compiled([str(uuid.uuid4()) for _ in range(50_000)])
    assert len(small.params) == len(large.params) == 1


def test_a_list_past_the_asyncpg_limit_still_compiles_to_one_parameter():
    ids = [str(uuid.uuid4()) for _ in range(ASYNCPG_PARAM_LIMIT + 1_000)]
    assert len(compiled(ids).params) == 1


def test_the_ids_survive_into_the_parameter():
    ids = [str(uuid.uuid4()) for _ in range(3)]
    (value,) = compiled(ids).params.values()
    assert [str(v) for v in value] == ids
