import pytest
from httpx import AsyncClient

BASE_URL = "/api/glossary"

TERM_PAYLOAD = {
    "name": "Zero Trust",
    "category": "protect",
    "maturity": "trending",
    "description": "A security model that requires strict verification for every person and device.",
    "long_description": "Zero Trust is an IT security model that requires strict identity verification.",
    "technologies": [{"name": "Zscaler", "url": "https://zscaler.com"}],
    "search_terms": ["ZTA", "zero-trust architecture"],
}


@pytest.mark.asyncio
async def test_list_glossary_terms_empty(client: AsyncClient, auth_headers: dict):
    resp = await client.get(BASE_URL, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_create_glossary_term(client: AsyncClient, auth_headers: dict):
    resp = await client.post(BASE_URL, json=TERM_PAYLOAD, headers=auth_headers)
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Zero Trust"
    assert data["category"] == "protect"
    assert data["maturity"] == "trending"
    assert data["description"] == TERM_PAYLOAD["description"]
    assert data["is_system"] is False
    assert data["technologies"] == [{"name": "Zscaler", "url": "https://zscaler.com"}]
    assert data["search_terms"] == ["ZTA", "zero-trust architecture"]
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_create_duplicate_term_fails(client: AsyncClient, auth_headers: dict):
    await client.post(BASE_URL, json=TERM_PAYLOAD, headers=auth_headers)
    resp = await client.post(BASE_URL, json=TERM_PAYLOAD, headers=auth_headers)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_get_glossary_term_by_id(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(BASE_URL, json=TERM_PAYLOAD, headers=auth_headers)
    term_id = create_resp.json()["id"]

    resp = await client.get(BASE_URL, headers=auth_headers)
    assert resp.status_code == 200
    ids = [t["id"] for t in resp.json()]
    assert term_id in ids


@pytest.mark.asyncio
async def test_update_glossary_term(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(BASE_URL, json=TERM_PAYLOAD, headers=auth_headers)
    term_id = create_resp.json()["id"]

    update_payload = {"name": "Zero Trust Architecture", "maturity": "mature"}
    resp = await client.put(f"{BASE_URL}/{term_id}", json=update_payload, headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Zero Trust Architecture"
    assert data["maturity"] == "mature"
    # Unchanged fields should persist
    assert data["category"] == "protect"
    assert data["description"] == TERM_PAYLOAD["description"]


@pytest.mark.asyncio
async def test_update_nonexistent_term_returns_404(client: AsyncClient, auth_headers: dict):
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.put(f"{BASE_URL}/{fake_id}", json={"name": "Nope"}, headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_glossary_term(client: AsyncClient, auth_headers: dict):
    create_resp = await client.post(BASE_URL, json=TERM_PAYLOAD, headers=auth_headers)
    term_id = create_resp.json()["id"]

    resp = await client.delete(f"{BASE_URL}/{term_id}", headers=auth_headers)
    assert resp.status_code == 204

    # Verify it's gone
    list_resp = await client.get(BASE_URL, headers=auth_headers)
    ids = [t["id"] for t in list_resp.json()]
    assert term_id not in ids


@pytest.mark.asyncio
async def test_delete_nonexistent_term_returns_404(client: AsyncClient, auth_headers: dict):
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.delete(f"{BASE_URL}/{fake_id}", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_terms_requires_auth(client: AsyncClient):
    resp = await client.get(BASE_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_create_term_requires_auth(client: AsyncClient):
    resp = await client.post(BASE_URL, json=TERM_PAYLOAD)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_delete_term_requires_auth(client: AsyncClient):
    fake_id = "00000000-0000-0000-0000-000000000000"
    resp = await client.delete(f"{BASE_URL}/{fake_id}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_terms_filter_by_category(client: AsyncClient, auth_headers: dict):
    await client.post(BASE_URL, json=TERM_PAYLOAD, headers=auth_headers)
    other = {
        **TERM_PAYLOAD,
        "name": "SIEM",
        "category": "detect",
        "description": "Security Information and Event Management.",
    }
    await client.post(BASE_URL, json=other, headers=auth_headers)

    resp = await client.get(f"{BASE_URL}?category=detect", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["name"] == "SIEM"


@pytest.mark.asyncio
async def test_list_terms_filter_by_search(client: AsyncClient, auth_headers: dict):
    await client.post(BASE_URL, json=TERM_PAYLOAD, headers=auth_headers)
    other = {**TERM_PAYLOAD, "name": "SIEM", "description": "Security Information and Event Management."}
    await client.post(BASE_URL, json=other, headers=auth_headers)

    resp = await client.get(f"{BASE_URL}?search=zero", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["name"] == "Zero Trust"
