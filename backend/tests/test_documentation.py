import pytest
from httpx import AsyncClient

from app.services import documentation as docs_service

BASE_URL = "/api/documentation"


@pytest.fixture
def docs_dir(tmp_path, monkeypatch):
    """Point the router at a scratch docs/ tree so tests don't ride on repo content."""
    root = tmp_path / "docs"
    (root / "diagrams").mkdir(parents=True)
    (root / "README.md").write_text("# IntelFeed Documentation\n\nTechnical documentation for IntelFeed.\n")
    (root / "architecture.md").write_text(
        "# Architecture\n\nSee [operations](operations.md) for deploys.\n\n## Backend\n\nDetails.\n"
    )
    (root / "operations.md").write_text("# Operations Guide\n\nDeployment and troubleshooting.\n")
    (root / "diagrams" / "entry-pipeline.md").write_text("# Entry Pipeline\n\n```mermaid\nflowchart TD\nA-->B\n```\n")
    docs_service.reset_index_cache()
    monkeypatch.setattr(docs_service, "docs_dir", lambda: root)
    yield root
    docs_service.reset_index_cache()


@pytest.mark.asyncio
async def test_index_requires_auth(client: AsyncClient, docs_dir):
    resp = await client.get(BASE_URL)
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sections_come_from_directories(client: AsyncClient, auth_headers: dict, docs_dir):
    """Nothing is curated: a page's section is just the folder it sits in."""
    resp = await client.get(BASE_URL, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()

    by_slug = {page["slug"]: page for page in body["pages"]}
    assert by_slug["README"]["section"] == "Documentation"
    assert by_slug["architecture"]["section"] == "Documentation"
    assert by_slug["operations"]["section"] == "Documentation"
    assert by_slug["diagrams/entry-pipeline"]["section"] == "Diagrams"

    # Root pages lead, then subdirectories alphabetically.
    assert body["sections"] == ["Documentation", "Diagrams"]


@pytest.mark.asyncio
async def test_index_page_leads_its_section_then_titles_sort(client: AsyncClient, auth_headers: dict, docs_dir):
    resp = await client.get(BASE_URL, headers=auth_headers)
    root_slugs = [p["slug"] for p in resp.json()["pages"] if p["section"] == "Documentation"]
    assert root_slugs == ["README", "architecture", "operations"]


@pytest.mark.asyncio
async def test_index_extracts_title_and_summary(client: AsyncClient, auth_headers: dict, docs_dir):
    resp = await client.get(BASE_URL, headers=auth_headers)
    page = next(p for p in resp.json()["pages"] if p["slug"] == "operations")
    assert page["title"] == "Operations Guide"
    assert page["summary"] == "Deployment and troubleshooting."


@pytest.mark.asyncio
async def test_title_is_the_files_own_h1(client: AsyncClient, auth_headers: dict, docs_dir):
    """No rewriting: whatever the H1 says is what the sidebar shows."""
    (docs_dir / "prefixed.md").write_text("# IntelFeed Query Language Reference\n\nSyntax.\n")
    pages = {p["slug"]: p for p in (await client.get(BASE_URL, headers=auth_headers)).json()["pages"]}
    assert pages["prefixed"]["title"] == "IntelFeed Query Language Reference"


@pytest.mark.asyncio
async def test_new_file_appears_without_restart(client: AsyncClient, auth_headers: dict, docs_dir):
    """Dropping a file into docs/ is the whole publishing step — no cache clear, no redeploy."""
    before = {p["slug"] for p in (await client.get(BASE_URL, headers=auth_headers)).json()["pages"]}
    assert "brand-new-doc" not in before

    (docs_dir / "brand-new-doc.md").write_text("# Brand New Doc\n\nDropped in just now.\n")

    body = (await client.get(BASE_URL, headers=auth_headers)).json()
    page = next(p for p in body["pages"] if p["slug"] == "brand-new-doc")
    assert page["title"] == "Brand New Doc"
    assert page["section"] == "Documentation"
    assert (await client.get(f"{BASE_URL}/brand-new-doc", headers=auth_headers)).status_code == 200


@pytest.mark.asyncio
async def test_edited_file_is_repicked_up(client: AsyncClient, auth_headers: dict, docs_dir):
    await client.get(BASE_URL, headers=auth_headers)
    (docs_dir / "operations.md").write_text("# Running IntelFeed\n\nRewritten and a good bit longer.\n")

    pages = {p["slug"]: p for p in (await client.get(BASE_URL, headers=auth_headers)).json()["pages"]}
    assert pages["operations"]["title"] == "Running IntelFeed"


@pytest.mark.asyncio
async def test_get_page_returns_raw_markdown(client: AsyncClient, auth_headers: dict, docs_dir):
    resp = await client.get(f"{BASE_URL}/architecture", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["title"] == "Architecture"
    # Mermaid fences and cross-links survive untouched for the client to render.
    assert "[operations](operations.md)" in body["markdown"]


@pytest.mark.asyncio
async def test_get_nested_diagram_page(client: AsyncClient, auth_headers: dict, docs_dir):
    resp = await client.get(f"{BASE_URL}/diagrams/entry-pipeline", headers=auth_headers)
    assert resp.status_code == 200
    assert "```mermaid" in resp.json()["markdown"]


@pytest.mark.asyncio
async def test_missing_page_404s(client: AsyncClient, auth_headers: dict, docs_dir):
    resp = await client.get(f"{BASE_URL}/no-such-page", headers=auth_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "slug",
    ["../CLAUDE", "../../etc/passwd", "diagrams/../../CLAUDE", "%2e%2e%2fCLAUDE"],
)
async def test_slug_cannot_escape_docs_dir(client: AsyncClient, auth_headers: dict, docs_dir, slug):
    """Slugs are filesystem paths — traversal must not read outside docs/."""
    # A sibling of docs/ that must stay unreachable.
    (docs_dir.parent / "CLAUDE.md").write_text("# Secret\n\nnot a doc\n")
    resp = await client.get(f"{BASE_URL}/{slug}", headers=auth_headers)
    assert resp.status_code == 404
    assert "Secret" not in resp.text


@pytest.mark.asyncio
async def test_missing_docs_dir_degrades_to_empty(client: AsyncClient, auth_headers: dict, monkeypatch):
    """A deploy without the docs/ mount loses the docs page, not the API."""
    docs_service.reset_index_cache()
    monkeypatch.setattr(docs_service, "docs_dir", lambda: None)
    try:
        resp = await client.get(BASE_URL, headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == {"pages": [], "sections": []}
        assert (await client.get(f"{BASE_URL}/architecture", headers=auth_headers)).status_code == 404
    finally:
        docs_service.reset_index_cache()
