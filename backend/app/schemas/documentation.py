from pydantic import BaseModel, Field


class DocumentationPageSummary(BaseModel):
    """One documentation page, as listed in the documentation sidebar."""

    slug: str = Field(
        description="Path-based identifier, relative to docs/ with the .md suffix removed.",
        json_schema_extra={"example": "intelligence-engine"},
    )
    title: str = Field(
        description="The page's first level-1 heading, falling back to a title-cased slug.",
        json_schema_extra={"example": "Intelligence Engine"},
    )
    section: str = Field(
        description=(
            "Sidebar grouping, derived from the page's directory under docs/. Pages at the "
            "root share one section; a subdirectory names its own."
        ),
        json_schema_extra={"example": "Diagrams"},
    )
    summary: str | None = Field(
        default=None,
        description="First paragraph of the page, used as sidebar hover text and search context.",
        json_schema_extra={"example": "Aho-Corasick autolinker, vocab versioning, correlation engine."},
    )


class DocumentationIndexResponse(BaseModel):
    """The full set of documentation pages, ordered for sidebar rendering."""

    pages: list[DocumentationPageSummary] = Field(description="Pages in section order.")
    sections: list[str] = Field(
        description="Section names in display order.",
        json_schema_extra={"example": ["Documentation", "Diagrams"]},
    )


class DocumentationPageResponse(BaseModel):
    """A single documentation page with its raw markdown body."""

    slug: str = Field(json_schema_extra={"example": "architecture"})
    title: str = Field(json_schema_extra={"example": "Architecture"})
    section: str = Field(json_schema_extra={"example": "Documentation"})
    markdown: str = Field(
        description="Raw markdown source. Rendering (including mermaid fences) happens client-side.",
        json_schema_extra={"example": "# Architecture\n\nIntelFeed is a self-hosted..."},
    )
