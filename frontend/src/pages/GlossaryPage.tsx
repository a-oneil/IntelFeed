import { useState, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import {
  useGlossaryTerms,
  useGlossaryCategories,
  useGlossaryArticleCounts,
  articleCountToMaturity,
  useCreateGlossaryTerm,
  useUpdateGlossaryTerm,
  useDeleteGlossaryTerm,
} from "@/hooks/useGlossary";
import type { GlossaryTerm, GlossaryTechnology } from "@/api/types";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import { Chip, PageHeader } from "@/components/primitives";
import { DataTable, type DataTableColumn, type SortDir } from "@/components/table/DataTable";
import { NameCell, MetaCell, NumCell, ActionsCell, RowActionButton } from "@/components/table/cells";
import { ResizeHandle } from "@/components/ResizeHandle";
import { useRailWidth } from "@/hooks/useRailWidth";
import styles from "./GlossaryPage.module.css";
import { useOpenSavedSearch } from "@/hooks/useOpenSavedSearch";
import { useIsVisitor } from "@/stores/authStore";

/** Outlined maturity badges. Deliberately literal, not --danger/--warning/
 *  --success: maturity is not a severity, and aliasing it onto the state ramp
 *  would make an unrelated signal move whenever a theme retunes those. */
const MATURITY_COLORS: Record<string, string> = {
  emerging: "#ef4444",
  trending: "#f59e0b",
  mature: "#22c55e",
};

const NIST_CSF_COLORS: Record<string, string> = {
  govern: "#6366f1",
  identify: "#3b82f6",
  protect: "#22c55e",
  detect: "#f59e0b",
  respond: "#ef4444",
  recover: "#8b5cf6",
};

const MATURITY_ORDER: Record<string, number> = { emerging: 0, trending: 1, mature: 2 };

export function GlossaryPage() {
  const [searchParams] = useSearchParams();
  const isVisitor = useIsVisitor();
  const [search, setSearch] = useState(searchParams.get("search") || "");
  const [editingTerm, setEditingTerm] = useState<GlossaryTerm | null>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const detailPane = useRailWidth("glossary-detail", { default: 380, min: 280, max: 640 });
  // Category, type and ordering are the table's own column filters and header
  // sort now — the page kept a parallel set of selects that did the same job.
  const [sort, setSort] = useState<{ key: string; dir: SortDir }>({ key: "name", dir: "asc" });

  const openSavedSearch = useOpenSavedSearch();
  const { data: terms, isLoading } = useGlossaryTerms();
  const { data: categories } = useGlossaryCategories();
  const { data: articleCounts } = useGlossaryArticleCounts();
  const deleteTerm = useDeleteGlossaryTerm();
  const undoableDelete = useUndoableDelete();

  // The header box searches names AND search_terms, which no single column
  // filter can express — that's why it survives alongside the table's own.
  const filteredTerms = useMemo(() => {
    if (!terms) return [];
    if (!search) return terms;
    const q = search.toLowerCase();
    return terms.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.search_terms?.some((st) => st.toLowerCase().includes(q)),
    );
  }, [terms, search]);

  const handleDelete = (term: GlossaryTerm) => {
    undoableDelete({
      label: `"${term.name}"`,
      key: `glossary-${term.id}`,
      onDelete: () => deleteTerm.mutate(term.id),
    });
  };

  const selectedTerm = filteredTerms.find((t) => t.id === selectedId) ?? null;

  const columns: DataTableColumn<GlossaryTerm>[] = useMemo(() => [
    {
      key: "name", label: "Term", width: 260, minWidth: 140, flex: true,
      textValue: (t) => t.name, sortValue: (t) => t.name.toLowerCase(),
      render: (t) => <NameCell value={t.name} />,
    },
    {
      key: "category", label: "Category", width: 140, minWidth: 100,
      sortValue: (t) => t.category,
      choices: [
        { value: "all", label: "Any category" },
        ...(categories ?? []).map((c) => ({
          value: c.name,
          label: c.name.charAt(0).toUpperCase() + c.name.slice(1) + (c.is_nist ? " (NIST)" : ""),
        })),
      ],
      choiceMatch: (t, v) => t.category === v,
      render: (t) => (
        <Chip tone="solid" truncate tint={NIST_CSF_COLORS[t.category] || "#6b7280"}>
          {t.category}
        </Chip>
      ),
    },
    {
      key: "maturity", label: "Maturity", width: 130, minWidth: 100,
      // Ranked by how much coverage the term has, not alphabetically.
      sortValue: (t) => {
        const m = articleCountToMaturity(articleCounts?.[t.id] ?? 0);
        return m ? MATURITY_ORDER[m] ?? -1 : -1;
      },
      choices: [
        { value: "all", label: "Any maturity" },
        { value: "emerging", label: "Emerging" },
        { value: "trending", label: "Trending" },
        { value: "mature", label: "Mature" },
        { value: "none", label: "No coverage" },
      ],
      choiceMatch: (t, v) => {
        const m = articleCountToMaturity(articleCounts?.[t.id] ?? 0);
        return v === "none" ? !m : m === v;
      },
      render: (t) => {
        const count = articleCounts?.[t.id] ?? 0;
        const maturity = articleCountToMaturity(count);
        return maturity ? (
          <Chip tone="outline" tint={MATURITY_COLORS[maturity]}>
            {maturity} ({count})
          </Chip>
        ) : (
          <MetaCell value={null} />
        );
      },
    },
    {
      key: "articles", label: "Articles", width: 90, minWidth: 70, hideable: true,
      numValue: (t) => articleCounts?.[t.id] ?? 0,
      render: (t) => <NumCell value={articleCounts?.[t.id] ?? 0} />,
    },
    {
      key: "source", label: "Source", width: 100, minWidth: 80, hideable: true,
      sortValue: (t) => (t.is_system ? 0 : 1),
      choices: [
        { value: "all", label: "All terms" },
        { value: "system", label: "System" },
        { value: "custom", label: "Custom" },
      ],
      choiceMatch: (t, v) => (v === "system" ? t.is_system : !t.is_system),
      render: (t) => <MetaCell value={t.is_system ? "system" : "custom"} />,
    },
    {
      key: "search_terms", label: "Aliases", width: 200, minWidth: 110, hideable: true, defaultHidden: true,
      textValue: (t) => (t.search_terms ?? []).join(", "),
      render: (t) => <MetaCell value={(t.search_terms ?? []).join(", ") || null} />,
    },
    // Search, edit and delete are all signed-in actions.
    ...(isVisitor ? [] : [{
      key: "actions", label: "", width: 150, minWidth: 150, sticky: "right" as const,
      render: (t: GlossaryTerm) => (
        <ActionsCell>
          <RowActionButton onClick={() => handleSearch(t)} title="Search articles">Search</RowActionButton>
          <RowActionButton onClick={() => setEditingTerm(t)} title="Edit term">Edit</RowActionButton>
          {!t.is_system && (
            <RowActionButton danger onClick={() => handleDelete(t)} title="Delete term">Delete</RowActionButton>
          )}
        </ActionsCell>
      ),
    }]),
  // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [categories, articleCounts, isVisitor]);

  const handleSearch = (term: GlossaryTerm) => {
    const allNames = [term.name, ...(term.search_terms || [])];
    const query = allNames.map((n) => `"${n}"`).join(" OR ");
    openSavedSearch({
      id: "glossary-search",
      name: "glossary-search",
      display_name: null,
      query,
      filters: {},
      unread_count: 0,
      total_count: 0,
      created_at: new Date().toISOString(),
    });
  };


  return (
    <div className={styles.container}>
      <PageHeader
        title="Glossary"
        count={
          filteredTerms.length === (terms?.length ?? 0)
            ? filteredTerms.length
            : `${filteredTerms.length} of ${terms?.length ?? 0}`
        }
        actions={
          isVisitor ? undefined : (
          <button className={styles.addBtn} onClick={() => setShowAddModal(true)}>
            + Add Term
          </button>
          )
        }
        controls={
          <input
            type="text"
            className={styles.searchInput}
            placeholder="Search terms and aliases…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        }
      />
      {/* The pane's width rides a custom property so the narrow-screen rule can
          still cap it. */}
      <div
        className={styles.layout}
        style={{ "--glossary-detail-w": `${detailPane.width}px` } as React.CSSProperties}
      >
        <div className={styles.tablePane}>
          <DataTable<GlossaryTerm>
            tableId="glossary"
            columns={columns}
            rows={filteredTerms}
            getRowId={(t) => t.id}
            activeRowId={selectedId}
            onRowClick={(t) => setSelectedId((prev) => (prev === t.id ? null : t.id))}
            sort={sort}
            onSortChange={setSort}
            isLoading={isLoading}
            noun="term"
            emptyMessage={search ? "No terms match your search." : "No glossary terms yet."}
          />
        </div>

        {/* Definitions used to push the list apart as an inline expansion; they
            open beside it now, the same way a requirement does. */}
        {selectedTerm && (
          /* The pane sits to the right of the handle, so a drag right has to
             shrink it — the delta is inverted. */
          <ResizeHandle
            label="definition pane"
            onResize={(delta) => detailPane.handleProps.onResize(-delta)}
            onResizeStart={detailPane.handleProps.onResizeStart}
            onResizeEnd={detailPane.handleProps.onResizeEnd}
            onReset={detailPane.handleProps.onReset}
          />
        )}

        {selectedTerm && (
          <aside className={styles.detailPane}>
            <div className={styles.detailHead}>
              <h2 className={styles.detailTitle}>{selectedTerm.name}</h2>
              <button
                className={styles.detailClose}
                onClick={() => setSelectedId(null)}
                aria-label="Close definition"
              >
                &times;
              </button>
            </div>
            <div className={styles.detailMeta}>
              <Chip tone="solid" truncate tint={NIST_CSF_COLORS[selectedTerm.category] || "#6b7280"}>
                {selectedTerm.category}
              </Chip>
              {selectedTerm.is_system && <Chip>System</Chip>}
              {(() => {
                const c = articleCounts?.[selectedTerm.id] ?? 0;
                const m = articleCountToMaturity(c);
                return m ? (
                  <Chip tone="outline" tint={MATURITY_COLORS[m]}>{m} ({c})</Chip>
                ) : null;
              })()}
            </div>
            <p className={styles.description}>
              {selectedTerm.long_description || selectedTerm.description}
            </p>
            {selectedTerm.technologies.length > 0 && (
              <div className={styles.detailBlock}>
                <div className={styles.detailLabel}>Technologies</div>
                <div className={styles.techList}>
                  {selectedTerm.technologies.map((tech) => (
                    <Chip key={tech.name} truncate className={styles.techChip}>
                      {tech.url ? (
                        <a href={tech.url} target="_blank" rel="noopener noreferrer">
                          {tech.name}
                        </a>
                      ) : (
                        tech.name
                      )}
                    </Chip>
                  ))}
                </div>
              </div>
            )}
            {selectedTerm.search_terms && selectedTerm.search_terms.length > 0 && (
              <div className={styles.detailBlock}>
                <div className={styles.detailLabel}>Search Terms</div>
                <div className={styles.searchTermsList}>
                  {selectedTerm.search_terms.map((st) => (
                    <Chip key={st} truncate className={styles.searchTermChip}>
                      {st}
                    </Chip>
                  ))}
                </div>
              </div>
            )}
            {!isVisitor && (
            <div className={styles.detailActions}>
              <RowActionButton onClick={() => handleSearch(selectedTerm)} title="Search articles">
                Search articles
              </RowActionButton>
              <RowActionButton onClick={() => setEditingTerm(selectedTerm)}>Edit</RowActionButton>
              {!selectedTerm.is_system && (
                <RowActionButton danger onClick={() => handleDelete(selectedTerm)}>
                  Delete
                </RowActionButton>
              )}
            </div>
            )}
          </aside>
        )}
      </div>

      {(showAddModal || editingTerm) && (
        <GlossaryFormModal
          term={editingTerm}
          categories={categories ?? []}
          onClose={() => {
            setShowAddModal(false);
            setEditingTerm(null);
          }}
        />
      )}
    </div>
  );
}

interface GlossaryFormModalProps {
  term: GlossaryTerm | null;
  categories: { name: string; is_nist: boolean; color: string }[];
  onClose: () => void;
}

function GlossaryFormModal({ term, categories, onClose }: GlossaryFormModalProps) {
  const isEditing = !!term;
  const createTerm = useCreateGlossaryTerm();
  const updateTerm = useUpdateGlossaryTerm();

  const [name, setName] = useState(term?.name || "");
  const [category, setCategory] = useState(term?.category || "protect");
  const [customCategory, setCustomCategory] = useState("");
  const [useCustomCategory, setUseCustomCategory] = useState(false);
  const [maturity, setMaturity] = useState(term?.maturity || "");
  const [description, setDescription] = useState(term?.description || "");
  const [longDescription, setLongDescription] = useState(term?.long_description || "");
  const [technologies, setTechnologies] = useState<GlossaryTechnology[]>(
    term?.technologies || [],
  );
  const [searchTerms, setSearchTerms] = useState<string[]>(term?.search_terms || []);
  const [error, setError] = useState<string | null>(null);

  const handleAddSearchTerm = () => {
    setSearchTerms([...searchTerms, ""]);
  };

  const handleRemoveSearchTerm = (index: number) => {
    setSearchTerms(searchTerms.filter((_, i) => i !== index));
  };

  const handleSearchTermChange = (index: number, value: string) => {
    const updated = [...searchTerms];
    updated[index] = value;
    setSearchTerms(updated);
  };

  const handleAddTech = () => {
    setTechnologies([...technologies, { name: "", url: null }]);
  };

  const handleRemoveTech = (index: number) => {
    setTechnologies(technologies.filter((_, i) => i !== index));
  };

  const handleTechChange = (index: number, field: "name" | "url", value: string) => {
    const updated = [...technologies];
    if (field === "url") {
      updated[index] = { ...updated[index], [field]: value || null };
    } else {
      updated[index] = { ...updated[index], [field]: value };
    }
    setTechnologies(updated);
  };

  const handleSubmit = async () => {
    const finalCategory = useCustomCategory ? customCategory.trim() : category;
    if (!name.trim() || !finalCategory || !description.trim()) {
      setError("Name, category, and description are required.");
      return;
    }

    const data = {
      name: name.trim(),
      category: finalCategory.toLowerCase(),
      maturity: maturity || undefined,
      description: description.trim(),
      long_description: longDescription.trim() || undefined,
      technologies: technologies.filter((t) => t.name.trim()),
      search_terms: searchTerms.filter((s) => s.trim()),
    };

    try {
      if (isEditing && term) {
        await updateTerm.mutateAsync({ id: term.id, data });
      } else {
        await createTerm.mutateAsync(data);
      }
      onClose();
    } catch {
      setError("Failed to save term. It may already exist.");
    }
  };

  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <h2>{isEditing ? "Edit Term" : "Add Term"}</h2>
          <button className={styles.modalClose} onClick={onClose}>
            &times;
          </button>
        </div>

        <div className={styles.modalBody}>
          {error && <div className={styles.modalError}>{error}</div>}

          <div className={styles.formField}>
            <label>Term Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g., Zero Trust Architecture"
            />
          </div>

          <div className={styles.formField}>
            <label>
              Search Terms
              <button type="button" className={styles.addTechBtn} onClick={handleAddSearchTerm}>
                + Add
              </button>
            </label>
            <span className={styles.fieldHint}>
              Alternate names or abbreviations used to match this term in articles
            </span>
            {searchTerms.map((st, i) => (
              <div key={i} className={styles.techRow}>
                <input
                  type="text"
                  value={st}
                  onChange={(e) => handleSearchTermChange(i, e.target.value)}
                  placeholder="e.g., ZTA, zero-trust"
                  className={styles.techNameInput}
                />
                <button
                  type="button"
                  className={styles.removeTechBtn}
                  onClick={() => handleRemoveSearchTerm(i)}
                >
                  &times;
                </button>
              </div>
            ))}
          </div>

          <div className={styles.formRow}>
            <div className={styles.formField}>
              <label>Category</label>
              {useCustomCategory ? (
                <input
                  type="text"
                  value={customCategory}
                  onChange={(e) => setCustomCategory(e.target.value)}
                  placeholder="Custom category..."
                />
              ) : (
                <select value={category} onChange={(e) => setCategory(e.target.value)}>
                  {categories
                    .filter((c) => c.is_nist)
                    .map((c) => (
                      <option key={c.name} value={c.name}>
                        {c.name.charAt(0).toUpperCase() + c.name.slice(1)}
                      </option>
                    ))}
                </select>
              )}
              <label className={styles.checkboxLabel}>
                <input
                  type="checkbox"
                  checked={useCustomCategory}
                  onChange={(e) => setUseCustomCategory(e.target.checked)}
                />
                Custom category
              </label>
            </div>

            <div className={styles.formField}>
              <label>Maturity</label>
              <select value={maturity} onChange={(e) => setMaturity(e.target.value)}>
                <option value="">None</option>
                <option value="emerging">Emerging</option>
                <option value="trending">Trending</option>
                <option value="mature">Mature</option>
              </select>
            </div>
          </div>

          <div className={styles.formField}>
            <label>Short Description</label>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Brief description..."
            />
          </div>

          <div className={styles.formField}>
            <label>Detailed Description</label>
            <textarea
              value={longDescription}
              onChange={(e) => setLongDescription(e.target.value)}
              placeholder="Full explanation (optional)..."
              rows={4}
            />
          </div>

          <div className={styles.formField}>
            <label>
              Technologies
              <button type="button" className={styles.addTechBtn} onClick={handleAddTech}>
                + Add
              </button>
            </label>
            {technologies.map((tech, i) => (
              <div key={i} className={styles.techRow}>
                <input
                  type="text"
                  value={tech.name}
                  onChange={(e) => handleTechChange(i, "name", e.target.value)}
                  placeholder="Name"
                  className={styles.techNameInput}
                />
                <input
                  type="text"
                  value={tech.url || ""}
                  onChange={(e) => handleTechChange(i, "url", e.target.value)}
                  placeholder="URL (optional)"
                  className={styles.techUrlInput}
                />
                <button
                  type="button"
                  className={styles.removeTechBtn}
                  onClick={() => handleRemoveTech(i)}
                >
                  &times;
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className={styles.modalFooter}>
          <button className={styles.cancelBtn} onClick={onClose}>
            Cancel
          </button>
          <button
            className={styles.saveBtn}
            onClick={handleSubmit}
            disabled={createTerm.isPending || updateTerm.isPending}
          >
            {createTerm.isPending || updateTerm.isPending ? "Saving..." : isEditing ? "Update" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
