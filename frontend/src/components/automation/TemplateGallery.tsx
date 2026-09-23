import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import api from "@/api/client";
import styles from "./TemplateGallery.module.css";

interface TemplateAction {
  type: string;
  config: Record<string, unknown>;
  [key: string]: unknown;
}

export interface AutomationTemplate {
  id: string;
  name: string;
  description: string;
  category: string;
  tags: string[];
  trigger_type: string;
  trigger_config: Record<string, unknown>;
  conditions: Record<string, unknown>;
  actions: TemplateAction[];
}

interface TemplateCategory {
  id: string;
  name: string;
  description: string;
}

interface TemplatesResponse {
  templates: AutomationTemplate[];
  categories: TemplateCategory[];
}

const CATEGORY_ICONS: Record<string, string> = {
  intelligence: "\u{1F50D}",
  detection: "\u{1F6E1}",
  alerting: "\u{1F514}",
  triage: "\u{1F4CB}",
  ai: "\u{2728}",
  reporting: "\u{1F4CA}",
  integration: "\u{1F517}",
};

function formatTrigger(trigger: string): string {
  return trigger.replace("on_", "").replace(/_/g, " ");
}

function formatActionType(type: string): string {
  return type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

interface Props {
  onClose: () => void;
  /** Create a rule from the template and open it in the builder. */
  onUseTemplate: (template: AutomationTemplate) => Promise<void> | void;
}

export function TemplateGallery({ onClose, onUseTemplate }: Props) {
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [expandedTemplate, setExpandedTemplate] = useState<string | null>(null);
  const [usingId, setUsingId] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["automation-templates"],
    queryFn: async () => {
      const res = await api.get<TemplatesResponse>("/automation/templates");
      return res.data;
    },
  });

  const templates = data?.templates ?? [];
  const categories = data?.categories ?? [];

  const filtered = templates.filter((t) => {
    if (selectedCategory && t.category !== selectedCategory) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        t.name.toLowerCase().includes(q) ||
        t.description.toLowerCase().includes(q) ||
        t.tags.some((tag) => tag.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const handleUseTemplate = async (template: AutomationTemplate) => {
    if (usingId) return;
    setUsingId(template.id);
    try {
      await onUseTemplate(template);
    } finally {
      setUsingId(null);
    }
  };

  // Group by category when browsing everything; a flat list when searching or
  // filtered to a single category.
  const grouped =
    selectedCategory || search
      ? null
      : categories
          .map((cat) => ({
            cat,
            items: filtered.filter((t) => t.category === cat.id),
          }))
          .filter((g) => g.items.length > 0);

  const renderCard = (template: AutomationTemplate) => {
    const isExpanded = expandedTemplate === template.id;
    const isUsing = usingId === template.id;
    return (
      <div
        key={template.id}
        className={styles.card}
        role="button"
        tabIndex={0}
        onClick={() => handleUseTemplate(template)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            handleUseTemplate(template);
          }
        }}
        aria-disabled={usingId !== null}
      >
        <div className={styles.cardHeader}>
          <span className={styles.cardIcon}>
            {CATEGORY_ICONS[template.category] || ""}
          </span>
          <div className={styles.cardTitleGroup}>
            <h3 className={styles.cardTitle}>{template.name}</h3>
            <span className={styles.triggerBadge}>
              {formatTrigger(template.trigger_type)}
            </span>
          </div>
        </div>
        <p className={styles.cardDesc}>{template.description}</p>

        <div className={styles.cardTags}>
          {template.tags.map((tag) => (
            <span key={tag} className={styles.tag}>
              {tag}
            </span>
          ))}
        </div>

        <button
          className={styles.detailsToggle}
          onClick={(e) => {
            e.stopPropagation();
            setExpandedTemplate(isExpanded ? null : template.id);
          }}
        >
          {isExpanded ? "Hide details" : "Show details"}
          <span className={styles.detailsArrow} data-expanded={isExpanded}>
            &#9656;
          </span>
        </button>

        {isExpanded && (
          <div className={styles.details} onClick={(e) => e.stopPropagation()}>
            {Object.keys(template.conditions).length > 0 && (
              <div className={styles.detailSection}>
                <span className={styles.detailLabel}>Conditions</span>
                <span className={styles.detailValue}>
                  {(
                    (
                      template.conditions as {
                        conditions?: { type: string }[];
                      }
                    ).conditions ?? []
                  )
                    .map((c) => formatActionType(c.type))
                    .join(", ") || "None"}
                </span>
              </div>
            )}
            <div className={styles.detailSection}>
              <span className={styles.detailLabel}>
                Actions ({template.actions.length})
              </span>
              <div className={styles.actionList}>
                {template.actions.map((action, i) => (
                  <span key={i} className={styles.actionChip}>
                    {formatActionType(action.type)}
                  </span>
                ))}
              </div>
            </div>
            {template.trigger_config &&
              Object.keys(template.trigger_config).length > 0 && (
                <div className={styles.detailSection}>
                  <span className={styles.detailLabel}>Trigger config</span>
                  <code className={styles.configCode}>
                    {JSON.stringify(template.trigger_config, null, 2)}
                  </code>
                </div>
              )}
          </div>
        )}

        <div className={styles.cardFooter}>
          <span className={styles.useHint}>
            {isUsing ? "Opening…" : "Open in builder →"}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <h2 className={styles.title}>Template Gallery</h2>
          <span className={styles.subtitle}>
            {filtered.length} template{filtered.length !== 1 ? "s" : ""}
          </span>
        </div>
        <button onClick={onClose} className={styles.closeBtn}>
          &times;
        </button>
      </div>

      <div className={styles.filters}>
        <input
          type="text"
          placeholder="Search templates..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className={styles.searchInput}
        />
        <div className={styles.categoryFilters}>
          <button
            className={`${styles.categoryChip} ${selectedCategory === null ? styles.categoryActive : ""}`}
            onClick={() => setSelectedCategory(null)}
          >
            All
          </button>
          {categories.map((cat) => (
            <button
              key={cat.id}
              className={`${styles.categoryChip} ${selectedCategory === cat.id ? styles.categoryActive : ""}`}
              onClick={() =>
                setSelectedCategory(
                  selectedCategory === cat.id ? null : cat.id
                )
              }
              title={cat.description}
            >
              {CATEGORY_ICONS[cat.id] || ""} {cat.name}
            </button>
          ))}
        </div>
      </div>

      <div className={styles.scroll}>
        {isLoading && <p className={styles.muted}>Loading templates...</p>}
        {!isLoading && filtered.length === 0 && (
          <p className={styles.muted}>No templates match your search.</p>
        )}

        {grouped
          ? grouped.map(({ cat, items }) => (
              <section key={cat.id} className={styles.group}>
                <div className={styles.groupHeader}>
                  <span className={styles.groupIcon}>
                    {CATEGORY_ICONS[cat.id] || ""}
                  </span>
                  <h3 className={styles.groupTitle}>{cat.name}</h3>
                  <span className={styles.groupCount}>{items.length}</span>
                  {cat.description && (
                    <span className={styles.groupDesc}>{cat.description}</span>
                  )}
                </div>
                <div className={styles.grid}>{items.map(renderCard)}</div>
              </section>
            ))
          : filtered.length > 0 && (
              <div className={styles.grid}>{filtered.map(renderCard)}</div>
            )}
      </div>
    </div>
  );
}
