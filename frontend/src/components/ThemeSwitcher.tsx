import { useState, useMemo } from "react";
import { toast } from "sonner";
import {
  useThemes,
  useSetThemePreference,
  useSetDefaultTheme,
  useCreateTheme,
  useUpdateTheme,
  useDeleteTheme,
  useDuplicateTheme,
  applyTheme,
} from "@/hooks/useThemes";
import { useAuthStore } from "@/stores/authStore";
import type { Theme } from "@/api/types";
import ThemeEditor from "./ThemeEditor";
import { useUndoableDelete } from "@/hooks/useUndoableDelete";
import styles from "./ThemeSwitcher.module.css";
import { AsyncStateLoading } from "@/components/AsyncState";

export default function ThemeSwitcher() {
  const { data: themes, isLoading } = useThemes();
  const setPreference = useSetThemePreference();
  const setDefaultTheme = useSetDefaultTheme();
  const createTheme = useCreateTheme();
  const updateTheme = useUpdateTheme();
  const deleteTheme = useDeleteTheme();
  const undoableDelete = useUndoableDelete();
  const duplicateTheme = useDuplicateTheme();

  const user = useAuthStore((s) => s.user);
  const isAdmin = user?.role === "admin";

  // Determine active theme: prefer user.theme_id, fall back to localStorage
  const activeId = useMemo(() => {
    if (user?.theme_id) return user.theme_id;
    return localStorage.getItem("intelfeed-theme-id");
  }, [user?.theme_id]);

  // Editor modal state
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingTheme, setEditingTheme] = useState<Theme | undefined>(undefined);

  // Split themes into system, the caller's own, and other users' custom themes.
  const systemThemes = useMemo(
    () => themes?.filter((t) => t.is_system) ?? [],
    [themes],
  );
  const myThemes = useMemo(
    () => themes?.filter((t) => !t.is_system && t.created_by === user?.id) ?? [],
    [themes, user?.id],
  );
  const sharedThemes = useMemo(
    () => themes?.filter((t) => !t.is_system && t.created_by && t.created_by !== user?.id) ?? [],
    [themes, user?.id],
  );

  const handleSelect = (theme: Theme) => {
    // Picked deliberately, so it sticks to this browser past logout.
    applyTheme(theme, "user");
    setPreference.mutate({ theme_id: theme.id });
  };

  const handleSetDefault = (theme: Theme) => {
    const clearing = theme.is_default;
    setDefaultTheme.mutate(
      { id: theme.id, clear: clearing },
      {
        onSuccess: () => {
          toast.success(
            clearing
              ? "Default theme cleared"
              : `"${theme.name}" is now the default theme for users without their own`,
          );
        },
        onError: () => {
          toast.error(clearing ? "Failed to clear default theme" : "Failed to set default theme");
        },
      },
    );
  };

  const handleUseDefault = () => {
    setPreference.mutate({ clear_theme: true });
    const instanceDefault = themes?.find((t) => t.is_default);
    if (instanceDefault) applyTheme(instanceDefault, "default");
  };

  const handleCreate = () => {
    setEditingTheme(undefined);
    setEditorOpen(true);
  };

  const handleEdit = (theme: Theme) => {
    setEditingTheme(theme);
    setEditorOpen(true);
  };

  const handleDuplicate = (theme: Theme) => {
    const newName = prompt("Enter a name for the duplicated theme:", `${theme.name} (copy)`);
    if (!newName) return;

    duplicateTheme.mutate(
      { id: theme.id, name: newName },
      {
        onSuccess: (duplicated) => {
          setEditingTheme(duplicated);
          setEditorOpen(true);
        },
      },
    );
  };

  const handleDelete = (theme: Theme) => {
    undoableDelete({
      label: `Theme "${theme.name}"`,
      key: `theme-${theme.id}`,
      onDelete: () => deleteTheme.mutate(theme.id),
    });
  };

  const handleEditorSave = (name: string, vars: Record<string, string>) => {
    if (editingTheme) {
      // Update existing user theme
      updateTheme.mutate(
        { id: editingTheme.id, name, css_variables: vars },
        {
          onSuccess: (updated) => {
            setEditorOpen(false);
            setEditingTheme(undefined);
            // Apply updated theme if it was the active one
            if (activeId === updated.id) {
              applyTheme(updated);
            }
          },
        },
      );
    } else {
      // Create new theme
      createTheme.mutate(
        { name, css_variables: vars },
        {
          onSuccess: (created) => {
            setEditorOpen(false);
            setEditingTheme(undefined);
            // Auto-apply the newly created theme
            handleSelect(created);
          },
        },
      );
    }
  };

  if (isLoading) return <AsyncStateLoading label="Loading themes…" compact />;

  return (
    <div className={styles.container}>
      <h3 className={styles.title}>Appearance</h3>

      {/* System Themes */}
      <div className={styles.sectionHeader}>
        <span className={styles.sectionLabel}>System Themes</span>
        {user?.theme_id && themes?.some((t) => t.is_default) && (
          <button className={styles.createBtn} onClick={handleUseDefault}>
            Use default theme
          </button>
        )}
      </div>
      <div className={styles.grid}>
        {systemThemes.map((theme) => (
          <ThemeCard
            key={theme.id}
            theme={theme}
            isActive={activeId === theme.id}
            onSelect={handleSelect}
            onDuplicate={handleDuplicate}
            onSetDefault={isAdmin ? handleSetDefault : undefined}
          />
        ))}
      </div>

      {/* My Themes */}
      <div className={styles.sectionHeader}>
        <span className={styles.sectionLabel}>My Themes</span>
        <button className={styles.createBtn} onClick={handleCreate}>
          + Create Theme
        </button>
      </div>
      {myThemes.length > 0 ? (
        <div className={styles.grid}>
          {myThemes.map((theme) => (
            <ThemeCard
              key={theme.id}
              theme={theme}
              isActive={activeId === theme.id}
              onSelect={handleSelect}
              onDuplicate={handleDuplicate}
              onEdit={handleEdit}
              onDelete={handleDelete}
              onSetDefault={isAdmin ? handleSetDefault : undefined}
            />
          ))}
        </div>
      ) : (
        <div className={styles.emptyState}>
          No custom themes yet. Create one or duplicate a system theme.
        </div>
      )}

      {/* Other users' custom themes: usable by anyone, editable only by admins */}
      {sharedThemes.length > 0 && (
        <>
          <div className={styles.sectionHeader}>
            <span className={styles.sectionLabel}>Shared themes</span>
          </div>
          <div className={styles.grid}>
            {sharedThemes.map((theme) => (
              <ThemeCard
                key={theme.id}
                theme={theme}
                isActive={activeId === theme.id}
                onSelect={handleSelect}
                onDuplicate={handleDuplicate}
                onEdit={isAdmin ? handleEdit : undefined}
                onDelete={isAdmin ? handleDelete : undefined}
                onSetDefault={isAdmin ? handleSetDefault : undefined}
              />
            ))}
          </div>
        </>
      )}

      {/* Theme Editor Modal */}
      {editorOpen && (
        <ThemeEditor
          theme={editingTheme}
          onSave={handleEditorSave}
          onClose={() => {
            setEditorOpen(false);
            setEditingTheme(undefined);
          }}
        />
      )}
    </div>
  );
}

interface ThemeCardProps {
  theme: Theme;
  isActive: boolean;
  onSelect: (theme: Theme) => void;
  onDuplicate: (theme: Theme) => void;
  onEdit?: (theme: Theme) => void;
  onDelete?: (theme: Theme) => void;
  onSetDefault?: (theme: Theme) => void;
}

function ThemeCard({
  theme,
  isActive,
  onSelect,
  onDuplicate,
  onEdit,
  onDelete,
  onSetDefault,
}: ThemeCardProps) {
  return (
    <button
      className={`${styles.card} ${isActive ? styles.active : ""}`}
      onClick={() => onSelect(theme)}
    >
      {theme.is_default && <span className={styles.defaultBadge}>Default</span>}

      {/* Action buttons shown on hover */}
      <div className={styles.cardActions} onClick={(e) => e.stopPropagation()}>
        <span
          className={styles.actionBtn}
          role="button"
          tabIndex={0}
          onClick={() => onDuplicate(theme)}
          onKeyDown={(e) => e.key === "Enter" && onDuplicate(theme)}
        >
          Duplicate
        </span>
        {onSetDefault && (
          <span
            className={styles.actionBtn}
            role="button"
            tabIndex={0}
            onClick={() => onSetDefault(theme)}
            onKeyDown={(e) => e.key === "Enter" && onSetDefault(theme)}
          >
            {theme.is_default ? "Clear default" : "Set default"}
          </span>
        )}
        {onEdit && (
          <span
            className={styles.actionBtn}
            role="button"
            tabIndex={0}
            onClick={() => onEdit(theme)}
            onKeyDown={(e) => e.key === "Enter" && onEdit(theme)}
          >
            Edit
          </span>
        )}
        {onDelete && (
          <span
            className={styles.deleteBtn}
            role="button"
            tabIndex={0}
            onClick={() => onDelete(theme)}
            onKeyDown={(e) => e.key === "Enter" && onDelete(theme)}
          >
            Delete
          </span>
        )}
      </div>

      {/* Theme preview thumbnail */}
      <div
        className={styles.preview}
        style={{
          backgroundColor: theme.css_variables["bg-primary"],
          borderColor: theme.css_variables["border"],
        }}
      >
        <div
          className={styles.previewSidebar}
          style={{
            backgroundColor:
              theme.css_variables["sidebar-bg"] ||
              theme.css_variables["bg-secondary"],
          }}
        >
          <div
            className={styles.previewDot}
            style={{ backgroundColor: theme.css_variables["accent"] }}
          />
          <div
            className={styles.previewDot}
            style={{ backgroundColor: theme.css_variables["text-muted"] }}
          />
          <div
            className={styles.previewDot}
            style={{ backgroundColor: theme.css_variables["text-muted"] }}
          />
        </div>
        <div className={styles.previewContent}>
          <div
            className={styles.previewLine}
            style={{
              backgroundColor: theme.css_variables["text-primary"],
              width: "60%",
            }}
          />
          <div
            className={styles.previewLine}
            style={{
              backgroundColor: theme.css_variables["text-secondary"],
              width: "80%",
            }}
          />
          <div
            className={styles.previewLine}
            style={{
              backgroundColor: theme.css_variables["text-muted"],
              width: "40%",
            }}
          />
        </div>
      </div>
      <span className={styles.name}>{theme.name}</span>
    </button>
  );
}
