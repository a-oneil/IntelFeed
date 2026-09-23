import { useState, type KeyboardEvent } from "react";
import { Chip } from "./primitives";
import styles from "./SimpleTagEditor.module.css";

interface SimpleTagEditorProps {
  tags: string[];
  onChange: (tags: string[]) => void;
  placeholder?: string;
}

export default function SimpleTagEditor({
  tags,
  onChange,
  placeholder = "Add tag...",
}: SimpleTagEditorProps) {
  const [input, setInput] = useState("");

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && input.trim()) {
      e.preventDefault();
      const tag = input.trim();
      if (!tags.includes(tag)) {
        onChange([...tags, tag]);
      }
      setInput("");
    } else if (e.key === "Backspace" && !input && tags.length > 0) {
      onChange(tags.slice(0, -1));
    }
  };

  const removeTag = (tag: string) => {
    onChange(tags.filter((t) => t !== tag));
  };

  return (
    <div className={styles.container}>
      <div className={styles.tags}>
        {tags.map((tag) => (
          <Chip key={tag} className={styles.tag}>
            {tag}
            <button
              className={styles.remove}
              onClick={() => removeTag(tag)}
              type="button"
            >
              ×
            </button>
          </Chip>
        ))}
        <input
          className={styles.input}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={tags.length === 0 ? placeholder : ""}
        />
      </div>
    </div>
  );
}
