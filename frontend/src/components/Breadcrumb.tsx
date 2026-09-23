import { useNavigate } from "react-router-dom";
import styles from "./Breadcrumb.module.css";

export interface BreadcrumbItem {
  label: string;
  to?: string;
  onClick?: () => void;
}

interface BreadcrumbProps {
  items: BreadcrumbItem[];
}

export function Breadcrumb({ items }: BreadcrumbProps) {
  const navigate = useNavigate();

  return (
    <nav className={styles.breadcrumb} aria-label="Breadcrumb">
      <ol className={styles.list}>
        {items.map((item, i) => {
          const isLast = i === items.length - 1;
          const isClickable = !isLast && (item.to || item.onClick);
          return (
            <li key={i} className={styles.item}>
              {i > 0 && <span className={styles.separator}>/</span>}
              {isClickable ? (
                <button
                  className={styles.link}
                  onClick={() => item.onClick ? item.onClick() : navigate(item.to!)}
                >
                  {item.label}
                </button>
              ) : (
                <span className={styles.current}>{item.label}</span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
