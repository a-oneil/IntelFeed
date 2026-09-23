/**
 * VendorPicker — searchable vendor selector for the Product profile. Extracted
 * from the legacy EntityProfilePanel.
 */
import { useState, useRef, useEffect } from "react";
import { useVendors } from "@/hooks/useIntelligence";
import styles from "./entityProfile.module.css";

export function VendorPicker({
  currentVendorId,
  currentVendorName,
  onSelect,
  onOpenVendor,
}: {
  currentVendorId: string | null;
  currentVendorName: string | null;
  onSelect: (vendorId: string) => void | Promise<unknown>;
  onOpenVendor: (vendorId: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const containerRef = useRef<HTMLSpanElement>(null);
  const { data, isLoading } = useVendors(open ? { search: search || undefined, limit: 20 } : undefined);

  useEffect(() => {
    if (!open) return;
    const handleClick = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
        setSearch("");
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        setSearch("");
      }
    };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [open]);

  const handlePick = async (vendorId: string) => {
    setOpen(false);
    setSearch("");
    await onSelect(vendorId);
  };

  return (
    <span className={styles.vendorPicker} ref={containerRef}>
      {currentVendorId ? (
        <button className={styles.vendorLink} onClick={() => onOpenVendor(currentVendorId)}>
          {currentVendorName || "Unknown Vendor"}
        </button>
      ) : null}
      <button type="button" className={styles.vendorPickerTrigger} onClick={() => setOpen((v) => !v)}>
        {currentVendorId ? "Change" : "+ Add vendor"}
      </button>
      {open && (
        <div className={styles.vendorPickerDropdown}>
          <input
            autoFocus
            type="text"
            placeholder="Search vendors..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className={styles.vendorPickerInput}
          />
          <div className={styles.vendorPickerList}>
            {isLoading && <div className={styles.vendorPickerHint}>Loading...</div>}
            {!isLoading && data?.items.length === 0 && <div className={styles.vendorPickerHint}>No vendors found</div>}
            {data?.items.map((v) => (
              <button
                key={v.id}
                type="button"
                className={styles.vendorPickerItem}
                onMouseDown={(e) => {
                  e.preventDefault();
                  handlePick(v.id);
                }}
              >
                <span>{v.name}</span>
                {v.vendor_type && <span className={styles.vendorPickerItemType}>{v.vendor_type}</span>}
              </button>
            ))}
          </div>
        </div>
      )}
    </span>
  );
}
