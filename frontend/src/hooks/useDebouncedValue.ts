import { useEffect, useState } from "react";

/** `value`, settled for `ms` — for search boxes that drive a query. */
export function useDebouncedValue<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const h = setTimeout(() => setSettled(value), ms);
    return () => clearTimeout(h);
  }, [value, ms]);
  return settled;
}
