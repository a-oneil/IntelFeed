import { useRef, useCallback } from "react";

interface LongPressHandlers {
  onTouchStart: (e: React.TouchEvent) => void;
  onTouchEnd: () => void;
  onTouchMove: () => void;
  onContextMenu: (e: React.MouseEvent) => void;
}

interface LongPressConfig {
  onLongPress: (position: { x: number; y: number }) => void;
  duration?: number;
  onContextMenu?: (e: React.MouseEvent) => void;
}

export function useLongPress(config: LongPressConfig): LongPressHandlers {
  const { onLongPress, duration = 500, onContextMenu } = config;
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const firedRef = useRef(false);

  const clear = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const handleTouchStart = useCallback(
    (e: React.TouchEvent) => {
      firedRef.current = false;
      const touch = e.touches[0];
      const x = touch.clientX;
      const y = touch.clientY;
      timerRef.current = setTimeout(() => {
        firedRef.current = true;
        onLongPress({ x, y });
        if (navigator.vibrate) {
          navigator.vibrate(10);
        }
      }, duration);
    },
    [onLongPress, duration]
  );

  const handleTouchEnd = useCallback(() => {
    clear();
  }, [clear]);

  const handleTouchMove = useCallback(() => {
    clear();
  }, [clear]);

  const handleContextMenu = useCallback(
    (e: React.MouseEvent) => {
      if (onContextMenu) {
        onContextMenu(e);
      }
    },
    [onContextMenu]
  );

  return {
    onTouchStart: handleTouchStart,
    onTouchEnd: handleTouchEnd,
    onTouchMove: handleTouchMove,
    onContextMenu: handleContextMenu,
  };
}
