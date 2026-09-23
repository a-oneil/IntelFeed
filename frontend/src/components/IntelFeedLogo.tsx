interface IntelFeedLogoProps {
  size?: number;
  className?: string;
}

/**
 * SVG logo component inspired by the IntelFeed brand:
 * Hexagonal network wireframe (hexagram with inner nodes) + RSS signal waves.
 * Uses currentColor so it inherits the accent theme color.
 */
export function IntelFeedLogo({ size = 22, className }: IntelFeedLogoProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
    >
      {/* Hexagon outline */}
      <path
        d="M12 2L21.2 7.5V16.5L12 22L2.8 16.5V7.5Z"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinejoin="round"
        fill="none"
      />
      {/* Internal network lines — hexagram (two overlapping triangles) */}
      {/* Triangle 1: V1→V3→V5 */}
      <path
        d="M12 2L21.2 16.5L2.8 16.5Z"
        stroke="currentColor"
        strokeWidth="0.7"
        strokeLinejoin="round"
        fill="none"
        opacity="0.6"
      />
      {/* Triangle 2: V2→V4→V6 */}
      <path
        d="M21.2 7.5L12 22L2.8 7.5Z"
        stroke="currentColor"
        strokeWidth="0.7"
        strokeLinejoin="round"
        fill="none"
        opacity="0.6"
      />
      {/* Outer vertex nodes */}
      <circle cx="12" cy="2" r="1.1" fill="currentColor" />
      <circle cx="21.2" cy="7.5" r="1.1" fill="currentColor" />
      <circle cx="21.2" cy="16.5" r="1.1" fill="currentColor" />
      <circle cx="12" cy="22" r="1.1" fill="currentColor" />
      <circle cx="2.8" cy="16.5" r="1.1" fill="currentColor" />
      <circle cx="2.8" cy="7.5" r="1.1" fill="currentColor" />
      {/* Inner intersection nodes (hexagram creates inner hexagon) */}
      <circle cx="15.5" cy="7.5" r="0.8" fill="currentColor" />
      <circle cx="18.3" cy="12" r="0.8" fill="currentColor" />
      <circle cx="15.5" cy="16.5" r="0.8" fill="currentColor" />
      <circle cx="8.5" cy="16.5" r="0.8" fill="currentColor" />
      <circle cx="5.7" cy="12" r="0.8" fill="currentColor" />
      <circle cx="8.5" cy="7.5" r="0.8" fill="currentColor" />
      {/* RSS signal waves */}
      <circle cx="8.5" cy="15.5" r="1.3" fill="currentColor" />
      <path
        d="M8.5 12.5C10.16 12.5 11.5 13.84 11.5 15.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        fill="none"
      />
      <path
        d="M8.5 9.8C11.65 9.8 14.2 12.35 14.2 15.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        fill="none"
      />
    </svg>
  );
}
