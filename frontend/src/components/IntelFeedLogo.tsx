import { FEED_DOT, HEXAGON, HEXAGRAM, MARK_WEIGHTS, NODES, WAVES } from "@/utils/brandMark";

interface IntelFeedLogoProps {
  size?: number;
  className?: string;
}

/**
 * The IntelFeed mark (utils/brandMark.ts). Uses currentColor so it takes the
 * theme's accent; at 32px and below it uses the heavier SMALL weights.
 */
export function IntelFeedLogo({ size = 22, className }: IntelFeedLogoProps) {
  const w = size <= 32 ? MARK_WEIGHTS.SMALL : MARK_WEIGHTS.FULL;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden="true"
    >
      <path d={HEXAGON} stroke="currentColor" strokeWidth={w.hex} strokeLinejoin="round" />
      {HEXAGRAM.map((d) => (
        <path key={d} d={d} stroke="currentColor" strokeWidth={w.net} strokeLinejoin="round" opacity={w.netOpacity} />
      ))}
      <g fill="currentColor">
        {NODES.map(([x, y]) => (
          <circle key={`${x},${y}`} cx={x} cy={y} r={w.node} />
        ))}
        <circle cx={FEED_DOT[0]} cy={FEED_DOT[1]} r={w.feed} />
      </g>
      {WAVES.map((d) => (
        <path key={d} d={d} stroke="currentColor" strokeWidth={w.wave} strokeLinecap="round" />
      ))}
    </svg>
  );
}
