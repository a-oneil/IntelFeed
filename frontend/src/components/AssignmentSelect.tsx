import type { AIProvider } from "@/api/types";

/**
 * Provider/model picker for AI task assignments. Options come from each
 * provider's cached model list (populated by running Test on the provider).
 * Value format is "providerId|model", "" = unassigned.
 *
 * When `requiresTools` is set (agentic tasks), providers without tool support
 * are disabled — the backend rejects those assignments with 400 anyway.
 */
export default function AssignmentSelect({
  providers,
  value,
  onChange,
  requiresTools = false,
  placeholder = "Not assigned",
  className,
}: {
  providers: AIProvider[] | undefined;
  value: string;
  onChange: (providerId: string, model: string) => void;
  requiresTools?: boolean;
  placeholder?: string;
  className?: string;
}) {
  return (
    <select
      className={className}
      value={value}
      onChange={(e) => {
        const [providerId, model] = e.target.value.split("|");
        if (providerId && model) onChange(providerId, model);
      }}
    >
      <option value="">{placeholder}</option>
      {providers?.map((p) => {
        const incompatible = requiresTools && !p.supports_tools;
        return p.models.map((m) => (
          <option
            key={`${p.id}|${m}`}
            value={`${p.id}|${m}`}
            disabled={incompatible}
          >
            {p.name} / {m}
            {incompatible ? " — no tool support" : ""}
          </option>
        ));
      })}
    </select>
  );
}
