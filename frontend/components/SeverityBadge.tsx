import { SEVERITY_STYLES } from "@/lib/format";
import type { Severity } from "@/lib/types";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const style = SEVERITY_STYLES[severity];
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ring-1 ${style.bg} ${style.text} ${style.ring}`}
    >
      {severity}
    </span>
  );
}
