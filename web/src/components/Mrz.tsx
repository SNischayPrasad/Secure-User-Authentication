import { splitFiller } from "../lib/mrz";

/** Renders MRZ lines with the filler characters dimmed, so the strip reads as a document. */
export function Mrz({ lines, className }: { lines: [string, string]; className?: string }) {
  return (
    <div className={className} aria-hidden="true">
      {lines.map((line, index) => (
        <span className="mrz__line" key={index}>
          {splitFiller(line).map((run, runIndex) =>
            run.filler ? (
              <span className="mrz__fill" key={runIndex}>
                {run.text}
              </span>
            ) : (
              <span key={runIndex}>{run.text}</span>
            ),
          )}
        </span>
      ))}
    </div>
  );
}
