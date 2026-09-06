import { STRENGTH_COLOUR, STRENGTH_LABEL, type Assessment } from "../lib/password";

/**
 * Four grade marks, the way a document carries security-grade stamps. It reports the same
 * policy the server enforces, so what the meter accepts is what the API accepts.
 */
export function PasswordMeter({ value, assessment }: { value: string; assessment: Assessment }) {
  if (!value) return null;

  return (
    <div>
      <div className="meter" aria-hidden="true">
        {[1, 2, 3, 4].map((step) => (
          <span
            key={step}
            className="meter__seg"
            data-on={assessment.score >= step}
            style={{ ["--level" as string]: STRENGTH_COLOUR[assessment.score] }}
          />
        ))}
      </div>

      <p className="meter__caption" role="status">
        {STRENGTH_LABEL[assessment.score]}
        {assessment.ok ? " — meets the policy" : ""}
      </p>

      {assessment.issues.length ? (
        <ul className="meter__issues">
          {assessment.issues.map((issue) => (
            <li key={issue}>{issue}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
