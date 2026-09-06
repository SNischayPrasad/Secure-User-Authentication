import { useId, useState, type InputHTMLAttributes, type ReactNode } from "react";

type FieldProps = InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  /** Adds a show/hide control. Only used for password inputs. */
  revealable?: boolean;
  children?: ReactNode;
};

/**
 * One labelled input. The label is a real <label> bound by id, the error is announced through
 * aria-describedby, and invalid state is exposed with aria-invalid rather than colour alone.
 */
export function Field({ label, hint, error, revealable, children, ...input }: FieldProps) {
  const id = useId();
  const describedBy: string[] = [];
  if (hint) describedBy.push(`${id}-hint`);
  if (error) describedBy.push(`${id}-error`);

  const [revealed, setRevealed] = useState(false);
  const type = revealable ? (revealed ? "text" : "password") : input.type;

  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>
        <span>{label}</span>
        {revealable ? (
          <button
            type="button"
            className="field__reveal"
            onClick={() => setRevealed((value) => !value)}
            aria-pressed={revealed}
          >
            {revealed ? "Hide" : "Show"}
          </button>
        ) : null}
      </label>

      <input
        {...input}
        id={id}
        type={type}
        className="field__input"
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy.length ? describedBy.join(" ") : undefined}
      />

      {children}

      {hint ? (
        <div className="field__hint" id={`${id}-hint`}>
          {hint}
        </div>
      ) : null}

      {error ? (
        <p className="field__error" id={`${id}-error`}>
          <span>{error}</span>
        </p>
      ) : null}
    </div>
  );
}
