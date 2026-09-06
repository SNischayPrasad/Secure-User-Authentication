import type { ButtonHTMLAttributes, ReactNode } from "react";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "ghost" | "danger";
  size?: "md" | "sm";
  block?: boolean;
  busy?: boolean;
  children: ReactNode;
};

/**
 * A button that stays the same width while it works, so the layout does not jump, and that
 * announces its busy state to assistive technology rather than only spinning.
 */
export function Button({
  variant = "default",
  size = "md",
  block,
  busy,
  children,
  disabled,
  className,
  ...rest
}: Props) {
  const classes = [
    "btn",
    variant !== "default" ? `btn--${variant}` : "",
    size === "sm" ? "btn--sm" : "",
    block ? "btn--block" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <button {...rest} className={classes} disabled={disabled || busy} aria-busy={busy || undefined}>
      {busy ? <span className="btn__spinner" aria-hidden="true" /> : null}
      {children}
    </button>
  );
}
