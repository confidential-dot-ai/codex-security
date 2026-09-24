/** A plain bordered card: 1px warm border, no shadow, matches the site. */
export function Card({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={`rounded-lg border border-border bg-card p-4 sm:p-5 ${className}`}>
      {children}
    </div>
  );
}
