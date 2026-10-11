export function ComingSoon({ title, note }: { title: string; note?: string }) {
  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">{title}</h1>
      </header>
      <div className="rounded-lg border border-dashed border-slate-800 bg-slate-900/30 px-6 py-16 text-center">
        <p className="text-sm text-slate-500">
          {note ?? "This page is wired into the nav per section 18 but not yet built out."}
        </p>
      </div>
    </div>
  );
}
