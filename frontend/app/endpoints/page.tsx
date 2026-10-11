import { StatCard } from "@/components/StatusBadges";

interface EndpointItem {
  id: string;
  url: string;
  method: string;
  parameters: string[];
  source: string;
  statusCode: number;
  contentType: string;
}

const mockEndpoints: EndpointItem[] = [
  {
    id: "e1",
    url: "https://api.example.com/users",
    method: "GET",
    parameters: ["page", "limit"],
    source: "katana",
    statusCode: 200,
    contentType: "application/json",
  },
  {
    id: "e2",
    url: "https://api.example.com/login",
    method: "POST",
    parameters: ["email", "password"],
    source: "katana",
    statusCode: 200,
    contentType: "application/json",
  },
  {
    id: "e3",
    url: "https://api.example.com/orders/{id}",
    method: "GET",
    parameters: ["id"],
    source: "gau",
    statusCode: 200,
    contentType: "application/json",
  },
  {
    id: "e4",
    url: "https://example.com/search",
    method: "GET",
    parameters: ["q", "page"],
    source: "katana",
    statusCode: 200,
    contentType: "text/html",
  },
  {
    id: "e5",
    url: "https://example.com/admin/dashboard",
    method: "GET",
    parameters: [],
    source: "ffuf",
    statusCode: 403,
    contentType: "text/html",
  },
  {
    id: "e6",
    url: "https://api.example.com/upload",
    method: "POST",
    parameters: ["file"],
    source: "katana",
    statusCode: 200,
    contentType: "multipart/form-data",
  },
];

function getMethodBadge(method: string) {
  const m = method.toUpperCase();
  let style = "bg-slate-500/10 text-slate-400 ring-slate-500/20";
  if (m === "GET") style = "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30";
  else if (m === "POST") style = "bg-sky-500/10 text-sky-400 ring-sky-500/30";
  else if (m === "PUT") style = "bg-amber-500/10 text-amber-400 ring-amber-500/30";
  else if (m === "DELETE") style = "bg-rose-500/10 text-rose-400 ring-rose-500/30";
  else if (m === "PATCH") style = "bg-purple-500/10 text-purple-400 ring-purple-500/30";

  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-mono font-medium ring-1 ${style}`}>
      {m}
    </span>
  );
}

function getStatusCodeBadge(code: number) {
  if (code >= 200 && code < 300) {
    return (
      <span className="font-mono text-xs text-emerald-400">
        {code}
      </span>
    );
  }
  if (code >= 300 && code < 500) {
    return (
      <span className="font-mono text-xs text-amber-400">
        {code}
      </span>
    );
  }
  return (
    <span className="font-mono text-xs text-rose-400">
      {code}
    </span>
  );
}

export default function EndpointsPage() {
  const total = mockEndpoints.length;
  const getCount = mockEndpoints.filter((e) => e.method === "GET").length;
  const postCount = mockEndpoints.filter((e) => e.method === "POST").length;
  const withParamsCount = mockEndpoints.filter((e) => e.parameters.length > 0).length;

  return (
    <div className="p-8">
      <header className="mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Discovered Endpoints</h1>
        <p className="mt-1 text-sm text-slate-500">
          Crawled and discovered HTTP endpoints with parameters and content types.
        </p>
      </header>

      <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Discovered Endpoints" value={total} accent="cyan" />
        <StatCard label="GET Endpoints" value={getCount} accent="emerald" />
        <StatCard label="POST Endpoints" value={postCount} accent="cyan" />
        <StatCard label="Parameterized" value={withParamsCount} accent="amber" />
      </div>

      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/50">
        <div className="border-b border-slate-800 px-4 py-3 text-sm font-medium text-slate-300">
          Endpoint Directory
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/70 text-xs uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3 font-medium">Method</th>
                <th className="px-4 py-3 font-medium">URL Endpoint</th>
                <th className="px-4 py-3 font-medium">Parameters</th>
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Content Type</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 bg-slate-950">
              {mockEndpoints.map((ep) => (
                <tr key={ep.id} className="hover:bg-slate-900/60 transition-colors">
                  <td className="px-4 py-3">{getMethodBadge(ep.method)}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-200">
                    {ep.url}
                  </td>
                  <td className="px-4 py-3">
                    {ep.parameters.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {ep.parameters.map((param) => (
                          <span
                            key={param}
                            className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-amber-300 ring-1 ring-amber-500/20"
                          >
                            {param}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-slate-800 px-2 py-0.5 font-mono text-xs text-slate-300">
                      {ep.source}
                    </span>
                  </td>
                  <td className="px-4 py-3">{getStatusCodeBadge(ep.statusCode)}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-400">
                    {ep.contentType}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
