export class ApiError extends Error { constructor(msg: string, public status: number) { super(msg); } }

export async function api<T>(path: string, init?: { method?: "GET" | "POST"; body?: unknown }): Promise<T> {
  const r = await fetch(`/api/proxy/${path}`, {
    method: init?.method ?? "GET",
    headers: { "content-type": "application/json", "x-qs-csrf": "1" },
    body: init?.body !== undefined ? JSON.stringify(init.body) : undefined,
    cache: "no-store",
  });
  if (r.status === 401 && typeof window !== "undefined") { window.location.href = "/login"; throw new ApiError("session expired", 401); }
  const j = await r.json().catch(() => null);
  if (!r.ok) {
    const d = j?.detail;
    throw new ApiError(typeof d === "string" ? d : Array.isArray(d) ? d.map((x: { msg: string }) => x.msg).join("; ") : r.statusText, r.status);
  }
  return j as T;
}
export const S = "sentinel";
