const readers = new Map<string, Set<() => void>>();
const views = new Map<string, unknown>();
export function registerReader(workspaceId: string, clear: () => void) {
  const group = readers.get(workspaceId) || new Set();
  group.add(clear);
  readers.set(workspaceId, group);
  return () => {
    group.delete(clear);
    if (!group.size) readers.delete(workspaceId);
  };
}
export function clearReaderCache(workspaceId: string) {
  for (const clear of [...(readers.get(workspaceId) || [])]) clear();
  for (const key of views.keys())
    if (key.startsWith(workspaceId + ":")) views.delete(key);
}
export function readReaderView<T>(key: string): T | undefined {
  return views.get(key) as T | undefined;
}
export function saveReaderView(key: string, value: unknown) {
  views.set(key, value);
  if (views.size > 96) views.delete(views.keys().next().value!);
}
