export function restoreVercelApiPath(request: { url?: string }): void {
  const requestUrl = new URL(request.url || '/', 'http://localhost');
  const apiPath = requestUrl.searchParams.get('__sentinel_path');
  if (!apiPath) return;

  requestUrl.searchParams.delete('__sentinel_path');
  request.url = `/api/${apiPath.replace(/^\/+/, '')}${requestUrl.search}`;
}
