export function log(message: string) {
  console.log(`[server] ${message}`);
}

export function setupVite() {
  // Backend-only - no vite setup needed
  return;
}

export function serveStatic(app: any) {
  // API-only backend - serve JSON responses
  app.get('*', (req: any, res: any) => {
    res.status(404).json({ error: 'API endpoint not found' });
  });
}
