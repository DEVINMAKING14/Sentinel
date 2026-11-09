import { createServer as createViteServer } from 'vite';
import app from './server';

async function startServer() {
  if (process.env.NODE_ENV !== 'production' && process.env.VERCEL !== '1') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  const port = Number.parseInt(process.env.PORT || '3000', 10);
  app.listen(port, '0.0.0.0', () => {
    console.log(`[SENTINEL ENGINE] Threat Intelligence platform online on port ${port}`);
  });
}

startServer().catch(error => {
  console.error('Failed to start Sentinel server:', error);
  process.exit(1);
});
