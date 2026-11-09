import type { Request, Response } from 'express';
import { createApp } from '../server';
import { restoreVercelApiPath } from '../server/vercelPath';

const appPromise = createApp();

export default async function handler(request: Request, response: Response): Promise<void> {
  try {
    restoreVercelApiPath(request);
    const app = await appPromise;
    app(request, response);
  } catch (error) {
    console.error('Failed to initialize the API handler:', error);
    response.status(500).json({ error: 'The investigation service could not be initialized.' });
  }
}
