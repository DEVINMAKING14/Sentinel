import type { Request, Response } from 'express';
import app from '../server';
import { restoreVercelApiPath } from '../server/vercelPath';

export default function handler(request: Request, response: Response): void {
  restoreVercelApiPath(request);
  app(request, response);
}
