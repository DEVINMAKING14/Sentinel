import { Request, Response } from 'express';
import { InvestigationDependencies, InvestigationError, investigateSubmittedUrl } from './investigation';
import { saveScan } from './store';

export function createInvestigationHandler(dependencies: InvestigationDependencies = {}) {
  return async (request: Request, response: Response): Promise<void> => {
    try {
      const result = await investigateSubmittedUrl(request.body?.url, dependencies);
      saveScan(result);
      response.json(result);
    } catch (error) {
      if (error instanceof InvestigationError) {
        response.status(error.statusCode).json({ error: error.message });
        return;
      }
      console.error('Investigation failed:', error);
      response.status(500).json({
        error: 'Investigation could not be completed.',
      });
    }
  };
}
