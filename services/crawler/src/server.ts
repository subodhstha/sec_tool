import express, { Request, Response } from 'express';
import { HeadlessCrawler } from './crawler';
import { parseOpenAPISpec, parseGraphQLSchema } from './api_parser';

const app = express();
const port = process.env.PORT || 3001;

app.use(express.json({ limit: '10mb' }));

app.post('/crawl', async (req: Request, res: Response) => {
  const { target_url, max_depth, max_pages } = req.body;
  if (!target_url) {
    return res.status(400).json({ error: 'target_url is required' });
  }

  try {
    const crawler = new HeadlessCrawler();
    const endpoints = await crawler.crawl({
      targetUrl: target_url,
      maxDepth: max_depth ? Number(max_depth) : 3,
      maxPages: max_pages ? Number(max_pages) : 25,
    });
    return res.json(endpoints);
  } catch (err: any) {
    console.error('[Crawler Service] Error during crawl:', err);
    return res.status(500).json({ error: err.message || 'Crawl failed' });
  }
});

app.post('/ingest-schema', (req: Request, res: Response) => {
  const { type, spec, base_url } = req.body;
  if (!spec || !base_url) {
    return res.status(400).json({ error: 'spec and base_url are required' });
  }

  try {
    if (type === 'GRAPHQL') {
      const endpoints = parseGraphQLSchema(spec, base_url);
      return res.json(endpoints);
    } else {
      const endpoints = parseOpenAPISpec(spec, base_url);
      return res.json(endpoints);
    }
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Schema ingestion failed' });
  }
});

app.get('/healthz', (_req: Request, res: Response) => {
  res.json({
    status: 'healthy',
    service: 'vyomite-crawler',
    version: '1.0.0',
  });
});

app.listen(port, () => {
  console.log(`[Vyomite Headless Crawler] Listening on port ${port}`);
});
