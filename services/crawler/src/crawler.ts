// FR-1.1: Headless DOM Crawling and SPA Mapping

import { normalizeUrl } from './normalizer';
import { TargetEndpoint, EndpointParam } from './api_parser';
import { chromium } from 'playwright';

export interface CrawlOptions {
  targetUrl: string;
  maxDepth?: number;
  maxPages?: number;
}

export class HeadlessCrawler {
  private visitedKeys = new Set<string>();

  /**
   * Crawls a target Single Page Application (SPA) or web service (FR-1.1)
   */
  async crawl(options: CrawlOptions): Promise<TargetEndpoint[]> {
    const maxDepth = options.maxDepth ?? 3;
    const maxPages = options.maxPages ?? 25;
    const endpoints: TargetEndpoint[] = [];
    const queue: { url: string; depth: number }[] = [{ url: options.targetUrl, depth: 0 }];

    const targetOrigin = new URL(options.targetUrl).origin;

    const browser = await chromium.launch({
      executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    try {
      const context = await browser.newContext({ ignoreHTTPSErrors: true });
      const page = await context.newPage();

      while (queue.length > 0 && endpoints.length < maxPages) {
        const current = queue.shift()!;
        const norm = normalizeUrl(current.url, maxDepth);

        // FR-1.3 Crawl Trap Prevention: Skip if exceeds depth or normalized pattern already visited
        if (norm.exceedsDepthLimit || this.visitedKeys.has(norm.normalizedKey)) {
          continue;
        }

        this.visitedKeys.add(norm.normalizedKey);

        try {
          await page.goto(current.url, { waitUntil: 'networkidle', timeout: 15000 });

          // Extract query parameters from URL itself
          const currentUrlObj = new URL(current.url);
          const queryParams: EndpointParam[] = [];
          currentUrlObj.searchParams.forEach((val, key) => {
            queryParams.push({ name: key, location: 'query', value: val });
          });

          endpoints.push({
            url: current.url,
            normalized_url: norm.normalizedPath,
            method: 'GET',
            parameters: queryParams,
            source: 'CRAWLER',
          });

          // DOM Analysis: Extract <a href="..."> links directly via DOM evaluation
          const links = await page.evaluate(() => {
            return Array.from(document.querySelectorAll('a[href]')).map(a => (a as HTMLAnchorElement).href);
          });

          for (const link of links) {
            try {
              const resolved = new URL(link, current.url);
              // Stay within same origin
              if (resolved.origin === targetOrigin && current.depth + 1 <= maxDepth) {
                const linkNorm = normalizeUrl(resolved.href, maxDepth);
                if (!this.visitedKeys.has(linkNorm.normalizedKey)) {
                  queue.push({ url: resolved.href, depth: current.depth + 1 });
                }
              }
            } catch {
              // Invalid link ignored
            }
          }

          // DOM Analysis: Extract forms
          const forms = await page.evaluate(() => {
            return Array.from(document.querySelectorAll('form')).map(form => {
              return {
                action: form.getAttribute('action') || '',
                method: (form.getAttribute('method') || 'GET').toUpperCase(),
                inputs: Array.from(form.querySelectorAll('input[name]')).map(input => (input as HTMLInputElement).name)
              };
            });
          });

          for (const form of forms) {
            try {
              const formActionUrl = new URL(form.action, current.url);
              if (formActionUrl.origin === targetOrigin) {
                const formParams: EndpointParam[] = form.inputs.map(name => ({
                  name,
                  location: form.method === 'POST' ? 'body' : 'query',
                  value: 'test'
                }));
                const formNorm = normalizeUrl(formActionUrl.href, maxDepth);
                endpoints.push({
                  url: formActionUrl.href,
                  normalized_url: formNorm.normalizedPath,
                  method: form.method,
                  parameters: formParams,
                  source: 'CRAWLER',
                });
              }
            } catch {
              // Ignore malformed form action
            }
          }
        } catch (err) {
          console.warn(`[Crawler] Failed fetching ${current.url}:`, err);
        }
      }
    } finally {
      await browser.close();
    }

    return endpoints;
  }
}
