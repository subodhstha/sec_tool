// FR-1.3: Crawl Trap Prevention & URL Normalization

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NUMERIC_ID_REGEX = /^\d+$/;
const HEX_HASH_REGEX = /^[0-9a-f]{32,64}$/i;

export interface NormalizedResult {
  originalUrl: string;
  normalizedPath: string;
  normalizedKey: string;
  depth: number;
  exceedsDepthLimit: boolean;
}

/**
 * Normalizes URL path segments to prevent crawl traps:
 * e.g., /user/1 and /user/2 -> /user/{id}
 * /order/550e8400-e29b-41d4-a716-446655440000 -> /order/{uuid}
 */
export function normalizeUrl(rawUrl: string, maxDepth: number = 3): NormalizedResult {
  try {
    const parsed = new URL(rawUrl);
    const rawSegments = parsed.pathname.split('/').filter(Boolean);
    const depth = rawSegments.length;

    const normalizedSegments = rawSegments.map(seg => {
      if (NUMERIC_ID_REGEX.test(seg)) {
        return '{id}';
      }
      if (UUID_REGEX.test(seg)) {
        return '{uuid}';
      }
      if (HEX_HASH_REGEX.test(seg)) {
        return '{hash}';
      }
      return seg;
    });

    const normalizedPath = '/' + normalizedSegments.join('/');

    // Sort query parameters alphabetically to avoid permutation crawl traps
    const searchParams = new URLSearchParams(parsed.search);
    const sortedKeys = Array.from(searchParams.keys()).sort();
    const sortedParamPairs: string[] = [];
    for (const key of sortedKeys) {
      sortedParamPairs.push(`${encodeURIComponent(key)}={param}`);
    }

    const paramSignature = sortedParamPairs.length > 0 ? `?${sortedParamPairs.join('&')}` : '';
    const normalizedKey = `${parsed.protocol}//${parsed.host}${normalizedPath}${paramSignature}`;

    return {
      originalUrl: rawUrl,
      normalizedPath,
      normalizedKey,
      depth,
      exceedsDepthLimit: depth > maxDepth,
    };
  } catch {
    return {
      originalUrl: rawUrl,
      normalizedPath: rawUrl,
      normalizedKey: rawUrl,
      depth: 0,
      exceedsDepthLimit: false,
    };
  }
}
