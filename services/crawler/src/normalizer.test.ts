import { normalizeUrl } from './normalizer';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`FAILED: ${msg}`);
    process.exit(1);
  }
}

console.log('Testing FR-1.3 Crawl Trap Prevention & URL Normalization...');

// Test 1: Numeric ID normalization
const res1 = normalizeUrl('https://example.com/api/v1/user/123/profile');
assert(res1.normalizedPath === '/api/v1/user/{id}/profile', `Expected /api/v1/user/{id}/profile, got ${res1.normalizedPath}`);

// Test 2: Multiple IDs
const res2 = normalizeUrl('https://example.com/api/v1/user/999/order/888');
assert(res2.normalizedPath === '/api/v1/user/{id}/order/{id}', `Expected /api/v1/user/{id}/order/{id}, got ${res2.normalizedPath}`);

// Test 3: UUID normalization
const res3 = normalizeUrl('https://example.com/tenant/550e8400-e29b-41d4-a716-446655440000/view');
assert(res3.normalizedPath === '/tenant/{uuid}/view', `Expected /tenant/{uuid}/view, got ${res3.normalizedPath}`);

// Test 4: Tree depth enforcement
const res4 = normalizeUrl('https://example.com/a/b/c/d/e/f', 3);
assert(res4.depth === 6, `Expected depth 6, got ${res4.depth}`);
assert(res4.exceedsDepthLimit === true, `Expected exceedsDepthLimit=true for depth 6 with maxDepth 3`);

// Test 5: Query parameter permutation invariance
const q1 = normalizeUrl('https://example.com/search?q=apple&page=1');
const q2 = normalizeUrl('https://example.com/search?page=2&q=banana');
assert(q1.normalizedKey === q2.normalizedKey, `Expected canonical query signatures to match: ${q1.normalizedKey} vs ${q2.normalizedKey}`);

console.log('ALL FR-1.3 NORMALIZATION TESTS PASSED CLEANLY!');
