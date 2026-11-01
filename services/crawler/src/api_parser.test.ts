import { parseOpenAPISpec } from './api_parser';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`FAILED: ${message}`);
    process.exit(1);
  }
}

const endpoints = parseOpenAPISpec({
  swagger: '2.0',
  paths: {
    '/upload': {
      post: {
        consumes: ['application/x-www-form-urlencoded'],
        parameters: [{ name: 'file', in: 'formData', type: 'string' }],
      },
    },
  },
}, 'https://example.test');

assert(endpoints[0].parameters[0].location === 'body', 'formData should map to body');
assert(endpoints[0].headers?.['Content-Type'] === 'application/x-www-form-urlencoded', 'formData content type should be preserved');

const xmlEndpoints = parseOpenAPISpec({
  openapi: '3.0.0',
  paths: {
    '/xml': {
      post: {
        requestBody: {
          content: {
            'application/xml': { schema: { properties: { document: { example: '<root/>' } } } },
          },
        },
      },
    },
  },
}, 'https://example.test');

assert(xmlEndpoints[0].parameters[0].location === 'xml', 'XML request bodies should map to xml');
assert(xmlEndpoints[0].headers?.['Content-Type'] === 'application/xml', 'XML content type should be preserved');

console.log('OPENAPI BODY LOCATION TESTS PASSED');