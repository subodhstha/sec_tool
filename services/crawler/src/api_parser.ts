// FR-1.2: API Schema Ingestion (OpenAPI / Swagger & GraphQL Introspection)

export interface EndpointParam {
  name: string;
  location: 'query' | 'header' | 'path' | 'body' | 'json' | 'cookie' | 'xml';
  value?: string;
}

export interface TargetEndpoint {
  url: string;
  normalized_url: string;
  method: string;
  parameters: EndpointParam[];
  headers?: Record<string, string>;
  source: 'CRAWLER' | 'OPENAPI' | 'GRAPHQL';
}

/**
 * Parses OpenAPI 3.0 or Swagger 2.0 JSON document into structured target endpoints (FR-1.2)
 */
export function parseOpenAPISpec(spec: any, baseUrl: string): TargetEndpoint[] {
  const endpoints: TargetEndpoint[] = [];
  if (!spec || typeof spec !== 'object' || !spec.paths) {
    return endpoints;
  }

  const cleanBase = baseUrl.replace(/\/+$/, '');

  for (const [pathKey, pathItem] of Object.entries<any>(spec.paths)) {
    if (!pathItem || typeof pathItem !== 'object') continue;

    const httpMethods = ['get', 'post', 'put', 'delete', 'patch', 'options', 'head'];
    for (const method of httpMethods) {
      const op = pathItem[method];
      if (!op) continue;

      const params: EndpointParam[] = [];

      // Extract parameters from path item and operation
      const allParams = [...(pathItem.parameters || []), ...(op.parameters || [])];
      for (const p of allParams) {
        if (!p || !p.name) continue;
        const location = p.in === 'formData' ? 'body' : p.in;
        params.push({
          name: p.name,
          location: (location as EndpointParam['location']) || 'query',
          value: p.example || p.schema?.default || 'test',
        });
      }

      const bodyInfo = getBodyInfo(op);
      params.push(...bodyInfo.parameters);

      const fullUrl = `${cleanBase}${pathKey.startsWith('/') ? pathKey : '/' + pathKey}`;
      endpoints.push({
        url: fullUrl,
        normalized_url: pathKey,
        method: method.toUpperCase(),
        parameters: params,
        headers: bodyInfo.contentType ? { 'Content-Type': bodyInfo.contentType } : undefined,
        source: 'OPENAPI',
      });
    }
  }

  return endpoints;
}

function getBodyInfo(operation: any): { parameters: EndpointParam[]; contentType?: string } {
  if ((operation.parameters || []).some((parameter: any) => parameter?.in === 'formData')) {
    return { parameters: [], contentType: operation.consumes?.[0] };
  }

  const requestBody = operation.requestBody;
  if (requestBody?.content) {
    const contentType = Object.keys(requestBody.content)[0];
    const schema = requestBody.content[contentType]?.schema;
    return {
      parameters: schemaProperties(schema, contentType === 'application/xml' ? 'xml' : contentType === 'application/json' ? 'json' : 'body'),
      contentType,
    };
  }

  const bodyParameter = (operation.parameters || []).find((parameter: any) => parameter?.in === 'body');
  if (bodyParameter?.schema) {
    const contentType = operation.consumes?.[0];
    return {
      parameters: schemaProperties(bodyParameter.schema, contentType === 'application/xml' ? 'xml' : contentType === 'application/json' ? 'json' : 'body'),
      contentType,
    };
  }

  return { parameters: [] };
}

function schemaProperties(schema: any, location: EndpointParam['location']): EndpointParam[] {
  if (!schema?.properties) return [{ name: 'body', location, value: 'test' }];
  return Object.entries<any>(schema.properties).map(([name, definition]) => ({
    name,
    location,
    value: definition?.example || definition?.default || definition?.enum?.[0] || 'test',
  }));
}

/**
 * Parses GraphQL introspection query output to map query and mutation endpoints (FR-1.2)
 */
export function parseGraphQLSchema(introspection: any, graphqlEndpointUrl: string): TargetEndpoint[] {
  const endpoints: TargetEndpoint[] = [];
  const schema = introspection?.data?.__schema;
  if (!schema) return endpoints;

  const types = schema.types || [];
  const queryTypeName = schema.queryType?.name || 'Query';
  const mutationTypeName = schema.mutationType?.name || 'Mutation';

  for (const t of types) {
    if (t.name === queryTypeName || t.name === mutationTypeName) {
      const fields = t.fields || [];
      for (const field of fields) {
        const params: EndpointParam[] = (field.args || []).map((arg: any) => ({
          name: arg.name,
          location: 'json',
          value: 'test',
        }));

        endpoints.push({
          url: graphqlEndpointUrl,
          normalized_url: `${graphqlEndpointUrl}#${t.name}.${field.name}`,
          method: 'POST',
          parameters: params,
          headers: { 'Content-Type': 'application/json' },
          source: 'GRAPHQL',
        });
      }
    }
  }

  return endpoints;
}
