/**
 * GraphQL Schema Parser
 * Fetches introspection query result and parses it into a hierarchical structure
 */

const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      types {
        kind
        name
        description
        fields(includeDeprecated: false) {
          name
          description
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
  }
`;

/**
 * Fetch and cache GraphQL schema introspection
 */
export async function fetchGraphQLSchema(graphqlUrl) {
  try {
    const response = await fetch(graphqlUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: INTROSPECTION_QUERY,
      }),
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    if (data.errors) {
      throw new Error(`GraphQL error: ${JSON.stringify(data.errors)}`);
    }

    return data.data.__schema;
  } catch (error) {
    console.error('Failed to fetch GraphQL schema:', error);
    throw error;
  }
}

/**
 * Parse schema to extract root Query type and its fields
 */
export function parseQueryFields(schema) {
  const queryType = schema.types.find((t) => t.name === 'Query');
  if (!queryType || !queryType.fields) {
    return [];
  }

  return queryType.fields.map((field) => ({
    name: field.name,
    description: field.description || '',
    type: getTypeName(field.type),
    fields: [],
  }));
}

/**
 * Get the actual type name, unwrapping non-null and list types
 */
function getTypeName(type) {
  if (type.kind === 'NON_NULL' || type.kind === 'LIST') {
    return getTypeName(type.ofType);
  }
  return type.name;
}

/**
 * Get fields of a specific type from the schema
 */
export function getTypeFields(schema, typeName) {
  const type = schema.types.find((t) => t.name === typeName);
  if (!type || !type.fields) {
    return [];
  }

  return type.fields.map((field) => ({
    name: field.name,
    description: field.description || '',
    type: getTypeName(field.type),
  }));
}

/**
 * Check if a type is a scalar (leaf) type or composite type
 */
export function isScalarType(schema, typeName) {
  const type = schema.types.find((t) => t.name === typeName);
  if (!type) return true; // Assume scalar if not found

  const scalarTypes = [
    'String',
    'Int',
    'Float',
    'Boolean',
    'ID',
    'Date',
    'DateTime',
    'JSON',
  ];

  return (
    scalarTypes.includes(typeName) || type.kind === 'SCALAR' || type.kind === 'ENUM'
  );
}

/**
 * Build a nested field structure for the selected path
 */
export function buildSelectedFieldStructure(selections) {
  // selections is an array of field names in order: ['scan', 'findings', 'severity']
  if (!selections || selections.length === 0) {
    return null;
  }

  let current = {
    name: selections[0],
  };

  let pointer = current;
  for (let i = 1; i < selections.length; i++) {
    pointer.fields = [{ name: selections[i] }];
    pointer = pointer.fields[0];
  }

  return current;
}

/**
 * Convert selected fields array to GraphQL query string
 */
export function generateGraphQLQuery(rootField, selectedFieldsPath) {
  if (!selectedFieldsPath || selectedFieldsPath.length === 0) {
    return `query { ${rootField} }`;
  }

  // Build nested field selection
  let fieldSelection = buildFieldSelection(selectedFieldsPath, 1);

  return `query {
  ${rootField} ${fieldSelection}
}`;
}

/**
 * Recursively build field selection string
 */
function buildFieldSelection(fields, depth) {
  if (!fields || fields.length === 0) {
    return '';
  }

  const indent = '  '.repeat(depth);
  let result = '{\n';

  for (const field of fields) {
    result += `${indent}${field.name}`;
    if (field.fields && field.fields.length > 0) {
      result += ' ' + buildFieldSelection(field.fields, depth + 1);
    }
    result += '\n';
  }

  result += '  '.repeat(depth - 1) + '}';
  return result;
}
