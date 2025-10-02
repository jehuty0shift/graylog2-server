(() => {
  const API_BROWSER_NAME = 'Graylog API Browser';
  const BASIC_SCHEME_NAME = 'basicAuth';
  const DEFAULT_SPEC_DESCRIPTION = 'Select a resource to view its operations.';

  const authState = {
    username: '',
    password: '',
    header: null,
  };

  const cache = new Map();
  let swaggerUi = null;
  let overviewData = null;

  const ready = (fn) => {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn, { once: true });
    } else {
      fn();
    }
  };

  const base64Encode = (value) => {
    try {
      return btoa(unescape(encodeURIComponent(value)));
    } catch (error) {
      console.error('Failed to encode credentials', error);
      throw error;
    }
  };

  const getOperationsMessageElement = () => document.getElementById('operations_message');

  const setOperationsMessage = (message, type = 'info') => {
    const element = getOperationsMessageElement();

    if (!element) {
      return;
    }

    if (message) {
      element.textContent = message;
      element.classList.add('is-visible');
      if (type === 'error') {
        element.classList.add('is-error');
      } else {
        element.classList.remove('is-error');
      }
    } else {
      element.textContent = '';
      element.classList.remove('is-visible', 'is-error');
    }
  };

  const buildHeaders = () => {
    const headers = new Headers();
    headers.set('X-Requested-By', API_BROWSER_NAME);
    headers.set('Accept', 'application/json');

    if (authState.header) {
      headers.set('Authorization', authState.header);
    }

    return headers;
  };

  const fetchJson = async (url) => {
    const response = await fetch(url, { headers: buildHeaders(), credentials: 'same-origin' });

    if (!response.ok) {
      const text = await response.text().catch(() => response.statusText);
      throw new Error(`Failed to load ${url} (${response.status} ${response.statusText}): ${text}`);
    }

    return response.json();
  };

  const toggleWarning = () => {
    const showWarning = document.body.dataset.showWarning;
    const warningBox = document.getElementById('warning_box');

    if (!warningBox) {
      return;
    }

    if (showWarning && showWarning !== 'false' && showWarning !== '0') {
      warningBox.classList.add('visible');
    } else {
      warningBox.classList.remove('visible');
    }
  };

  const updateAuthState = () => {
    const userField = document.getElementById('input_apiUser');
    const passField = document.getElementById('input_apiPassword');
    const statusField = document.getElementById('auth_status');

    const username = userField?.value?.trim() ?? '';
    const password = passField?.value ?? '';

    if (username && password) {
      authState.username = username;
      authState.password = password;
      authState.header = `Basic ${base64Encode(`${username}:${password}`)}`;
      statusField?.classList.add('is-active');
      if (statusField) {
        statusField.textContent = 'Credentials ready';
      }
    } else {
      authState.username = '';
      authState.password = '';
      authState.header = null;
      statusField?.classList.remove('is-active');
      if (statusField) {
        statusField.textContent = 'Not authenticated';
      }
    }

    applyPreauthorization();
  };

  const applyPreauthorization = () => {
    if (!swaggerUi || typeof swaggerUi.preauthorizeBasic !== 'function') {
      return;
    }

    if (authState.username && authState.password) {
      try {
        swaggerUi.preauthorizeBasic(BASIC_SCHEME_NAME, {
          username: authState.username,
          password: authState.password,
        });
      } catch (error) {
        console.warn('Unable to preauthorize basic authentication', error);
      }
    }
  };

  const getApiDocsBaseUrl = () => {
    const datasetPath = document.body.dataset.apiDocsPath || '/api/api-docs';
    const normalizedPath = datasetPath.replace(/\/+$/, '') || '/api/api-docs';
    const absolute = new URL(normalizedPath, window.location.origin);

    return absolute.toString().replace(/\/$/, '');
  };

  const getDefaultApiLocation = () => {
    try {
      const docsUrl = new URL(getApiDocsBaseUrl());
      let path = docsUrl.pathname.replace(/\/?api-docs.*$/i, '');
      if (!path) {
        path = '/';
      }
      if (path.length > 1 && path.endsWith('/')) {
        path = path.slice(0, -1);
      }

      return {
        schemes: [docsUrl.protocol.replace(':', '')],
        host: docsUrl.host,
        basePath: path || '/',
      };
    } catch (error) {
      return {
        schemes: [window.location.protocol.replace(':', '')],
        host: window.location.host,
        basePath: '/api',
      };
    }
  };

  const getResourceUrl = (path) => {
    const baseUrl = getApiDocsBaseUrl();
    const normalizedPath = path.startsWith('/') ? path.slice(1) : path;
    return `${baseUrl}/${normalizedPath}`;
  };

  const renderResources = (overview) => {
    const list = document.getElementById('resource_list');

    if (!list) {
      return;
    }

    list.innerHTML = '';

    const apis = overview?.apis ?? [];
    if (!apis.length) {
      const empty = document.createElement('div');
      empty.className = 'resource-empty';
      empty.textContent = 'No documented resources were found.';
      list.appendChild(empty);
      return;
    }

    apis.forEach((api) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'resource-button';
      button.dataset.path = api.path;
      button.dataset.name = api.name || api.path;

      const title = document.createElement('div');
      title.className = 'resource-title';
      title.textContent = api.name || api.path;
      button.appendChild(title);

      if (api.description) {
        const description = document.createElement('div');
        description.className = 'resource-description';
        description.textContent = api.description;
        button.appendChild(description);
      }

      button.addEventListener('click', () => selectResource(api, button));
      list.appendChild(button);
    });
  };

  const normalizePath = (path) => {
    if (!path) {
      return '/';
    }

    let normalized = path;
    if (!normalized.startsWith('/')) {
      normalized = `/${normalized}`;
    }

    if (normalized.length > 1 && normalized.endsWith('/')) {
      normalized = normalized.slice(0, -1);
    }

    return normalized;
  };

  const convertRef = (ref) => {
    if (!ref || typeof ref !== 'string') {
      return ref;
    }

    if (ref.startsWith('#/')) {
      return ref.replace(/^#\/?/, '#/definitions/');
    }

    return `#/definitions/${ref}`;
  };

  const normalizeSchema = (schema) => {
    if (!schema || typeof schema !== 'object') {
      return schema;
    }

    if (Array.isArray(schema)) {
      return schema.map((item) => normalizeSchema(item));
    }

    const result = {};

    Object.entries(schema).forEach(([key, value]) => {
      if (key === 'id') {
        return;
      }

      if (key === '$ref') {
        result.$ref = convertRef(String(value));
        return;
      }

      if (value && typeof value === 'object') {
        result[key] = normalizeSchema(value);
        return;
      }

      result[key] = value;
    });

    if (!result.type && result.properties) {
      result.type = 'object';
    }

    return result;
  };

  const convertModels = (models) => {
    if (!models || typeof models !== 'object') {
      return {};
    }

    const definitions = {};
    Object.entries(models).forEach(([name, schema]) => {
      definitions[name] = normalizeSchema(schema);
    });
    return definitions;
  };

  const PRIMITIVE_TYPES = {
    string: () => ({ type: 'string' }),
    String: () => ({ type: 'string' }),
    boolean: () => ({ type: 'boolean' }),
    Boolean: () => ({ type: 'boolean' }),
    int: () => ({ type: 'integer', format: 'int32' }),
    Integer: () => ({ type: 'integer', format: 'int32' }),
    long: () => ({ type: 'integer', format: 'int64' }),
    Long: () => ({ type: 'integer', format: 'int64' }),
    float: () => ({ type: 'number', format: 'float' }),
    Float: () => ({ type: 'number', format: 'float' }),
    double: () => ({ type: 'number', format: 'double' }),
    Double: () => ({ type: 'number', format: 'double' }),
    number: () => ({ type: 'number' }),
    BigDecimal: () => ({ type: 'number', format: 'double' }),
    byte: () => ({ type: 'string', format: 'byte' }),
    Byte: () => ({ type: 'string', format: 'byte' }),
    date: () => ({ type: 'string', format: 'date' }),
    Date: () => ({ type: 'string', format: 'date' }),
    DateTime: () => ({ type: 'string', format: 'date-time' }),
    LocalDate: () => ({ type: 'string', format: 'date' }),
    UUID: () => ({ type: 'string', format: 'uuid' }),
    void: () => null,
    Void: () => null,
  };

  const clone = (value) => {
    if (Array.isArray(value)) {
      return value.map((item) => clone(item));
    }

    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, clone(val)]));
    }

    return value;
  };

  const convertTypeToSchema = (typeName, models) => {
    if (!typeName || typeof typeName !== 'string') {
      return null;
    }

    const trimmed = typeName.trim();
    if (!trimmed) {
      return null;
    }

    if (trimmed.endsWith('[]')) {
      const itemType = trimmed.slice(0, -2);
      return {
        type: 'array',
        items: convertTypeToSchema(itemType, models) || { type: 'string' },
      };
    }

    const primitiveFactory = PRIMITIVE_TYPES[trimmed];
    if (primitiveFactory) {
      return primitiveFactory();
    }

    if (models && models[trimmed]) {
      return { $ref: `#/definitions/${trimmed}` };
    }

    return { type: 'string' };
  };

  const applySchemaToParameter = (target, schema) => {
    if (!schema) {
      target.type = 'string';
      return;
    }

    if (schema.$ref) {
      target.type = 'string';
      return;
    }

    if (schema.type === 'array') {
      target.type = 'array';
      target.items = clone(schema.items) || { type: 'string' };
      return;
    }

    if (schema.type) {
      target.type = schema.type;
    }

    if (schema.format) {
      target.format = schema.format;
    }

    if (schema.enum) {
      target.enum = clone(schema.enum);
    }

    if (schema.pattern) {
      target.pattern = schema.pattern;
    }

    if (schema.minimum !== undefined) {
      target.minimum = schema.minimum;
    }

    if (schema.maximum !== undefined) {
      target.maximum = schema.maximum;
    }

    if (schema.default !== undefined) {
      target.default = schema.default;
    }
  };

  const mapParameterLocation = (paramType) => {
    const normalized = typeof paramType === 'string' ? paramType.toLowerCase() : '';
    switch (normalized) {
      case 'query':
        return 'query';
      case 'path':
        return 'path';
      case 'header':
        return 'header';
      case 'form':
        return 'formData';
      default:
        return 'body';
    }
  };

  const convertParameter = (parameter, models) => {
    const location = mapParameterLocation(parameter.paramType || parameter.kind);
    const name = parameter.name || (location === 'body' ? 'body' : 'parameter');
    const converted = {
      name,
      in: location,
      description: parameter.description || undefined,
      required: location === 'path' ? true : Boolean(parameter.required ?? parameter.isRequired),
    };

    const schema = convertTypeToSchema(parameter.type, models);

    if (location === 'body') {
      converted.schema = schema || { type: 'string' };
    } else if (location === 'formData') {
      applySchemaToParameter(converted, schema);
    } else {
      applySchemaToParameter(converted, schema);
    }

    if (parameter.defaultValue !== undefined && parameter.defaultValue !== null && parameter.defaultValue !== '') {
      if (location === 'body') {
        if (converted.schema && converted.schema.type && converted.schema.type !== 'object') {
          converted.schema.default = parameter.defaultValue;
        }
      } else {
        converted.default = parameter.defaultValue;
      }
    }

    return converted;
  };

  const guessSuccessCode = (method) => {
    switch (method) {
      case 'post':
        return 201;
      case 'delete':
        return 204;
      default:
        return 200;
    }
  };

  const convertResponses = (operation, models) => {
    const responses = {};
    const messages = Array.isArray(operation.responseMessages) ? operation.responseMessages : [];
    const successCode = guessSuccessCode((operation.method || 'get').toLowerCase());

    const attachSchema = (target, typeName) => {
      const schema = convertTypeToSchema(typeName, models);
      if (schema) {
        if (schema.$ref || schema.type) {
          target.schema = schema;
        }
      }
    };

    if (messages.length) {
      messages.forEach((message) => {
        const code = String(message.code ?? successCode);
        responses[code] = {
          description: message.message || `HTTP ${code}`,
        };

        if (message.responseModel) {
          attachSchema(responses[code], message.responseModel);
        }
      });

      const successKey = Object.keys(responses).find((key) => {
        const value = Number(key);
        return Number.isFinite(value) && value >= 200 && value < 300;
      });

      if (successKey && !responses[successKey].schema) {
        attachSchema(responses[successKey], operation.type);
      }
    } else {
      responses[String(successCode)] = {
        description: 'Success',
      };
      attachSchema(responses[String(successCode)], operation.type);
    }

    if (!Object.keys(responses).length) {
      responses[String(successCode)] = { description: 'Success' };
    }

    return responses;
  };

  const convertOperation = (operation, models, resourceName) => {
    const method = (operation.method || 'get').toLowerCase();
    const converted = {
      summary: operation.summary || operation.nickname || '',
      description: operation.notes || '',
      operationId: operation.nickname || `${method}_${Math.random().toString(36).slice(2)}`,
      tags: resourceName ? [resourceName] : undefined,
      produces: operation.produces || ['application/json'],
      consumes: operation.consumes || ['application/json'],
      parameters: [],
      responses: {},
    };

    const params = Array.isArray(operation.parameters) ? operation.parameters : [];
    converted.parameters = params.map((parameter) => convertParameter(parameter, models));
    converted.responses = convertResponses(operation, models);

    return { method, converted };
  };

  const parseBaseUrl = (basePath) => {
    try {
      const url = new URL(basePath);
      let path = url.pathname || '/';
      if (path.length > 1 && path.endsWith('/')) {
        path = path.slice(0, -1);
      }
      return {
        schemes: [url.protocol.replace(':', '')],
        host: url.host,
        basePath: path || '/',
      };
    } catch (error) {
      return getDefaultApiLocation();
    }
  };

  const buildEmptySpec = (description = DEFAULT_SPEC_DESCRIPTION) => {
    const defaults = getDefaultApiLocation();
    return {
      swagger: '2.0',
      info: {
        title: 'Graylog REST API',
        version: '1.0.0',
        description,
      },
      schemes: defaults.schemes,
      host: defaults.host,
      basePath: defaults.basePath,
      paths: {},
      definitions: {},
      securityDefinitions: {
        [BASIC_SCHEME_NAME]: {
          type: 'basic',
          description: 'Basic authentication using Graylog credentials.',
        },
      },
      security: [{ [BASIC_SCHEME_NAME]: [] }],
    };
  };

  const convertResourceSpec = (resource, overview, overviewEntry) => {
    const definitions = convertModels(resource.models);
    const baseInfo = parseBaseUrl(resource.basePath || overview?.basePath || window.location.origin);
    const infoTitle = overview?.info?.title || 'Graylog REST API';
    const lookupEntry =
      overviewEntry || overview?.apis?.find((api) => api.path === resource.resourcePath || api.path === resource.path);
    const resourceName = lookupEntry?.name || resource.resourcePath || (overviewEntry && overviewEntry.path) || 'Resource';
    const resourceDescription = lookupEntry?.description || resource.description || '';

    const spec = {
      swagger: '2.0',
      info: {
        title: `${infoTitle} – ${resourceName}`,
        version: resource.apiVersion || overview?.apiVersion || '1.0.0',
        description: resourceDescription || overview?.info?.description || '',
      },
      schemes: baseInfo.schemes,
      host: baseInfo.host,
      basePath: baseInfo.basePath,
      tags: resourceName ? [{ name: resourceName, description: resourceDescription }] : undefined,
      paths: {},
      definitions,
      securityDefinitions: {
        [BASIC_SCHEME_NAME]: {
          type: 'basic',
          description: 'Basic authentication using Graylog credentials.',
        },
      },
      security: [{ [BASIC_SCHEME_NAME]: [] }],
    };

    const apis = Array.isArray(resource.apis) ? resource.apis : [];

    apis.forEach((api) => {
      const path = normalizePath(api.path || resource.resourcePath);
      if (!spec.paths[path]) {
        spec.paths[path] = {};
      }

      const operations = Array.isArray(api.operations) ? api.operations : [];
      operations.forEach((operation) => {
        const { method, converted } = convertOperation(operation, definitions, resourceName);
        spec.paths[path][method] = converted;
      });
    });

    if (!Object.keys(spec.paths).length) {
      spec.paths['/'] = {
        get: {
          summary: 'No operations available',
          description: 'The selected resource does not define any operations.',
          responses: {
            200: { description: 'Success' },
          },
        },
      };
    }

    return spec;
  };

  const updateSwaggerSpec = (spec) => {
    if (!swaggerUi) {
      return;
    }

    const system = typeof swaggerUi.getSystem === 'function' ? swaggerUi.getSystem() : null;
    if (!system || !system.specActions) {
      return;
    }

    const serialized = typeof spec === 'string' ? spec : JSON.stringify(spec);
    system.specActions.updateSpec(serialized);

    // Swagger UI may re-render asynchronously, defer preauthorization.
    setTimeout(applyPreauthorization, 0);
  };

  const selectResource = async (api, button) => {
    const list = document.getElementById('resource_list');
    if (list) {
      list.querySelectorAll('.resource-button').forEach((el) => el.classList.remove('active'));
    }

    button?.classList.add('active');
    setOperationsMessage('Loading operations …');

    try {
      const spec = await loadResourceSpecification(api.path);
      const converted = convertResourceSpec(spec, overviewData, api);
      updateSwaggerSpec(converted);
      setOperationsMessage(null);
    } catch (error) {
      console.error(error);
      setOperationsMessage(error.message || 'Unable to load the selected resource.', 'error');
      updateSwaggerSpec(buildEmptySpec(error.message));
    }
  };

  const loadResourceSpecification = async (path) => {
    if (cache.has(path)) {
      return cache.get(path);
    }

    const url = getResourceUrl(path);
    const spec = await fetchJson(url);
    cache.set(path, spec);
    return spec;
  };

  const initializeForm = () => {
    const form = document.getElementById('api_selector');
    if (form) {
      form.addEventListener('submit', (event) => {
        event.preventDefault();
      });
    }

    const userField = document.getElementById('input_apiUser');
    const passField = document.getElementById('input_apiPassword');

    userField?.addEventListener('input', updateAuthState);
    passField?.addEventListener('input', updateAuthState);
    userField?.addEventListener('change', updateAuthState);
    passField?.addEventListener('change', updateAuthState);
  };

  const initializeSwaggerUi = () => {
    if (typeof SwaggerUIBundle !== 'function') {
      console.error('Swagger UI bundle is not available.');
      return;
    }

    swaggerUi = SwaggerUIBundle({
      dom_id: '#swagger_ui',
      spec: buildEmptySpec(),
      deepLinking: true,
      docExpansion: 'none',
      defaultModelsExpandDepth: 1,
      presets: [SwaggerUIBundle.presets.apis],
      layout: 'BaseLayout',
      requestInterceptor: (request) => {
        request.headers['X-Requested-By'] = API_BROWSER_NAME;
        if (authState.header) {
          request.headers.Authorization = authState.header;
        } else if (request.headers.Authorization) {
          delete request.headers.Authorization;
        }
        return request;
      },
    });
  };

  const loadOverview = async () => {
    const url = getApiDocsBaseUrl();
    overviewData = await fetchJson(url);
    renderResources(overviewData);
  };

  ready(async () => {
    toggleWarning();
    initializeForm();
    initializeSwaggerUi();
    updateAuthState();
    setOperationsMessage(DEFAULT_SPEC_DESCRIPTION);

    try {
      await loadOverview();
    } catch (error) {
      console.error(error);
      setOperationsMessage(error.message || 'Unable to load API overview.', 'error');
    }
  });
})();
