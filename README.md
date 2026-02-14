# ctr-router

A minimalistic Express-like router for AWS Lambda functions behind API Gateway. Zero external dependencies beyond the AWS Lambda types — designed to stay small, fast, and predictable inside a cold-start-sensitive environment.

## Quick start

```ts
// routes.ts
import { App, Router, type Request, type Response } from '@workspace/ctr-router';

const app = new App();

const router = new Router()
  .get('/health', (_req: Request, res: Response) => {
    return res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

app.use('/', router);
export { app };
```

```ts
// index.ts (Lambda handler)
import type { APIGatewayEvent, APIGatewayProxyResult } from 'aws-lambda';
import { app } from './routes';

export const handler = async (event: APIGatewayEvent): Promise<APIGatewayProxyResult> => {
  return app.handle(event);
};
```

## Concepts

### App and Router

- **`App`** is the top-level entry point. It holds global middleware, mounts routers, and exposes the `handle(event)` method that you call from your Lambda handler.
- **`Router`** groups related routes together. You can nest routers and mount them under path prefixes.

Both can be created with `new` or as a plain function call:

```ts
const app = new App();   // or: const app = App();
const router = new Router(); // or: const router = Router();
```

### Request

Every handler receives a `Request` object with the following fields:

| Field | Type | Description |
|---|---|---|
| `event` | `APIGatewayEvent` | The raw Lambda event |
| `path` | `string` | Normalized request path |
| `method` | `HttpMethod` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, or `HEAD` |
| `params` | `Record<string, string>` | URL parameters extracted from `:param` segments |
| `query` | `Record<string, string \| undefined>` | Query string parameters (single value) |
| `queryMulti` | `Record<string, string[]>` | Query string parameters (all values, for repeated keys) |
| `headers` | `Record<string, string \| undefined>` | Request headers |
| `body` | `unknown` | Lazily parsed JSON body (only parsed when accessed) |
| `locals` | `Record<string, unknown>` | Shared data between middleware and handlers |

### Response

The `Response` object provides a chainable API to build the `APIGatewayProxyResult`:

```ts
// JSON response
res.status(200).json({ message: 'ok' });

// Plain text
res.status(200).text('Hello');

// Empty response with status
res.sendStatus(204);

// Empty response (200 by default)
res.send();

// Set headers
res.header('x-request-id', '123').json({ ok: true });

// Set multiple headers at once
res.set({ 'x-request-id': '123', 'x-trace': 'abc' }).json({ ok: true });

// Set content type shorthand
res.type('text/html').text('<h1>Hello</h1>');
```

### HttpStatus

A convenience object with named status codes:

```ts
import { HttpStatus } from '@workspace/ctr-router';

res.status(HttpStatus.NOT_FOUND).json({ message: 'Not found' });
res.status(HttpStatus.CREATED).json(newRecord);
res.sendStatus(HttpStatus.NO_CONTENT);
```

Available constants: `OK` (200), `CREATED` (201), `ACCEPTED` (202), `NO_CONTENT` (204), `MOVED_PERMANENTLY` (301), `FOUND` (302), `NOT_MODIFIED` (304), `BAD_REQUEST` (400), `UNAUTHORIZED` (401), `FORBIDDEN` (403), `NOT_FOUND` (404), `CONFLICT` (409), `UNPROCESSABLE_ENTITY` (422), `TOO_MANY_REQUESTS` (429), `INTERNAL_SERVER_ERROR` (500), `BAD_GATEWAY` (502), `SERVICE_UNAVAILABLE` (503), `GATEWAY_TIMEOUT` (504).

## Routing

### HTTP methods

```ts
router.get('/items', handler);
router.post('/items', handler);
router.put('/items/:id', handler);
router.patch('/items/:id', handler);
router.delete('/items/:id', handler);
router.options('/items', handler);
router.head('/items', handler);
```

All methods are also available directly on `App`.

### Route parameters

Use `:param` segments to capture URL parts:

```ts
router.get('/users/:userId/posts/:postId', (req: Request, res: Response) => {
  const { userId, postId } = req.params;
  return res.json({ userId, postId });
});
```

### Query strings

```ts
// GET /search?q=hello&tag=a&tag=b
router.get('/search', (req: Request, res: Response) => {
  const q = req.query.q;           // "hello"
  const tags = req.queryMulti.tag;  // ["a", "b"]
  return res.json({ q, tags });
});
```

`query` gives you the first value for each key. `queryMulti` gives you all values as arrays, which is useful when API Gateway sends repeated query parameters.

### Mounting routers

```ts
const usersRouter = new Router()
  .get('/', listUsers)
  .get('/:id', getUser)
  .post('/', createUser);

const postsRouter = new Router()
  .get('/', listPosts)
  .post('/', createPost);

const app = new App();
app.use('/users', usersRouter);
app.use('/posts', postsRouter);
```

This produces routes: `GET /users`, `GET /users/:id`, `POST /users`, `GET /posts`, `POST /posts`.

Routers can also be mounted on other routers:

```ts
const v1 = new Router();
v1.use('/users', usersRouter);
v1.use('/posts', postsRouter);

const app = new App();
app.use('/v1', v1);
// Routes: GET /v1/users, GET /v1/users/:id, etc.
```

## Middleware

Middleware are handlers registered with `app.use()`. They run before route handlers. A middleware that returns `undefined` passes control to the next handler in the chain.

### Global middleware

```ts
const app = new App();

// Runs before every route handler
app.use((req: Request, res: Response) => {
  console.log(`${req.method} ${req.path}`);
  return undefined; // continue to next handler
});

app.use('/api', apiRouter);
```

### Passing data with `req.locals`

Middleware can attach data to `req.locals` for downstream handlers to read:

```ts
const authenticate = (req: Request, res: Response) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(HttpStatus.UNAUTHORIZED).json({ message: 'Missing token' });
  }
  req.locals.userId = verifyToken(token);
  return undefined; // continue
};

router.get('/profile', authenticate, (req: Request, res: Response) => {
  const userId = req.locals.userId as string;
  return res.json({ userId });
});
```

### Route-level middleware

You can pass multiple handlers to a single route. They execute in order, and the first one to return a result short-circuits the rest:

```ts
router.post('/orders', validateBody, authorize, createOrder);
```

## Error handling

Wrap error handlers with the `onError` function and register them as middleware:

```ts
import { onError, HttpStatus } from '@workspace/ctr-router';

const errorHandler = onError((error: unknown, req: Request, res: Response) => {
  console.error('Unhandled error:', error);
  return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ message: 'Something went wrong' });
});

// Register as global error handler
app.use(errorHandler);
```

Error handlers are skipped during normal execution. When any handler in the pipeline throws, the error handlers run in order. If no error handler produces a response, the router returns a generic 500 response.

Route-level error handlers work too:

```ts
const routeErrorHandler = onError((error, req, res) => {
  return res.status(HttpStatus.BAD_REQUEST).json({ message: 'Invalid request' });
});

router.post('/items', parseItem, routeErrorHandler);
```

## CORS

The built-in `cors()` middleware handles CORS headers:

```ts
import { App, cors } from '@workspace/ctr-router';

const app = new App();

// Allow all origins (default)
app.use(cors());

// Restricted
app.use(cors({
  origin: 'https://myapp.example.com',
  credentials: true,
}));
```

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `origin` | `string` | `'*'` | `Access-Control-Allow-Origin` value |
| `methods` | `HttpMethod[]` | `['GET','POST','PUT','PATCH','DELETE','OPTIONS']` | Allowed methods |
| `allowHeaders` | `string[]` | `['Content-Type','Authorization']` | Allowed request headers |
| `exposeHeaders` | `string[]` | `[]` | Headers the browser can read |
| `maxAge` | `number` | `86400` | Preflight cache duration in seconds |
| `credentials` | `boolean` | `false` | Whether to send `Access-Control-Allow-Credentials` |

### Handling preflight requests

CORS preflight is an OPTIONS request. You can register a catch-all OPTIONS route to respond with 204:

```ts
app.use(cors({ origin: 'https://myapp.example.com' }));

app.options('/:path', (_req: Request, res: Response) => {
  return res.sendStatus(HttpStatus.NO_CONTENT);
});
```

## HEAD requests

HEAD requests are handled automatically. If you register a GET route, HEAD requests to the same path will match it and return the same response with an empty body:

```ts
router.get('/health', (_req, res) => res.json({ status: 'ok' }));
// HEAD /health -> 200, headers from the GET handler, empty body
```

You can also register explicit HEAD routes if you need different behavior:

```ts
router.head('/large-file', (_req, res) => {
  return res.header('content-length', '10485760').sendStatus(HttpStatus.OK);
});
```

## Handler flow

Understanding when handlers run and stop:

1. Global middleware run first (in registration order).
2. The matched route's handlers run next (in order).
3. Global error handlers run last (only if something threw).

A handler can:
- **Return a result** (`APIGatewayProxyResult`) — stops the chain, sends the response.
- **Return `undefined`** — passes control to the next handler.
- **Throw** — skips remaining normal handlers, triggers error handlers.

If the matched route's handlers all return `undefined` without calling any `res` method, the router responds with `204 No Content`.

If no route matches, the router responds with `404 Not Found`.

## Full example

```ts
import type { APIGatewayEvent, APIGatewayProxyResult } from 'aws-lambda';
import { App, Router, cors, onError, HttpStatus, type Request, type Response } from '@workspace/ctr-router';

// -- Middleware --
const logger = (req: Request, _res: Response) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  return undefined;
};

const auth = (req: Request, res: Response) => {
  const token = req.headers.authorization;
  if (!token) return res.status(HttpStatus.UNAUTHORIZED).json({ message: 'Unauthorized' });
  req.locals.userId = 'user-123'; // decoded from token
  return undefined;
};

// -- Routes --
const publicRouter = new Router()
  .get('/health', (_req, res) => res.json({ status: 'ok' }));

const itemsRouter = new Router()
  .get('/', async (_req, res) => {
    const items = [{ id: 1, name: 'Widget' }]; // from DB
    return res.json(items);
  })
  .get('/:id', (req, res) => {
    return res.json({ id: req.params.id });
  })
  .post('/', (req, res) => {
    const data = req.body as { name: string };
    return res.status(HttpStatus.CREATED).json({ id: 2, name: data.name });
  })
  .delete('/:id', (req, res) => {
    return res.sendStatus(HttpStatus.NO_CONTENT);
  });

// -- App --
const app = new App();

app.use(logger);
app.use(cors({ origin: 'https://myapp.example.com', credentials: true }));

app.options('/:path', (_req, res) => res.sendStatus(HttpStatus.NO_CONTENT));

app.use('/', publicRouter);
app.use('/items', auth, itemsRouter);

app.use(onError((err, _req, res) => {
  console.error(err);
  return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({ message: 'Internal error' });
}));

// -- Lambda entry point --
export const handler = async (event: APIGatewayEvent): Promise<APIGatewayProxyResult> => {
  return app.handle(event);
};
```

## Exports

```ts
import {
  App,          // App factory (callable / newable)
  Router,       // Router factory (callable / newable)
  Response,     // Response class
  HttpStatus,   // Status code constants
  cors,         // CORS middleware factory
  onError,      // Error handler wrapper

  // Types
  type Request,
  type RouteHandler,
  type ErrorRouteHandler,
  type CorsOptions,
} from '@workspace/ctr-router';
```
