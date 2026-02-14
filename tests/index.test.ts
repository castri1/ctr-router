import type { APIGatewayEvent } from 'aws-lambda'
import type { RouteHandler } from '../src/index'
import { App, cors, HttpStatus, onError, Response, Router } from '../src/index'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(
  overrides: Partial<APIGatewayEvent> & { path: string; httpMethod: string },
): APIGatewayEvent {
  const { path, httpMethod, ...rest } = overrides
  return {
    body: null,
    headers: {},
    multiValueHeaders: {},
    httpMethod,
    isBase64Encoded: false,
    path,
    pathParameters: null,
    queryStringParameters: null,
    multiValueQueryStringParameters: null,
    stageVariables: null,
    requestContext: {} as APIGatewayEvent['requestContext'],
    resource: '',
    ...rest,
  }
}

function makeV2Event(
  rawPath: string,
  httpMethod: string,
  extra?: Partial<APIGatewayEvent>,
): APIGatewayEvent {
  const base = makeEvent({ path: '/ignored', httpMethod })
  return { ...base, ...extra, rawPath } as unknown as APIGatewayEvent
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

describe('Response', () => {
  it('json() returns JSON with correct defaults', () => {
    const res = new Response()
    const result = res.json({ ok: true })
    expect(result.statusCode).toBe(200)
    expect(result.headers?.['content-type']).toBe('application/json')
    expect(JSON.parse(result.body)).toEqual({ ok: true })
  })

  it('json(null) serialises to {}', () => {
    const result = new Response().json(null)
    expect(JSON.parse(result.body)).toEqual({})
  })

  it('json(undefined) serialises to {}', () => {
    const result = new Response().json(undefined)
    expect(JSON.parse(result.body)).toEqual({})
  })

  it('text() returns plain text', () => {
    const result = new Response().text('hello')
    expect(result.statusCode).toBe(200)
    expect(result.headers?.['content-type']).toBe('text/plain; charset=utf-8')
    expect(result.body).toBe('hello')
  })

  it('send() returns empty body', () => {
    const result = new Response().send()
    expect(result.body).toBe('')
  })

  it('sendStatus() sets status and empty body', () => {
    const result = new Response().sendStatus(204)
    expect(result.statusCode).toBe(204)
    expect(result.body).toBe('')
  })

  it('status() is chainable', () => {
    const result = new Response().status(201).json({ id: 1 })
    expect(result.statusCode).toBe(201)
  })

  it('header() lowercases name', () => {
    const result = new Response().header('X-Custom', 'val').json({})
    expect(result.headers?.['x-custom']).toBe('val')
  })

  it('set() applies multiple headers', () => {
    const result = new Response().set({ 'X-A': '1', 'X-B': '2' }).json({})
    expect(result.headers?.['x-a']).toBe('1')
    expect(result.headers?.['x-b']).toBe('2')
  })

  it('type() sets content-type', () => {
    const result = new Response().type('text/html').text('<h1>hi</h1>')
    expect(result.headers?.['content-type']).toBe('text/html')
  })

  it('getResult() returns undefined before commit', () => {
    expect(new Response().getResult()).toBeUndefined()
  })

  it('getResult() returns result after commit', () => {
    const res = new Response()
    const result = res.json({ x: 1 })
    expect(res.getResult()).toEqual(result)
  })
})

// ---------------------------------------------------------------------------
// HttpStatus
// ---------------------------------------------------------------------------

describe('HttpStatus', () => {
  it('has correct common values', () => {
    expect(HttpStatus.OK).toBe(200)
    expect(HttpStatus.CREATED).toBe(201)
    expect(HttpStatus.NOT_FOUND).toBe(404)
    expect(HttpStatus.INTERNAL_SERVER_ERROR).toBe(500)
  })
})

// ---------------------------------------------------------------------------
// onError
// ---------------------------------------------------------------------------

describe('onError', () => {
  it('marks handler with __errorHandler', () => {
    const handler = onError((_err, _req, res) =>
      res.status(500).json({ error: 'fail' }),
    )
    expect(handler.__errorHandler).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Router – basic routing
// ---------------------------------------------------------------------------

describe('Router', () => {
  it('can be called as a function', () => {
    const r = Router()
    expect(r).toBeTruthy()
    expect(typeof r.get).toBe('function')
  })

  it('can be called with new', () => {
    const r = new Router()
    expect(r).toBeTruthy()
  })

  it('handles GET route', async () => {
    const router = Router()
    router.get('/hello', (_req, res) => res.json({ msg: 'hi' }))
    const result = await router.handle(
      makeEvent({ path: '/hello', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
    expect(JSON.parse(result.body)).toEqual({ msg: 'hi' })
  })

  it('handles POST route', async () => {
    const router = Router()
    router.post('/items', (_req, res) => res.status(201).json({ id: 1 }))
    const result = await router.handle(
      makeEvent({ path: '/items', httpMethod: 'POST' }),
    )
    expect(result.statusCode).toBe(201)
  })

  it('handles PUT route', async () => {
    const router = Router()
    router.put('/items/:id', (req, res) => res.json({ id: req.params.id }))
    const result = await router.handle(
      makeEvent({ path: '/items/42', httpMethod: 'PUT' }),
    )
    expect(JSON.parse(result.body)).toEqual({ id: '42' })
  })

  it('handles PATCH route', async () => {
    const router = Router()
    router.patch('/items/:id', (req, res) =>
      res.json({ patched: req.params.id }),
    )
    const result = await router.handle(
      makeEvent({ path: '/items/7', httpMethod: 'PATCH' }),
    )
    expect(JSON.parse(result.body)).toEqual({ patched: '7' })
  })

  it('handles DELETE route', async () => {
    const router = Router()
    router.delete('/items/:id', (_req, res) => res.sendStatus(204))
    const result = await router.handle(
      makeEvent({ path: '/items/1', httpMethod: 'DELETE' }),
    )
    expect(result.statusCode).toBe(204)
  })

  it('handles OPTIONS route', async () => {
    const router = Router()
    router.options('/test', (_req, res) => res.sendStatus(204))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'OPTIONS' }),
    )
    expect(result.statusCode).toBe(204)
  })

  it('returns 404 for unmatched routes', async () => {
    const router = Router()
    router.get('/exists', (_req, res) => res.json({}))
    const result = await router.handle(
      makeEvent({ path: '/nope', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(404)
  })

  it('returns 404 for wrong method', async () => {
    const router = Router()
    router.get('/hello', (_req, res) => res.json({}))
    const result = await router.handle(
      makeEvent({ path: '/hello', httpMethod: 'POST' }),
    )
    expect(result.statusCode).toBe(404)
  })
})

// ---------------------------------------------------------------------------
// Route parameters
// ---------------------------------------------------------------------------

describe('Route parameters', () => {
  it('extracts single param', async () => {
    const router = Router()
    router.get('/users/:id', (req, res) => res.json({ id: req.params.id }))
    const result = await router.handle(
      makeEvent({ path: '/users/abc', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ id: 'abc' })
  })

  it('extracts multiple params', async () => {
    const router = Router()
    router.get('/users/:userId/posts/:postId', (req, res) =>
      res.json({ userId: req.params.userId, postId: req.params.postId }),
    )
    const result = await router.handle(
      makeEvent({ path: '/users/u1/posts/p2', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ userId: 'u1', postId: 'p2' })
  })

  it('decodes URI-encoded params', async () => {
    const router = Router()
    router.get('/search/:query', (req, res) =>
      res.json({ q: req.params.query }),
    )
    const result = await router.handle(
      makeEvent({ path: '/search/hello%20world', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ q: 'hello world' })
  })
})

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

describe('Query parameters', () => {
  it('passes single-value query params', async () => {
    const router = Router()
    router.get('/search', (req, res) => res.json({ q: req.query.q }))
    const result = await router.handle(
      makeEvent({
        path: '/search',
        httpMethod: 'GET',
        queryStringParameters: { q: 'test' },
      }),
    )
    expect(JSON.parse(result.body)).toEqual({ q: 'test' })
  })

  it('passes multi-value query params from multiValueQueryStringParameters', async () => {
    const router = Router()
    router.get('/filter', (req, res) => res.json({ tags: req.queryMulti.tag }))
    const result = await router.handle(
      makeEvent({
        path: '/filter',
        httpMethod: 'GET',
        queryStringParameters: { tag: 'b' },
        multiValueQueryStringParameters: { tag: ['a', 'b'] },
      }),
    )
    expect(JSON.parse(result.body)).toEqual({ tags: ['a', 'b'] })
  })

  it('builds queryMulti from single values when multiValue is absent', async () => {
    const router = Router()
    router.get('/q', (req, res) => res.json(req.queryMulti))
    const result = await router.handle(
      makeEvent({
        path: '/q',
        httpMethod: 'GET',
        queryStringParameters: { a: '1', b: '2' },
        multiValueQueryStringParameters: null,
      }),
    )
    expect(JSON.parse(result.body)).toEqual({ a: ['1'], b: ['2'] })
  })

  it('handles missing query params', async () => {
    const router = Router()
    router.get('/test', (req, res) =>
      res.json({ q: req.query, qm: req.queryMulti }),
    )
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    const body = JSON.parse(result.body)
    expect(body.q).toEqual({})
    expect(body.qm).toEqual({})
  })
})

// ---------------------------------------------------------------------------
// Body parsing
// ---------------------------------------------------------------------------

describe('Body parsing', () => {
  it('lazily parses JSON body', async () => {
    const router = Router()
    router.post('/data', (req, res) => res.json({ received: req.body }))
    const result = await router.handle(
      makeEvent({
        path: '/data',
        httpMethod: 'POST',
        body: JSON.stringify({ name: 'test' }),
      }),
    )
    expect(JSON.parse(result.body)).toEqual({ received: { name: 'test' } })
  })

  it('returns undefined for invalid JSON', async () => {
    const router = Router()
    router.post('/data', (req, res) => res.json({ body: req.body }))
    const result = await router.handle(
      makeEvent({ path: '/data', httpMethod: 'POST', body: 'not json' }),
    )
    expect(JSON.parse(result.body)).toEqual({})
  })

  it('returns undefined for null body', async () => {
    const router = Router()
    router.post('/data', (req, res) => res.json({ body: req.body }))
    const result = await router.handle(
      makeEvent({ path: '/data', httpMethod: 'POST', body: null }),
    )
    expect(JSON.parse(result.body)).toEqual({})
  })
})

// ---------------------------------------------------------------------------
// HEAD requests
// ---------------------------------------------------------------------------

describe('HEAD requests', () => {
  it('explicit HEAD route returns empty body', async () => {
    const router = Router()
    router.head('/test', (_req, res) => res.json({ should: 'be stripped' }))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'HEAD' }),
    )
    expect(result.body).toBe('')
    expect(result.statusCode).toBe(200)
  })

  it('falls back to GET handler for HEAD with empty body', async () => {
    const router = Router()
    router.get('/test', (_req, res) => res.status(200).json({ data: true }))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'HEAD' }),
    )
    expect(result.body).toBe('')
    expect(result.statusCode).toBe(200)
  })

  it('returns 404 when no HEAD or GET handler matches', async () => {
    const router = Router()
    router.post('/test', (_req, res) => res.json({}))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'HEAD' }),
    )
    expect(result.statusCode).toBe(404)
  })
})

// ---------------------------------------------------------------------------
// API Gateway v2 (rawPath)
// ---------------------------------------------------------------------------

describe('API Gateway v2 rawPath', () => {
  it('prefers rawPath over path', async () => {
    const router = Router()
    router.get('/v2-path', (req, res) => res.json({ path: req.path }))
    const result = await router.handle(makeV2Event('/v2-path', 'GET'))
    expect(result.statusCode).toBe(200)
    expect(JSON.parse(result.body)).toEqual({ path: '/v2-path' })
  })
})

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

describe('Path normalization', () => {
  it('strips trailing slash from event path', async () => {
    const router = Router()
    router.get('/test', (_req, res) => res.json({ ok: true }))
    const result = await router.handle(
      makeEvent({ path: '/test/', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
  })

  it('adds leading slash to route pattern', async () => {
    const router = Router()
    router.get('test', (_req, res) => res.json({ ok: true }))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
  })

  it('handles root path', async () => {
    const router = Router()
    router.get('/', (_req, res) => res.json({ root: true }))
    const result = await router.handle(
      makeEvent({ path: '/', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
  })
})

// ---------------------------------------------------------------------------
// Middleware pipeline
// ---------------------------------------------------------------------------

describe('Middleware pipeline', () => {
  it('runs middleware before handler', async () => {
    const router = Router()
    const middleware: RouteHandler = (req, _res) => {
      req.locals.userId = 'from-middleware'
      return undefined
    }
    router.get('/test', middleware, (req, res) =>
      res.json({ user: req.locals.userId }),
    )
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ user: 'from-middleware' })
  })

  it('short-circuits when middleware returns a result', async () => {
    const router = Router()
    const authGuard: RouteHandler = (_req, res) =>
      res.status(401).json({ error: 'unauthorized' })
    let reached = false
    router.get('/protected', authGuard, (_req, res) => {
      reached = true
      return res.json({})
    })
    const result = await router.handle(
      makeEvent({ path: '/protected', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(401)
    expect(reached).toBe(false)
  })

  it('chains multiple middleware', async () => {
    const router = Router()
    const order: number[] = []
    const m1: RouteHandler = (req, _res) => {
      order.push(1)
      req.locals.a = 1
      return undefined
    }
    const m2: RouteHandler = (req, _res) => {
      order.push(2)
      req.locals.b = 2
      return undefined
    }
    router.get('/test', m1, m2, (req, res) => {
      order.push(3)
      return res.json({ a: req.locals.a, b: req.locals.b })
    })
    await router.handle(makeEvent({ path: '/test', httpMethod: 'GET' }))
    expect(order).toEqual([1, 2, 3])
  })
})

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe('Error handling', () => {
  it('error handler catches thrown errors', async () => {
    const router = Router()
    router.get(
      '/fail',
      () => {
        throw new Error('boom')
      },
      onError((err, _req, res) =>
        res.status(500).json({ error: (err as Error).message }),
      ),
    )
    const result = await router.handle(
      makeEvent({ path: '/fail', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(500)
    expect(JSON.parse(result.body)).toEqual({ error: 'boom' })
  })

  it('error handler catches async errors', async () => {
    const router = Router()
    router.get(
      '/fail',
      async () => {
        throw new Error('async boom')
      },
      onError((err, _req, res) =>
        res.status(500).json({ error: (err as Error).message }),
      ),
    )
    const result = await router.handle(
      makeEvent({ path: '/fail', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(500)
    expect(JSON.parse(result.body)).toEqual({ error: 'async boom' })
  })

  it('falls back to 500 when no error handler catches', async () => {
    const router = Router()
    router.get('/fail', () => {
      throw new Error('unhandled')
    })
    const result = await router.handle(
      makeEvent({ path: '/fail', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(500)
    expect(JSON.parse(result.body)).toEqual({
      message: 'Internal Server Error',
    })
  })

  it('returns 204 when handler returns nothing', async () => {
    const router = Router()
    router.get('/noop', () => undefined)
    const result = await router.handle(
      makeEvent({ path: '/noop', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(204)
  })
})

// ---------------------------------------------------------------------------
// Router composition (use)
// ---------------------------------------------------------------------------

describe('Router composition', () => {
  it('mounts child router with prefix', async () => {
    const parent = Router()
    const child = Router()
    child.get('/list', (_req, res) => res.json({ items: [] }))
    parent.use('/api', child)
    const result = await parent.handle(
      makeEvent({ path: '/api/list', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
    expect(JSON.parse(result.body)).toEqual({ items: [] })
  })

  it('mounts child router without prefix', async () => {
    const parent = Router()
    const child = Router()
    child.get('/hello', (_req, res) => res.json({ hi: true }))
    parent.use(child)
    const result = await parent.handle(
      makeEvent({ path: '/hello', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
  })

  it('nested params work through composition', async () => {
    const parent = Router()
    const child = Router()
    child.get('/:id', (req, res) => res.json({ id: req.params.id }))
    parent.use('/items', child)
    const result = await parent.handle(
      makeEvent({ path: '/items/99', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ id: '99' })
  })

  it('throws when use() is called without router', () => {
    const router = Router()
    expect(() =>
      // biome-ignore lint/suspicious/noExplicitAny: testing invalid usage
      (router as any).use('/prefix'),
    ).toThrow(/Router\.use requires a Router instance/)
  })

  it('deeply nested routers work', async () => {
    const root = Router()
    const v1 = Router()
    const users = Router()
    users.get('/:id', (req, res) => res.json({ userId: req.params.id }))
    v1.use('/users', users)
    root.use('/api/v1', v1)
    const result = await root.handle(
      makeEvent({ path: '/api/v1/users/42', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ userId: '42' })
  })
})

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------

describe('App', () => {
  it('can be called as function or constructor', () => {
    expect(App()).toBeTruthy()
    expect(new App()).toBeTruthy()
  })

  it('handles routes directly', async () => {
    const app = App()
    app.get('/test', (_req, res) => res.json({ ok: true }))
    const result = await app.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
  })

  it('applies global middleware to routes', async () => {
    const app = App()
    app.use((req, _res) => {
      req.locals.global = true
      return undefined
    })
    app.get('/test', (req, res) => res.json({ global: req.locals.global }))
    const result = await app.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ global: true })
  })

  it('applies global error handler', async () => {
    const app = App()
    app.use(
      onError((err, _req, res) =>
        res.status(500).json({ caught: (err as Error).message }),
      ),
    )
    app.get('/fail', () => {
      throw new Error('app error')
    })
    const result = await app.handle(
      makeEvent({ path: '/fail', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(500)
    expect(JSON.parse(result.body)).toEqual({ caught: 'app error' })
  })

  it('mounts router with prefix', async () => {
    const app = App()
    const api = Router()
    api.get('/items', (_req, res) => res.json({ items: [] }))
    app.use('/api', api)
    const result = await app.handle(
      makeEvent({ path: '/api/items', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
  })

  it('mounts router without prefix', async () => {
    const app = App()
    const api = Router()
    api.get('/items', (_req, res) => res.json({ items: [] }))
    app.use(api)
    const result = await app.handle(
      makeEvent({ path: '/items', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
  })

  it('global middleware wraps mounted router handlers', async () => {
    const app = App()
    app.use((req, _res) => {
      req.locals.injected = 'yes'
      return undefined
    })
    const api = Router()
    api.get('/test', (req, res) => res.json({ injected: req.locals.injected }))
    app.use('/api', api)
    const result = await app.handle(
      makeEvent({ path: '/api/test', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ injected: 'yes' })
  })

  it('supports all HTTP methods', async () => {
    const app = App()
    app.post('/p', (_req, res) => res.status(201).json({}))
    app.put('/p', (_req, res) => res.json({}))
    app.patch('/p', (_req, res) => res.json({}))
    app.delete('/p', (_req, res) => res.sendStatus(204))
    app.options('/p', (_req, res) => res.sendStatus(204))
    app.head('/p', (_req, res) => res.sendStatus(204))

    const post = await app.handle(makeEvent({ path: '/p', httpMethod: 'POST' }))
    expect(post.statusCode).toBe(201)

    const del = await app.handle(
      makeEvent({ path: '/p', httpMethod: 'DELETE' }),
    )
    expect(del.statusCode).toBe(204)
  })
})

// ---------------------------------------------------------------------------
// CORS middleware
// ---------------------------------------------------------------------------

describe('cors', () => {
  it('applies default CORS headers', async () => {
    const router = Router()
    router.get('/test', cors(), (_req, res) => res.json({}))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(result.headers?.['access-control-allow-origin']).toBe('*')
    expect(result.headers?.['access-control-allow-methods']).toBe(
      'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    )
    expect(result.headers?.['access-control-allow-headers']).toBe(
      'Content-Type,Authorization',
    )
    expect(result.headers?.['access-control-max-age']).toBe('86400')
  })

  it('applies custom CORS options', async () => {
    const router = Router()
    router.get(
      '/test',
      cors({
        origin: 'https://example.com',
        methods: ['GET', 'POST'],
        allowHeaders: ['X-Custom'],
        exposeHeaders: ['X-Exposed'],
        maxAge: 3600,
        credentials: true,
      }),
      (_req, res) => res.json({}),
    )
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(result.headers?.['access-control-allow-origin']).toBe(
      'https://example.com',
    )
    expect(result.headers?.['access-control-allow-methods']).toBe('GET,POST')
    expect(result.headers?.['access-control-allow-headers']).toBe('X-Custom')
    expect(result.headers?.['access-control-expose-headers']).toBe('X-Exposed')
    expect(result.headers?.['access-control-max-age']).toBe('3600')
    expect(result.headers?.['access-control-allow-credentials']).toBe('true')
  })

  it('does not set credentials header when false', async () => {
    const router = Router()
    router.get('/test', cors(), (_req, res) => res.json({}))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(result.headers?.['access-control-allow-credentials']).toBeUndefined()
  })
})

// ---------------------------------------------------------------------------
// Method chaining
// ---------------------------------------------------------------------------

describe('Method chaining', () => {
  it('router methods are chainable', () => {
    const r = Router()
      .get('/a', (_req, res) => res.json({}))
      .post('/b', (_req, res) => res.json({}))
      .put('/c', (_req, res) => res.json({}))
      .patch('/d', (_req, res) => res.json({}))
      .delete('/e', (_req, res) => res.json({}))
    expect(r).toBeTruthy()
  })

  it('app methods are chainable', () => {
    const a = App()
      .use((_req, _res) => undefined)
      .get('/a', (_req, res) => res.json({}))
      .post('/b', (_req, res) => res.json({}))
    expect(a).toBeTruthy()
  })
})

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

describe('Edge cases', () => {
  it('handles special regex characters in path segments', async () => {
    const router = Router()
    router.get('/api/v1.0/test', (_req, res) => res.json({ ok: true }))
    const result = await router.handle(
      makeEvent({ path: '/api/v1.0/test', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(200)
  })

  it('does not match partial paths', async () => {
    const router = Router()
    router.get('/test', (_req, res) => res.json({}))
    const result = await router.handle(
      makeEvent({ path: '/test/extra', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(404)
  })

  it('does not match shorter paths', async () => {
    const router = Router()
    router.get('/test/extra', (_req, res) => res.json({}))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(result.statusCode).toBe(404)
  })

  it('handles missing httpMethod (defaults to GET)', async () => {
    const router = Router()
    router.get('/test', (_req, res) => res.json({ ok: true }))
    const event = makeEvent({ path: '/test', httpMethod: 'GET' })
    // biome-ignore lint/suspicious/noExplicitAny: testing missing httpMethod
    ;(event as any).httpMethod = undefined
    const result = await router.handle(event)
    expect(result.statusCode).toBe(200)
  })

  it('request headers are passed through', async () => {
    const router = Router()
    router.get('/test', (req, res) =>
      res.json({ auth: req.headers.authorization }),
    )
    const result = await router.handle(
      makeEvent({
        path: '/test',
        httpMethod: 'GET',
        headers: { authorization: 'Bearer token123' },
      }),
    )
    expect(JSON.parse(result.body)).toEqual({ auth: 'Bearer token123' })
  })

  it('event is accessible on request', async () => {
    const router = Router()
    router.get('/test', (req, res) => res.json({ hasEvent: !!req.event }))
    const result = await router.handle(
      makeEvent({ path: '/test', httpMethod: 'GET' }),
    )
    expect(JSON.parse(result.body)).toEqual({ hasEvent: true })
  })
})
