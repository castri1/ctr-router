import type { APIGatewayEvent, APIGatewayProxyResult } from 'aws-lambda'

type HttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'OPTIONS'
  | 'HEAD'

export type Request = {
  event: APIGatewayEvent
  path: string
  method: HttpMethod
  params: Record<string, string>
  query: Record<string, string | undefined>
  queryMulti: Record<string, string[]>
  headers: Record<string, string | undefined>
  body: unknown
  locals: Record<string, unknown>
}

export const HttpStatus = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,

  MOVED_PERMANENTLY: 301,
  FOUND: 302,
  NOT_MODIFIED: 304,

  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  UNPROCESSABLE_ENTITY: 422,
  TOO_MANY_REQUESTS: 429,

  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504,
} as const
export type HttpStatus = (typeof HttpStatus)[keyof typeof HttpStatus]

export class Response {
  private statusCode = 200
  private headers: Record<string, string> = {}
  private result: APIGatewayProxyResult | undefined

  status(code: number | HttpStatus): this {
    this.statusCode = Number(code)
    return this
  }

  header(name: string, value: string): this {
    this.headers[name.toLowerCase()] = value
    return this
  }

  set(headers: Record<string, string>): this {
    for (const [k, v] of Object.entries(headers)) {
      this.headers[k.toLowerCase()] = v
    }
    return this
  }

  type(contentType: string): this {
    this.header('content-type', contentType)
    return this
  }

  private commit(body: string, defaultType: string): APIGatewayProxyResult {
    const headers = { 'content-type': defaultType, ...this.headers }
    this.result = { statusCode: this.statusCode, headers, body }
    return this.result
  }

  json(data: unknown): APIGatewayProxyResult {
    return this.commit(JSON.stringify(data ?? {}), 'application/json')
  }

  text(message: string): APIGatewayProxyResult {
    return this.commit(message, 'text/plain; charset=utf-8')
  }

  send(): APIGatewayProxyResult {
    return this.commit('', 'text/plain; charset=utf-8')
  }

  sendStatus(status: number): APIGatewayProxyResult {
    this.statusCode = status
    return this.commit('', 'text/plain; charset=utf-8')
  }

  getResult(): APIGatewayProxyResult | undefined {
    return this.result
  }
}

export type RouteHandler = (
  req: Request,
  res: Response,
) =>
  | APIGatewayProxyResult
  | undefined
  | Promise<APIGatewayProxyResult | undefined>

type ErrorHandlerFn = (
  error: unknown,
  req: Request,
  res: Response,
) =>
  | APIGatewayProxyResult
  | undefined
  | Promise<APIGatewayProxyResult | undefined>

export type ErrorRouteHandler = ErrorHandlerFn & { __errorHandler: true }

export function onError(handler: ErrorHandlerFn): ErrorRouteHandler {
  const marked = handler as ErrorRouteHandler
  marked.__errorHandler = true
  return marked
}

type AnyHandler = RouteHandler | ErrorRouteHandler

function isErrorHandler(fn: AnyHandler): fn is ErrorRouteHandler {
  return '__errorHandler' in fn && fn.__errorHandler === true
}

function normalizePath(inputPath: string | undefined | null): string {
  const raw = inputPath ?? '/'
  let p = raw.startsWith('/') ? raw : `/${raw}`
  if (p.length > 1 && p.endsWith('/')) p = p.slice(0, -1)
  return p
}

function getEventPath(event: APIGatewayEvent): string {
  // Prefer HTTP API v2 rawPath if present, else fallback to v1 path
  const possibleRawPath = (event as unknown as { rawPath?: unknown }).rawPath
  const rawPath =
    typeof possibleRawPath === 'string' ? possibleRawPath : event.path
  return normalizePath(rawPath)
}

function safeParseJson(maybeJson: string | null): unknown {
  if (!maybeJson) return undefined
  try {
    return JSON.parse(maybeJson)
  } catch {
    return undefined
  }
}

function escapeRegex(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function compileRoutePattern(pathPattern: string): {
  regex: RegExp
  paramNames: string[]
  pattern: string
} {
  const pattern = normalizePath(pathPattern)
  const segments = pattern.split('/').filter(Boolean)
  const paramNames: string[] = []

  const regexParts = segments.map((segment) => {
    if (segment.startsWith(':')) {
      const name = segment.slice(1)
      paramNames.push(name)
      return '([^/]+)'
    }
    return escapeRegex(segment)
  })

  const regex = new RegExp(`^/${regexParts.join('/')}$`)
  return { regex, paramNames, pattern }
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

function joinPaths(base: string, sub: string): string {
  const a = normalizePath(base)
  const b = normalizePath(sub)
  if (a === '/') return b
  if (b === '/') return a
  return normalizePath(`${a}/${b.replace(/^\//, '')}`)
}

async function runHandlerPipeline(
  handlers: AnyHandler[],
  req: Request,
  res: Response,
): Promise<APIGatewayProxyResult | undefined> {
  try {
    for (const h of handlers) {
      if (isErrorHandler(h)) continue
      const maybeResult = await (h as RouteHandler)(req, res)
      if (maybeResult) return maybeResult
      const captured = res.getResult()
      if (captured) return captured
    }
    return undefined
  } catch (err) {
    for (const h of handlers) {
      if (!isErrorHandler(h)) continue
      try {
        const maybeResult = await (h as ErrorHandlerFn)(err, req, res)
        if (maybeResult) return maybeResult
        const captured = res.getResult()
        if (captured) return captured
      } catch {
        // keep trying next error handler
      }
    }
    throw err
  }
}

type CompiledRoute = {
  method: HttpMethod
  pattern: string
  regex: RegExp
  paramNames: string[]
  handlers: AnyHandler[]
}

class RouterImpl {
  private routeMap: Map<HttpMethod, CompiledRoute[]> = new Map()

  addRoute(
    method: HttpMethod,
    pattern: string,
    regex: RegExp,
    paramNames: string[],
    handlers: AnyHandler[],
  ): void {
    let bucket = this.routeMap.get(method)
    if (!bucket) {
      bucket = []
      this.routeMap.set(method, bucket)
    }
    bucket.push({ method, pattern, regex, paramNames, handlers })
  }

  getRoutes(): Array<{
    method: HttpMethod
    pattern: string
    handlers: AnyHandler[]
  }> {
    const routes: Array<{
      method: HttpMethod
      pattern: string
      handlers: AnyHandler[]
    }> = []
    for (const bucket of this.routeMap.values()) {
      for (const r of bucket) {
        routes.push({
          method: r.method,
          pattern: r.pattern,
          handlers: r.handlers,
        })
      }
    }
    return routes
  }

  use(prefix: string, child: RouterImpl): this
  use(child: RouterImpl): this
  use(prefixOrChild: string | RouterImpl, maybeChild?: RouterImpl): this {
    let base = '/'
    let child: RouterImpl | undefined
    if (typeof prefixOrChild === 'string') {
      base = prefixOrChild
      child = maybeChild
    } else {
      child = prefixOrChild
    }
    if (!child) throw new Error('Router.use requires a Router instance')

    for (const r of child.getRoutes()) {
      const combined = joinPaths(base, r.pattern)
      const { regex, paramNames, pattern } = compileRoutePattern(combined)
      this.addRoute(r.method, pattern, regex, paramNames, r.handlers)
    }
    return this
  }

  get(path: string, ...handlers: AnyHandler[]): this {
    const { regex, paramNames, pattern } = compileRoutePattern(path)
    this.addRoute('GET', pattern, regex, paramNames, handlers)
    return this
  }

  post(path: string, ...handlers: AnyHandler[]): this {
    const { regex, paramNames, pattern } = compileRoutePattern(path)
    this.addRoute('POST', pattern, regex, paramNames, handlers)
    return this
  }

  put(path: string, ...handlers: AnyHandler[]): this {
    const { regex, paramNames, pattern } = compileRoutePattern(path)
    this.addRoute('PUT', pattern, regex, paramNames, handlers)
    return this
  }

  patch(path: string, ...handlers: AnyHandler[]): this {
    const { regex, paramNames, pattern } = compileRoutePattern(path)
    this.addRoute('PATCH', pattern, regex, paramNames, handlers)
    return this
  }

  delete(path: string, ...handlers: AnyHandler[]): this {
    const { regex, paramNames, pattern } = compileRoutePattern(path)
    this.addRoute('DELETE', pattern, regex, paramNames, handlers)
    return this
  }

  options(path: string, ...handlers: AnyHandler[]): this {
    const { regex, paramNames, pattern } = compileRoutePattern(path)
    this.addRoute('OPTIONS', pattern, regex, paramNames, handlers)
    return this
  }

  head(path: string, ...handlers: AnyHandler[]): this {
    const { regex, paramNames, pattern } = compileRoutePattern(path)
    this.addRoute('HEAD', pattern, regex, paramNames, handlers)
    return this
  }

  async handle(event: APIGatewayEvent): Promise<APIGatewayProxyResult> {
    const method = (event.httpMethod?.toUpperCase() as HttpMethod) || 'GET'
    const reqPath = getEventPath(event)

    // Lazy body parsing — only computed on first access
    let parsedBody: unknown
    let bodyParsed = false

    const candidates = this.routeMap.get(method)

    // For HEAD, fall back to GET handlers if no explicit HEAD route matches
    const fallbackCandidates =
      method === 'HEAD' ? this.routeMap.get('GET') : undefined

    const matchRoute = (
      routes: CompiledRoute[] | undefined,
    ): APIGatewayProxyResult | null | Promise<APIGatewayProxyResult | null> => {
      if (!routes) return null

      for (const route of routes) {
        const match = route.regex.exec(reqPath)
        if (!match) continue

        const params: Record<string, string> = {}
        route.paramNames.forEach((name, idx) => {
          params[name] = safeDecode(match[idx + 1] ?? '')
        })

        const req: Request = {
          event,
          path: reqPath,
          method,
          params,
          query: event.queryStringParameters ?? {},
          queryMulti: buildQueryMulti(event),
          headers: event.headers ?? {},
          get body() {
            if (!bodyParsed) {
              parsedBody = safeParseJson(event.body ?? null)
              bodyParsed = true
            }
            return parsedBody
          },
          locals: {},
        }

        return (async () => {
          try {
            const res = new Response()
            const maybeResult = await runHandlerPipeline(
              route.handlers,
              req,
              res,
            )
            if (maybeResult) return maybeResult
            const captured = res.getResult()
            if (captured) return captured
            return { statusCode: HttpStatus.NO_CONTENT, headers: {}, body: '' }
          } catch (error) {
            console.error('Route handler error:', error)
            return new Response()
              .status(HttpStatus.INTERNAL_SERVER_ERROR)
              .json({ message: 'Internal Server Error' })
          }
        })()
      }

      return null
    }

    const primary = await matchRoute(candidates)
    if (primary) {
      if (method === 'HEAD') {
        return { ...primary, body: '' }
      }
      return primary
    }

    const fallback = await matchRoute(fallbackCandidates)
    if (fallback) {
      return { ...fallback, body: '' }
    }

    return new Response()
      .status(HttpStatus.NOT_FOUND)
      .json({ message: 'Not Found', method, path: reqPath })
  }
}

function buildQueryMulti(event: APIGatewayEvent): Record<string, string[]> {
  const multi = event.multiValueQueryStringParameters
  if (!multi) {
    const single = event.queryStringParameters
    if (!single) return {}
    const result: Record<string, string[]> = {}
    for (const [k, v] of Object.entries(single)) {
      if (v !== undefined) result[k] = [v]
    }
    return result
  }
  const result: Record<string, string[]> = {}
  for (const [k, v] of Object.entries(multi)) {
    if (v) result[k] = v
  }
  return result
}

function isRouterLike(obj: unknown): obj is {
  getRoutes: () => Array<{
    method: HttpMethod
    pattern: string
    handlers: AnyHandler[]
  }>
} {
  return (
    typeof obj === 'object' &&
    obj !== null &&
    'getRoutes' in (obj as Record<string, unknown>) &&
    typeof (obj as { getRoutes: unknown }).getRoutes === 'function'
  )
}

export type CorsOptions = {
  origin?: string
  methods?: HttpMethod[]
  allowHeaders?: string[]
  exposeHeaders?: string[]
  maxAge?: number
  credentials?: boolean
}

const DEFAULT_CORS_METHODS: HttpMethod[] = [
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'OPTIONS',
]

export function cors(opts?: CorsOptions): RouteHandler {
  const origin = opts?.origin ?? '*'
  const methods = (opts?.methods ?? DEFAULT_CORS_METHODS).join(',')
  const allowHeaders =
    opts?.allowHeaders?.join(',') ?? 'Content-Type,Authorization'
  const exposeHeaders = opts?.exposeHeaders?.join(',') ?? ''
  const maxAge = opts?.maxAge ?? 86400
  const credentials = opts?.credentials ?? false

  return (_req: Request, res: Response) => {
    res.header('access-control-allow-origin', origin)
    res.header('access-control-allow-methods', methods)
    res.header('access-control-allow-headers', allowHeaders)
    if (exposeHeaders)
      res.header('access-control-expose-headers', exposeHeaders)
    res.header('access-control-max-age', String(maxAge))
    if (credentials) res.header('access-control-allow-credentials', 'true')
    return undefined
  }
}

class AppImpl {
  private root: RouterImpl = new RouterImpl()
  private globalHandlers: AnyHandler[] = []

  private composeHandlers(routeHandlers: AnyHandler[]): AnyHandler[] {
    const globalNormal = this.globalHandlers.filter((h) => !isErrorHandler(h))
    const globalError = this.globalHandlers.filter((h) => isErrorHandler(h))
    return [...globalNormal, ...routeHandlers, ...globalError]
  }

  private mountRouter(child: RouterImpl, base?: string): void {
    for (const r of child.getRoutes()) {
      const combinedPath = base ? joinPaths(base, r.pattern) : r.pattern
      const combinedHandlers = this.composeHandlers(r.handlers)
      const { regex, paramNames, pattern } = compileRoutePattern(combinedPath)
      this.root.addRoute(r.method, pattern, regex, paramNames, combinedHandlers)
    }
  }

  use(...args: Array<string | RouterImpl | AnyHandler>): this {
    if (typeof args[0] === 'string' && args[1] && isRouterLike(args[1])) {
      this.mountRouter(args[1] as RouterImpl, args[0] as string)
      return this
    }

    if (isRouterLike(args[0])) {
      this.mountRouter(args[0] as RouterImpl)
      return this
    }

    const handlers = args as AnyHandler[]
    this.globalHandlers.push(...handlers)
    return this
  }

  get(path: string, ...handlers: AnyHandler[]): this {
    this.root.get(path, ...this.composeHandlers(handlers))
    return this
  }

  post(path: string, ...handlers: AnyHandler[]): this {
    this.root.post(path, ...this.composeHandlers(handlers))
    return this
  }

  put(path: string, ...handlers: AnyHandler[]): this {
    this.root.put(path, ...this.composeHandlers(handlers))
    return this
  }

  patch(path: string, ...handlers: AnyHandler[]): this {
    this.root.patch(path, ...this.composeHandlers(handlers))
    return this
  }

  delete(path: string, ...handlers: AnyHandler[]): this {
    this.root.delete(path, ...this.composeHandlers(handlers))
    return this
  }

  options(path: string, ...handlers: AnyHandler[]): this {
    this.root.options(path, ...this.composeHandlers(handlers))
    return this
  }

  head(path: string, ...handlers: AnyHandler[]): this {
    this.root.head(path, ...this.composeHandlers(handlers))
    return this
  }

  async handle(event: APIGatewayEvent): Promise<APIGatewayProxyResult> {
    return this.root.handle(event)
  }
}

// Public factories (callable and newable)
export type Router = RouterImpl
export interface RouterFactory {
  (): RouterImpl
  new (): RouterImpl
}
export const Router: RouterFactory = function Router(): RouterImpl {
  return new RouterImpl()
} as unknown as RouterFactory

export type App = AppImpl
export interface AppFactory {
  (): AppImpl
  new (): AppImpl
}
export const App: AppFactory = function App(): AppImpl {
  return new AppImpl()
} as unknown as AppFactory
