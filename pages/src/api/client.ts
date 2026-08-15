import type {
  ApiErrorDetail,
  HealthResponse,
  RunPageResponse,
  RunStatus,
  RunView,
  SnapshotResponse,
  TaskDetail,
} from './types'
import i18n from '../i18n'

export class ApiError extends Error {
  status: number
  detail: ApiErrorDetail

  constructor(status: number, detail: ApiErrorDetail) {
    super(detail.message)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
  }
}

async function readError(response: Response): Promise<ApiErrorDetail> {
  try {
    const body = (await response.json()) as { detail?: Partial<ApiErrorDetail> }
    return {
      code: body.detail?.code || `http_${response.status}`,
      message: body.detail?.message || response.statusText || i18n.t('errors.requestFailed'),
    }
  } catch {
    return { code: `http_${response.status}`, message: response.statusText || i18n.t('errors.requestFailed') }
  }
}

export async function requestJson<T>(url: string, signal?: AbortSignal): Promise<T> {
  let response: Response
  try {
    response = await fetch(url, { headers: { Accept: 'application/json' }, signal })
  } catch (error) {
    throw new ApiError(0, {
      code: 'network_error',
      message: error instanceof Error ? error.message : i18n.t('errors.cannotConnectApi'),
    })
  }
  if (!response.ok) throw new ApiError(response.status, await readError(response))
  return (await response.json()) as T
}

function apiUrl(baseUrl: string, path: string): string {
  return `${baseUrl}${path}`
}

export function encodeTaskIdPath(taskId: string): string {
  return taskId.split('/').map(encodeURIComponent).join('/')
}

export async function checkApiConnection(baseUrl: string): Promise<void> {
  await requestJson<HealthResponse>(apiUrl(baseUrl, '/healthz'))
  await requestJson<HealthResponse>(apiUrl(baseUrl, '/readyz'))
}

export interface RunFilters {
  status?: RunStatus
  gamever?: string
}

export function listRuns(
  baseUrl: string,
  offset: number,
  filters: RunFilters,
  signal?: AbortSignal,
): Promise<RunPageResponse> {
  const params = new URLSearchParams({ offset: String(offset), limit: '50' })
  if (filters.status) params.set('status', filters.status)
  if (filters.gamever) params.set('gamever', filters.gamever)
  return requestJson(apiUrl(baseUrl, `/api/v1/runs?${params}`), signal)
}

export function getRun(baseUrl: string, runId: string, signal?: AbortSignal): Promise<RunView> {
  return requestJson(apiUrl(baseUrl, `/api/v1/runs/${encodeURIComponent(runId)}`), signal)
}

export function getSnapshot(
  baseUrl: string,
  runId: string,
  signal?: AbortSignal,
): Promise<SnapshotResponse> {
  return requestJson(apiUrl(baseUrl, `/api/v1/runs/${encodeURIComponent(runId)}/snapshot`), signal)
}

export function getTaskDetail(
  baseUrl: string,
  runId: string,
  taskId: string,
  signal?: AbortSignal,
): Promise<TaskDetail> {
  const runPath = encodeURIComponent(runId)
  return requestJson(apiUrl(baseUrl, `/api/v1/runs/${runPath}/tasks/${encodeTaskIdPath(taskId)}`), signal)
}

export function streamUrl(baseUrl: string, runId: string, after: string): string {
  const runPath = encodeURIComponent(runId)
  return apiUrl(baseUrl, `/api/v1/runs/${runPath}/stream?after=${encodeURIComponent(after)}`)
}
