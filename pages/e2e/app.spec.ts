import { expect, test } from '@playwright/test'
import { createHash } from 'node:crypto'

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem('gsvibe.language', 'zh-CN')
  })
})

test('opens the static symbol browser without a Process API connection', async ({ page }) => {
  const indexResponse = await page.request.get('gamesymbols/index.json')
  expect(indexResponse.ok()).toBeTruthy()
  const index = await indexResponse.json()
  expect(index.schemaVersion).toBe(4)
  const currentVersion = index.versions[0]
  expect(currentVersion.sha256).toMatch(/^[0-9a-f]{64}$/)
  expect(currentVersion.url).toBe(`${currentVersion.gameVersion}.${currentVersion.sha256}.json`)
  expect(currentVersion.size).toBeGreaterThan(0)
  expect(currentVersion.lastPublishTime).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/)
  const datasetResponse = await page.request.get(`gamesymbols/${currentVersion.url}`)
  expect(datasetResponse.ok()).toBeTruthy()
  const datasetBytes = await datasetResponse.body()
  expect(datasetBytes.byteLength).toBe(currentVersion.size)
  expect(createHash('sha256').update(datasetBytes).digest('hex')).toBe(currentVersion.sha256)
  const dataset = JSON.parse(datasetBytes.toString('utf8'))
  expect(dataset.schemaVersion).toBe(5)
  expect(dataset.source.snapshotSchemaVersion).toBe(8)
  expect(dataset.source.lastPublishTime).toBe(currentVersion.lastPublishTime)
  expect(Object.keys(dataset.binaries).length).toBeGreaterThan(0)
  const firstBinary = Object.values(Object.values(dataset.binaries)[0] as Record<string, unknown>)[0] as Record<string, unknown>
  expect(firstBinary.sha256).toMatch(/^[0-9a-f]{64}$/)
  expect(firstBinary.md5).toMatch(/^[0-9a-f]{32}$/)
  expect(firstBinary.crc32).toMatch(/^[0-9a-f]{8}$/)
  expect(firstBinary.crc64).toMatch(/^[0-9a-f]{16}$/)
  expect(firstBinary.size).toEqual(expect.any(Number))
  expect(typeof firstBinary.isBlob).toBe('boolean')

  const progressRequests: string[] = []
  page.on('request', (request) => {
    if (/\/api\/v1\/|\/healthz|\/readyz/.test(request.url())) progressRequests.push(request.url())
  })
  await page.goto('./')
  await expect(page.getByRole('heading', { name: '浏览符号' })).toBeVisible()
  await expect(page.locator('.symbol-version-controls').getByText(currentVersion.gameVersion, { exact: true })).toBeVisible()
  await expect(page.getByText(new RegExp(`最后更新 \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2} · ${currentVersion.fileCount} 个符号`))).toBeVisible()

  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByLabel('游戏版本')).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy()
  expect(progressRequests).toEqual([])
  expect(await page.evaluate(() => Object.keys(localStorage).filter((key) => key.startsWith('gsvibe.api')))).toEqual([])
})

test('switches the static application between supported languages', async ({ page }) => {
  await page.goto('./')
  await page.getByLabel('语言').click()
  await page.locator('.ant-select-dropdown').getByText('English', { exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Explore Symbols' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')

  await page.getByLabel('Language').click()
  await page.locator('.ant-select-dropdown').getByText('Traditional Chinese', { exact: true }).click()
  await expect(page.getByRole('heading', { name: '瀏覽符號' })).toBeVisible()
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-TW')
})

test('searches symbols, opens details, and persists the selected theme', async ({ page }) => {
  const index = await (await page.request.get('gamesymbols/index.json')).json()
  const dataset = await (await page.request.get(`gamesymbols/${index.versions[0].url}`)).json()
  const record = dataset.records[0]
  await page.goto('./')
  await page.getByPlaceholder('搜索符号名或 Artifact').fill(record.symbolName)
  await page.locator('.symbol-search-card').getByRole('button', { name: record.symbolName, exact: true }).first().click()
  await expect(page.getByText('符号详情', { exact: true })).toBeVisible()
  await expect(page.getByText(record.id, { exact: true })).toBeVisible()
  await page.keyboard.press('Escape')

  await page.getByRole('button', { name: '切换到浅色模式' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  await expect(page.getByRole('heading', { name: '浏览符号' })).toBeVisible()
})
