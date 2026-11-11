import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../../', import.meta.url));
let fixtureRoot: string;

test.beforeAll(async () => {
  fixtureRoot = await mkdtemp(path.join(repo, '.venv', 'browser-fixtures-'));
});

async function project(name: string, marker: string, extraFiles = 0) {
  const root = path.join(fixtureRoot, name);
  await mkdir(root, { recursive: true });
  await writeFile(path.join(root, 'main.py'), `from core import describe\n\nMARKER = '${marker}'\n\nif __name__ == '__main__':\n    print(describe(MARKER))\n`);
  await writeFile(path.join(root, 'core.py'), 'def describe(value: str) -> str:\n    return value.upper()\n');
  await writeFile(path.join(root, 'README.md'), `# ${name}\nLocal browser acceptance fixture.\n`);
  await writeFile(path.join(root, '.env'), 'FAKE_SECRET_MUST_NOT_BE_VISIBLE=true\n');
  await Promise.all(Array.from({ length: extraFiles }, (_, index) => writeFile(
    path.join(root, `module_${index}.py`),
    Array.from({ length: 30 }, (_, n) => `def function_${n}(value):\n    return value + ${n}\n`).join('\n'),
  )));
  return root;
}

async function api(request: APIRequestContext) {
  const response = await request.get('/api/session');
  expect(response.ok()).toBeTruthy();
  return { 'X-CodeSentry-Token': (await response.json()).token as string };
}

async function seed(request: APIRequestContext, root: string, name: string) {
  const response = await request.post('/api/workspaces', { headers: await api(request), data: { path: root, name,
    access_policy: { confirmed: true, settings: { respect_gitignore: true, exclude: [], local_only: [], model_scope: [] } } } });
  expect(response.status()).toBe(201);
  return response.json() as Promise<{ id: string }>;
}

async function openWorkspace(page: Page, id: string) {
  await page.locator(`[data-testid="workspace-card"][data-workspace-id="${id}"]`).click();
  await expect(page).toHaveURL(new RegExp(id));
  await expect(page.getByTestId('file-tree')).toBeVisible();
}

test('real workspaces isolate and restore the single read-only source preview', async ({ page, request }) => {
  const errors: string[] = [];
  const external: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', req => { if (/^https?:/.test(req.url()) && !req.url().startsWith('http://127.0.0.1:8766/')) external.push(req.url()); });
  const alpha = await project('alpha', 'ALPHA_WORKSPACE_SENTINEL');
  const beta = await project('beta', 'BETA_WORKSPACE_SENTINEL');
  await page.goto('/');
  await page.getByRole('button', { name: '添加工作空间' }).click();
  await page.getByLabel('项目目录', { exact: true }).fill(alpha);
  await page.getByLabel('工作空间名称').fill('浏览器验收 Alpha');
  await page.getByTestId('access-preview-button').click();
  await expect(page.getByTestId('access-preview')).toBeVisible();
  await page.getByLabel('我已核对以上文件访问范围', { exact: true }).check();
  await page.getByRole('button', { name: '打开工作空间', exact: true }).click();
  await expect(page.locator('.topbar-workspace')).toContainText('浏览器验收 Alpha');
  const alphaId = page.url().split('/').at(-1)!;
  await page.getByRole('treeitem', { name: '打开 main.py', exact: true }).click();
  await expect(page.getByTestId('code-editor')).toContainText('ALPHA_WORKSPACE_SENTINEL');
  await expect(page.getByTestId('file-tree')).not.toContainText('.env');
  // The real Monaco model is read-only: keyboard input cannot change the source.
  await page.getByTestId('code-editor').click();
  await page.keyboard.press('Control+Home');
  await page.keyboard.type('SHOULD_NOT_BE_INSERTED');
  await expect(page.getByTestId('code-editor')).not.toContainText('SHOULD_NOT_BE_INSERTED');
  await page.getByRole('treeitem', { name: '打开 core.py', exact: true }).click();

  const betaWorkspace = await seed(request, beta, '浏览器验收 Beta');
  await page.reload();
  await openWorkspace(page, betaWorkspace.id);
  await expect(page.getByTestId('code-editor')).toHaveCount(0);
  await page.getByRole('treeitem', { name: '打开 main.py', exact: true }).click();
  await expect(page.getByTestId('code-editor')).toContainText('BETA_WORKSPACE_SENTINEL');
  await expect(page.getByTestId('code-editor')).not.toContainText('ALPHA_WORKSPACE_SENTINEL');
  await openWorkspace(page, alphaId);
  await expect(page.locator('.file-breadcrumb')).toContainText('core.py');
  await page.reload();
  await expect(page.locator('.file-breadcrumb')).toContainText('core.py');
  await expect(page.getByRole('complementary', { name: '源码预览' }).getByRole('tab')).toHaveCount(0);
  await expect(page.getByRole('button', { name: '变更范围', exact: true })).toHaveCount(0);
  await page.getByRole('treeitem', { name: '打开 main.py', exact: true }).click();
  await expect(page.getByTestId('code-editor')).toContainText('ALPHA_WORKSPACE_SENTINEL');
  await writeFile(path.join(alpha, 'main.py'), "MARKER = 'ALPHA_CHANGED'\n");
  await page.getByRole('button', { name: '刷新当前文件', exact: true }).click();
  await expect(page.getByTestId('code-editor')).toContainText('ALPHA_CHANGED');
  await openWorkspace(page, betaWorkspace.id);
  await expect(page.getByTestId('code-editor')).toContainText('BETA_WORKSPACE_SENTINEL');
  expect(errors).toEqual([]);
  expect(external).toEqual([]);
});

test('migration waits for scope confirmation; excluded files stay unreadable while local-only files remain readable', async ({ page, request }) => {
  const root = await project('privacy-migration', 'MIGRATION_MAIN_SENTINEL');
  await writeFile(path.join(root, 'hidden.py'), "MARKER = 'FULLY_EXCLUDED_SENTINEL'\n");
  await writeFile(path.join(root, 'local.py'), "MARKER = 'LOCAL_ONLY_SENTINEL'\n");
  await writeFile(path.join(root, 'ignored.py'), "MARKER = 'GIT_IGNORED_SENTINEL'\n");
  await writeFile(path.join(root, '.gitignore'), 'ignored.py\n');
  const headers = await api(request);
  const opened = await request.post('/api/workspaces', { headers, data: { path: root, name: '权限迁移验收' } });
  const workspace = await opened.json();
  expect(workspace.access_policy.confirmed).toBe(false);
  const contentRequests: string[] = [];
  page.on('request', req => { if (req.url().includes(`/api/workspaces/${workspace.id}/file`) || req.url().includes(`/api/workspaces/${workspace.id}/analyses`)) contentRequests.push(req.url()); });
  await page.addInitScript(id => localStorage.setItem('codesentry.workspace.'+id, JSON.stringify({workspace_id:id,tabs:['hidden.py'],selected:'hidden.py',expanded:[]})), workspace.id);
  await page.goto(`/#/workspace/${workspace.id}`);
  await expect(page.getByRole('dialog').getByRole('heading', { name: '确认文件访问范围', exact: true })).toBeVisible();
  expect(contentRequests).toEqual([]);
  await page.getByTestId('exclude-input').fill('hidden.py');
  await page.getByTestId('local-only-input').fill('local.py');
  await page.getByTestId('access-preview-button').click();
  await expect(page.getByTestId('access-preview')).toContainText('hidden.py');
  await expect(page.getByTestId('access-preview')).toContainText('local.py');
  expect(contentRequests).toEqual([]);
  await page.getByLabel('我已核对以上文件访问范围', { exact: true }).check();
  await page.getByTestId('access-confirm-button').click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(page.getByTestId('file-tree')).not.toContainText('hidden.py');
  await expect(page.getByTestId('file-tree')).not.toContainText('ignored.py');
  await page.getByRole('treeitem', { name: '打开 local.py', exact: true }).click();
  await expect(page.getByTestId('code-editor')).toContainText('LOCAL_ONLY_SENTINEL');
  const denied = await request.get(`/api/workspaces/${workspace.id}/file?path=hidden.py`, { headers });
  expect([400,403]).toContain(denied.status());
  const changed = await request.patch(`/api/workspaces/${workspace.id}`, { headers, data: { access_policy: { confirmed: true,
    settings: { respect_gitignore:true,exclude:['hidden.py','local.py'],local_only:[],model_scope:[] } } } });
  expect(changed.ok()).toBeTruthy();
  // A second tab/client may tighten permissions: the open editor must clear too.
  await expect(page.getByTestId('code-editor')).toHaveCount(0, { timeout:10_000 });
  await expect(page.getByTestId('file-tree')).not.toContainText('local.py');
  await page.reload();
  await expect(page.getByTestId('code-editor')).toHaveCount(0);
  await expect(page.getByTestId('file-tree')).not.toContainText('local.py');
});

test('a slow old file response cannot replace the newly selected workspace', async ({ page, request }) => {
  const a = await seed(request, await project('race-alpha', 'SLOW_ALPHA_SENTINEL'), '慢响应 Alpha');
  const b = await seed(request, await project('race-beta', 'CURRENT_BETA_SENTINEL'), '当前 Beta');
  let started!: () => void;
  const pending = new Promise<void>(resolve => { started = resolve; });
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route(`**/api/workspaces/${a.id}/file?**`, async route => {
    const response = await route.fetch();
    started();
    await gate;
    await route.fulfill({ response }).catch(() => { /* workspace switch aborts this request */ });
  });
  await page.goto(`/#/workspace/${a.id}`);
  await page.getByRole('treeitem', { name: '打开 main.py', exact: true }).click();
  await pending;
  await openWorkspace(page, b.id);
  await page.getByRole('treeitem', { name: '打开 main.py', exact: true }).click();
  await expect(page.getByTestId('code-editor')).toContainText('CURRENT_BETA_SENTINEL');
  release();
  await page.unrouteAll({ behavior: 'wait' });
  await expect(page.getByTestId('code-editor')).not.toContainText('SLOW_ALPHA_SENTINEL');
  await expect(page.locator('.topbar-workspace')).toContainText('当前 Beta');
});
