import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import { mkdtemp, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../../', import.meta.url));
const fakeKey = 'sk-E2E_SYNTHETIC_ONLY_NOT_A_REAL_KEY';

async function seed(request: APIRequestContext, name: string, auth: Record<string, string>) {
  const root = await mkdtemp(path.join(repo, '.venv', 'settings-browser-fixture-'));
  await writeFile(path.join(root, 'main.py'), 'def run():\n    return 42\n');
  const result = await request.post('/api/workspaces', { headers: auth, data: { path: root, name,
    access_policy: { confirmed: true, settings: { model_scope: ['main.py'] } } } });
  expect(result.status()).toBe(201);
  return result.json() as Promise<{ id: string }>;
}
async function openSettings(page: Page) {
  await page.getByRole('button', { name: '对话设置', exact: true }).click();
  await page.getByRole('button', { name: '打开模型设置', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: '模型设置', exact: true });
  await expect(dialog.getByRole('button', { name: '保存模型设置' })).toBeEnabled();
  return dialog;
}

test('the dialogue settings preserve project-scoped enablement and explicit key restore', async ({ page, request }) => {
  const auth = { 'X-CodeSentry-Token': (await (await request.get('/api/session')).json()).token };
  const a = await seed(request, '配置 Alpha', auth);
  const b = await seed(request, '配置 Beta', auth);
  const read = (id: string) => request.get('/api/workspaces/' + id + '/semantic-profile', { headers: auth }).then(response => response.json());
  const diagnostics = () => request.get('/api/e2e/semantic-transport', { headers: auth }).then(response => response.json());
  const before = await diagnostics();
  await page.goto('/#/workspace/' + a.id);
  let dialog = await openSettings(page);
  await expect(dialog).toContainText('已使用 CodeSentry .env 密钥');
  await expect(dialog.getByLabel('DeepSeek API key')).toHaveValue('');
  await dialog.getByLabel('启用 DeepSeek 对话').check();
  await dialog.getByRole('button', { name: '保存模型设置' }).click();
  await expect(dialog).toContainText('模型设置已保存');
  expect(await read(a.id)).toMatchObject({ enabled: true, key_source: 'env_file' });

  await dialog.getByRole('button', { name: '清除此工作空间密钥' }).click();
  await expect(dialog).toContainText('尚未配置密钥');
  expect(await read(a.id)).toMatchObject({ key_configured: false, configured_key_enabled: false });
  await page.reload();
  dialog = await openSettings(page);
  await expect(dialog).toContainText('尚未配置密钥');
  await dialog.getByRole('button', { name: '使用启动配置密钥' }).click();
  await expect(dialog).toContainText('已使用 CodeSentry .env 密钥');
  expect(await read(a.id)).toMatchObject({ enabled: true, configured_key_enabled: true, key_source: 'env_file' });
  await dialog.getByRole('button', { name: '关闭模型设置' }).click();

  await page.locator('[data-workspace-id="' + b.id + '"]').click();
  dialog = await openSettings(page);
  await expect(dialog.getByLabel('启用 DeepSeek 对话')).not.toBeChecked();
  expect(await read(b.id)).toMatchObject({ enabled: false, key_source: 'env_file' });
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }))).not.toContain(fakeKey);
  expect((await diagnostics()).requests).toBe(before.requests);
});
