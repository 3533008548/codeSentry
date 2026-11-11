import { test, expect, type APIRequestContext, type Page } from '@playwright/test';
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = fileURLToPath(new URL('../../', import.meta.url));
async function headers(request: APIRequestContext) {
  return { 'X-CodeSentry-Token': (await (await request.get('/api/session')).json()).token };
}
async function seed(request: APIRequestContext, name: string) {
  const root = await mkdtemp(path.join(repo, '.venv', 'learning-browser-fixture-'));
  await mkdir(path.join(root, 'api'));
  await writeFile(path.join(root, 'task_service.py'), `class TaskService:
    def __init__(self, repository):
        self.repository = repository

    # 创建一条新任务
    def create(self, data):
        name = data["name"].strip()
        if not name:
            raise ValueError("名称不能为空")

        task = {"name": name}

        self.repository.save(task)

        return task
`);
  await writeFile(path.join(root, 'api', 'routes.py'), 'def create_task(data, service):\n    if not data.get("name", "").strip():\n        raise ValueError("名称不能为空")\n    return service.create(data)\n');
  await writeFile(path.join(root, 'repository.py'), 'class Repository:\n    def save(self, task):\n        self.last_task = task\n');
  await writeFile(path.join(root, 'README.md'), '# 任务管理示例\n这是用于界面验收的合成项目，所有模型回答均为测试响应。\n');
  await writeFile(path.join(root, 'local.py'), 'LOCAL_ONLY_CHAT_SENTINEL = True\n');
  const auth = await headers(request);
  const response = await request.post('/api/workspaces', { headers: auth, data: { path: root, name,
    access_policy: { confirmed: true, settings: { model_scope: ['*.py', 'api/*.py', 'README.md'], local_only: ['local.py'], exclude: [], respect_gitignore: true } } } });
  expect(response.status()).toBe(201);
  const workspace = await response.json();
  const base = `/api/workspaces/${workspace.id}`;
  const profile = await (await request.get(base + '/semantic-profile', { headers: auth })).json();
  const configured = await request.put(base + '/semantic-profile', { headers: auth, data: { expected_revision: profile.revision, settings: { enabled: true, model: 'deepseek-flash' } } });
  expect(configured.ok()).toBeTruthy();
  return { id: workspace.id, root, base, auth };
}
async function width(page: Page, selector: string) {
  return Math.round((await page.locator(selector).boundingBox())!.width);
}
async function drag(page: Page, side: '左' | '右', delta: number) {
  const box = (await page.getByRole('separator', { name: `调整${side}侧栏宽度` }).boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down(); await page.mouse.move(box.x + box.width / 2 + delta, box.y + box.height / 2, { steps: 10 }); await page.mouse.up();
}

test('CRAP runs from the agent chat and saves the report with source links', async ({ page, request }) => {
  const sample = await seed(request, 'CRAP 合成验收');
  await writeFile(path.join(sample.root, 'coverage.json'), JSON.stringify({ meta: { format: 3, branch_coverage: true }, files: {
    'api/routes.py': { functions: { create_task: {
      start_line: 1, executed_lines: [2], missing_lines: [3, 4], missing_branches: [[2, 3], [2, 4]],
      summary: { covered_lines: 1, num_statements: 3, covered_branches: 0, num_branches: 2 },
    } } },
  } }));
  const diagnostics = () => request.get('/api/e2e/semantic-transport', { headers: sample.auth }).then(response => response.json());
  const before = await diagnostics();
  await page.goto(`/#/workspace/${sample.id}`);
  await expect(page.getByRole('button', { name: 'CRAP 报告' })).toHaveCount(0);
  const input = page.getByRole('textbox', { name: '向项目Agent提问' });
  await input.fill('找一处适合拆分的 Python 函数。');
  await page.getByRole('button', { name: '发送', exact: true }).click();
  await page.getByRole('button', { name: '允许本项目自动取材与对话' }).click();
  const sent = page.waitForRequest(request => request.method() === 'POST' && request.url().endsWith('/messages'));
  await page.getByRole('button', { name: '发送', exact: true }).click();
  expect((await sent).postDataJSON().question).toBe('找一处适合拆分的 Python 函数。');
  const report = page.getByRole('region', { name: 'CRAP 维护风险报告' });
  const functionRow = report.getByRole('row').filter({ hasText: 'create_task' });
  await expect(functionRow).toContainText('6.00');
  await expect(functionRow).toContainText('0.0%（0/2）');
  await expect(functionRow).toContainText('未覆盖分支示例 2 → 3、2 → 4');
  await page.getByText('工具记录 · 2 步', { exact: true }).click();
  await expect(page.getByText('计算复杂度 · 已完成')).toBeVisible();
  await expect(page.getByText('读取源码 · 已完成')).toBeVisible();
  await functionRow.getByRole('button', { name: /api\/routes.py:1/ }).click();
  await expect(page.getByTestId('code-editor')).toContainText('def create_task');
  await page.reload();
  await expect(functionRow).toContainText('6.00');
  await expect(input).toHaveValue('');
  await expect(functionRow.getByRole('button', { name: '讨论改法', exact: true })).toHaveCount(0);
  await expect(page.locator('.chat-turn > .chat-citations button')).toHaveText(/api\/routes.py:1/);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth)).toBe(390);
  expect((await diagnostics()).requests).toBe(before.requests + 3);
});

test('project notes keep cited evidence locally and flag source changes', async ({ page, request }) => {
  const sample = await seed(request, '项目笔记合成验收');
  await page.goto(`/#/workspace/${sample.id}`);
  const input = page.getByRole('textbox', { name: '向项目Agent提问' });
  await input.fill('带我理解任务创建的入口和流程。');
  await page.getByRole('button', { name: '发送', exact: true }).click();
  await page.getByRole('button', { name: '允许本项目自动取材与对话' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('button', { name: '发送', exact: true }).click();
  const diagnosis = async () => (await (await request.get('/api/e2e/semantic-transport', { headers: sample.auth })).json()).requests;
  await page.getByRole('button', { name: '记下这点' }).click();
  const before = await diagnosis();
  const compose = page.getByRole('dialog', { name: '保存项目笔记' });
  await compose.getByLabel('笔记内容').fill('记录已查阅的任务创建路径。');
  await compose.getByLabel('保存范围').selectOption('project');
  await compose.getByRole('button', { name: '保存笔记' }).click();
  const notes = page.getByRole('dialog', { name: '项目笔记' });
  await expect(notes.getByText('证据快照一致')).toBeVisible();
  await expect(notes.getByText('待验证的判断')).toBeVisible();
  await notes.getByRole('button', { name: /api\/routes\.py:/ }).click();
  await expect(page.getByTestId('code-editor')).toContainText('def create_task');
  await page.reload();
  await page.getByRole('button', { name: '项目笔记', exact: true }).click();
  await expect(notes.getByText('记录已查阅的任务创建路径。')).toBeVisible();
  await writeFile(path.join(sample.root, 'api', 'routes.py'), 'def create_task(payload):\n    return {"changed": True}\n');
  await notes.getByRole('button', { name: '重新核对' }).click();
  await expect(notes.getByText('证据已过期')).toBeVisible();
  await expect(notes.getByRole('button', { name: /api\/routes\.py:/ })).toHaveCount(0);
  await notes.getByRole('button', { name: '归档笔记', exact: true }).click();
  await expect(notes.getByText('已归档')).toBeVisible();
  await notes.getByRole('button', { name: '删除归档笔记' }).click();
  await expect(notes.getByText(/还没有笔记/)).toBeVisible();
  expect(await diagnosis()).toBe(before);
});

test('project coaching grants once, answers followups, opens evidence and isolates projects', async ({ page, request }) => {
  await page.setViewportSize({ width: 1600, height: 1080 });
  const failures: string[] = [], external: string[] = [];
  page.on('pageerror', error => failures.push(error.message));
  page.on('request', req => { if (/^https?:/.test(req.url()) && !req.url().startsWith('http://127.0.0.1:8766/')) external.push(req.url()); });
  const first = await seed(request, '本地分析工具 · 合成验收');
  await page.goto(`/#/workspace/${first.id}`);
  await expect(page.getByTestId('project-chat')).toBeVisible();
  const input = page.getByRole('textbox', { name: '向项目Agent提问' });
  await input.fill('带我走通任务创建这条流程，也帮我留意值得重构的地方。');
  await page.getByRole('button', { name: '发送', exact: true }).click();
  await expect(page.getByRole('dialog', { name: '项目对话设置' })).toBeVisible();
  await page.getByRole('button', { name: '允许本项目自动取材与对话' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.getByRole('button', { name: '发送', exact: true }).click();
  await expect(page.locator('.chat-answer')).toContainText('接收请求 → 处理业务 → 保存结果');
  await page.locator('.chat-citations button').filter({ hasText: 'task_service.py' }).first().click();
  await expect(page.getByTestId('code-editor')).toContainText('TaskService');
  await expect(input).toBeVisible();
  await drag(page, '左', 55); await drag(page, '右', -80);
  expect(await width(page, '.explorer')).toBe(284);
  expect(await width(page, '.source-pane')).toBe(523);
  await page.locator('.chat-scroll').evaluate(element => { element.scrollTop = 0; });
  await page.getByRole('button', { name: '收起左侧栏', exact: true }).click();
  expect(await width(page, '.source-pane')).toBe(523);
  await page.getByRole('button', { name: '收起右侧栏', exact: true }).click();
  expect(await width(page, '.project-chat')).toBe(1600);
  await page.getByRole('button', { name: '显示文件栏', exact: true }).click();
  await page.getByRole('button', { name: '显示源码预览', exact: true }).click();
  expect(await width(page, '.explorer')).toBe(284);
  expect(await width(page, '.source-pane')).toBe(523);
  await page.reload();
  await expect(page.locator('.chat-answer')).toBeVisible();
  expect(await width(page, '.explorer')).toBe(284);
  expect(await width(page, '.source-pane')).toBe(523);
  await page.getByRole('button', { name: '收起左侧栏', exact: true }).click();
  await page.getByRole('button', { name: '专注对话', exact: true }).click();
  await page.getByRole('button', { name: '退出专注', exact: true }).click();
  await expect(page.locator('.explorer')).toBeHidden();
  expect(await width(page, '.source-pane')).toBe(523);
  await page.getByRole('button', { name: '显示文件栏', exact: true }).click();
  await page.getByRole('button', { name: '解释这两处校验', exact: true }).click();
  await page.getByRole('button', { name: '发送', exact: true }).click();
  await expect(page.getByTestId('chat-turn')).toHaveCount(2);
  await expect(page.locator('.chat-answer')).toHaveCount(2);
  await expect(page.getByRole('dialog')).toHaveCount(0);
  const other = await seed(request, '另一个独立项目 · 合成验收');
  await page.reload();
  await page.locator(`[data-workspace-id="${other.id}"]`).click();
  await expect(page.getByTestId('chat-turn')).toHaveCount(0);
  expect(await width(page, '.explorer')).toBe(229);
  await page.locator(`[data-workspace-id="${first.id}"]`).click();
  await expect(page.getByTestId('chat-turn')).toHaveCount(2);
  expect(await width(page, '.explorer')).toBe(284);
  await page.getByRole('button', { name: '恢复布局', exact: true }).click();
  expect(await width(page, '.explorer')).toBe(229);
  await page.getByRole('separator', { name: '调整左侧栏宽度' }).focus();
  await page.keyboard.press('ArrowRight');
  expect(await width(page, '.explorer')).toBe(239);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: '收起文件栏', exact: true }).click();
  await page.getByRole('button', { name: '收起源码预览', exact: true }).click();
  await expect(input).toBeVisible();
  const metrics = await page.evaluate(() => ({ width: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
  expect(metrics.scroll).toBe(metrics.width);
  expect(failures).toEqual([]); expect(external).toEqual([]);
});
