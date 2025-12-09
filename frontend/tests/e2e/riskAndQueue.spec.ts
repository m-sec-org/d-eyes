import { test, expect } from '@playwright/test';

test.describe('Risk & Queue workspaces', () => {
  test('renders risk dashboard trends from summary API', async ({ page }) => {
    await page.goto('/risks');

    await expect(page.getByRole('heading', { name: '风险监控' })).toBeVisible();
    await expect(page.getByRole('button', { name: '导出风险报表' })).toBeVisible();
    await expect(page.getByText('状态趋势')).toBeVisible();
    await expect(page.getByText(/较前 24 小时/).first()).toBeVisible();
  });

  test('shows queue monitor sticky toolbar and pagination summaries', async ({ page }) => {
    await page.goto('/queues');

    await expect(page.getByRole('heading', { name: '命令队列' })).toBeVisible();
    await expect(page.getByText('队列运行洞察')).toBeVisible();

    await page.getByRole('tab', { name: '任务类型' }).click();
    await expect(page.getByText(/显示 \d+ \/ \d+ 种任务/)).toBeVisible();

    await page.getByRole('tab', { name: 'Agent 活动' }).click();
    await expect(page.getByText(/显示 1-1 \/ 1 个 Agent/)).toBeVisible();
  });
});
