import { test, expect } from '@playwright/test';

test.describe('EventsWorkspace e2e', () => {
  test('loads events timeline, respond shortcuts, and collector controls', async ({ page }) => {
    await page.goto('/events');

    await expect(page.getByRole('heading', { name: '事件工作台' })).toBeVisible();
    await expect(page.getByLabel('事件时间线')).toBeVisible();
    await expect(page.getByLabel('事件热图')).toBeVisible();

    const quickActionButton = page.getByLabel('respond 快捷操作').getByRole('button', { name: '触发 Respond' }).first();
    await quickActionButton.click();
    await expect(page.getByText('已触发 Respond 任务').first()).toBeVisible();

    const detectionButton = page.getByLabel('实时检测告警').getByRole('button', { name: '触发 Respond' }).first();
    await detectionButton.click();
    await expect(page.getByText('已为检测结果创建 Respond 任务').first()).toBeVisible();

    const collectorCard = page.getByLabel('collector 控制面');
    await collectorCard.getByRole('spinbutton', { name: 'Lag 阈值 (秒)' }).fill('4');
    await collectorCard.getByRole('button', { name: '保存配置' }).click();
    await expect(page.getByText('Collector 配置已更新').first()).toBeVisible();
  });
});
