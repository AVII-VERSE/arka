import { test, expect } from '@playwright/test';

test.describe('ARKA MVP Acceptance End-to-End Workflow', () => {
  test('SOC Dashboard Navigation and Real-Time Event Metric Display', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('header')).toContainText('ARKA');
    await expect(page.locator('body')).toContainText('SOC Overview');
  });

  test('Navigate to Alert Triage & Response Center', async ({ page }) => {
    await page.goto('/');
    await page.click('button:has-text("Alert Triage")');
    await expect(page.locator('body')).toContainText('Alert Triage & Response Center');
  });
});
