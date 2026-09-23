import { test, expect } from "@playwright/test";

const TEST_USER = {
  email: `e2e-${Date.now()}@test.local`,
  password: "TestPass123!",
};

test.describe("Authentication", () => {
  test("register a new user and see empty feed list", async ({ page }) => {
    await page.goto("/");

    // Should redirect to login
    await expect(page).toHaveURL(/login/);

    // Navigate to register
    await page.click("text=Register");
    await expect(page).toHaveURL(/register/);

    // Fill registration form
    await page.fill('input[name="email"], input[type="email"]', TEST_USER.email);
    await page.fill('input[name="password"], input[type="password"]', TEST_USER.password);

    await page.click('button[type="submit"]');

    // Should be on main page after registration
    await expect(page.locator('[role="main"], #main-content')).toBeVisible({
      timeout: 15_000,
    });
  });

  test("login with existing credentials", async ({ page }) => {
    // First register
    await page.goto("/register");
    const email = `e2e-login-${Date.now()}@test.local`;
    await page.fill('input[name="email"], input[type="email"]', email);
    await page.fill('input[name="password"], input[type="password"]', "TestPass123!");
    await page.click('button[type="submit"]');
    await expect(page.locator('[role="main"], #main-content')).toBeVisible({
      timeout: 15_000,
    });

    // Logout (clear storage)
    await page.evaluate(() => localStorage.clear());
    await page.goto("/login");

    // Login
    await page.fill('input[name="email"], input[type="email"]', email);
    await page.fill('input[name="password"], input[type="password"]', "TestPass123!");
    await page.click('button[type="submit"]');

    await expect(page.locator('[role="main"], #main-content')).toBeVisible({
      timeout: 15_000,
    });
  });
});
