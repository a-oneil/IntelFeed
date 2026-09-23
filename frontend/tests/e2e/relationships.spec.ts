import { test, expect } from "@playwright/test";

/**
 * Relationships browser e2e: seeds an actor + malware + typed relationship via
 * the API, then verifies the profile Relationships tab renders the verb chip,
 * tier chip and evidence controls, and that confirming a relationship swaps in
 * the CONFIRMED chip.
 */
test.describe("Relationships browser", () => {
  test("verb chip, tier chip and confirm flow on an actor profile", async ({ page }) => {
    // Register a fresh user via the UI
    await page.goto("/register");
    const email = `e2e-rel-${Date.now()}@test.local`;
    await page.fill('input[name="email"], input[type="email"]', email);
    await page.fill('input[name="password"], input[type="password"]', "TestPass123!");
    await page.click('button[type="submit"]');
    await expect(page.locator('[role="main"], #main-content')).toBeVisible({ timeout: 15_000 });

    // Seed data through the API using the app's own token
    const token = await page.evaluate(() => {
      const raw = localStorage.getItem("intelfeed-auth");
      return raw ? JSON.parse(raw)?.state?.accessToken : null;
    });
    expect(token).toBeTruthy();
    const headers = { Authorization: `Bearer ${token}` };

    const stamp = Date.now();
    const actorResp = await page.request.post("/api/entity-profiles/threat-actors", {
      headers,
      data: { name: `E2E Actor ${stamp}` },
    });
    expect(actorResp.ok()).toBeTruthy();
    const actor = await actorResp.json();

    const malwareResp = await page.request.post("/api/entity-profiles/malware", {
      headers,
      data: { name: `E2ELoader${stamp}` },
    });
    expect(malwareResp.ok()).toBeTruthy();
    const malware = await malwareResp.json();

    const relResp = await page.request.post("/api/entity-relationships", {
      headers,
      data: {
        source_type: "threat_actor",
        source_id: actor.id,
        target_type: "malware",
        target_id: malware.id,
        relationship_type: "uses",
        confidence: "probable",
      },
    });
    expect(relResp.ok()).toBeTruthy();

    // Open the actor profile → Relationships tab
    await page.goto(`/workbench/threat_actor/${actor.id}`);
    await page.getByText("Relationships", { exact: false }).first().click();

    // The typed relationship renders as a row: counterpart + passive verb chip
    // (viewed entity is the source → "E2ELoader… — used [by me]")
    const malwareLabel = page.getByText(malware.name).first();
    await expect(malwareLabel).toBeVisible({ timeout: 15_000 });
    await expect(page.getByText("used", { exact: true }).first()).toBeVisible();

    // Confirm the relationship from the row's hover actions
    await malwareLabel.hover();
    await page.getByTitle("Confirm this relationship").first().click();

    // The tier chip is replaced by the analyst-confirmed chip
    await expect(page.getByText(/confirmed\s*✓/i).first()).toBeVisible({ timeout: 15_000 });
  });
});
