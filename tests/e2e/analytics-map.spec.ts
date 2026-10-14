import { test, expect, type Page } from '@playwright/test';

/**
 * Regression tests for the countries map (the "Map" view of the analytics
 * page's countries panel).
 *
 * maplibre-gl v6 moved its tile worker into a separate ES module resolved at
 * runtime from `import.meta.url`, which Turbopack cannot resolve correctly. The
 * worker silently failed to start and the map rendered as an empty ocean — no
 * countries, no hover popups, and no visible error in the UI.
 *
 * The fix stages the worker under /maplibre/ (scripts/copy-maplibre-worker.mjs)
 * and points maplibre at it via setWorkerUrl(). These tests cover both the
 * plumbing (worker assets served, CSP allows the worker) and the observable
 * outcome (country geometry is actually rendered and hit-testable).
 */

const MAP_CANVAS = 'canvas.maplibregl-canvas';

async function gotoAnalyticsMap(page: Page) {
  await page.goto('/analytics');
  const toggle = page.getByRole('group', { name: 'Show countries as' });
  await expect(toggle).toBeVisible({ timeout: 15_000 });
  await toggle.getByRole('button', { name: 'Map' }).click();
  await expect(toggle.getByRole('button', { name: 'Map' })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator(MAP_CANVAS)).toBeVisible({ timeout: 15_000 });
}

test.describe('Analytics world map', () => {
  test('maplibre worker assets are served from /maplibre/', async ({ page }) => {
    const mapRequests: { url: string; status: number }[] = [];
    page.on('response', (res) => {
      const url = new URL(res.url()).pathname;
      if (url.startsWith('/maplibre/')) mapRequests.push({ url, status: res.status() });
    });

    await gotoAnalyticsMap(page);
    // The worker is spawned lazily once the map starts loading its source.
    await expect
      .poll(() => mapRequests.map((r) => r.url), { timeout: 15_000 })
      .toContain('/maplibre/maplibre-gl-worker.mjs');

    // The worker is an ES module that imports ./maplibre-gl-shared.mjs relative
    // to itself — staging only the entry file leaves that import 404ing. The
    // browser does not report the requests a worker makes to the page, so ask
    // for the file itself; the hover test below shows the worker running on it.
    const shared = await page.request.get('/maplibre/maplibre-gl-shared.mjs');
    expect(shared.status()).toBe(200);
    expect(shared.headers()['content-type']).toMatch(/javascript/);

    const failed = mapRequests.filter((r) => r.status >= 400);
    expect(failed, `maplibre assets failed to load: ${JSON.stringify(failed)}`).toEqual([]);
  });

  test('map loads without CSP violations or worker errors', async ({ page }) => {
    const errors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') errors.push(msg.text());
    });
    page.on('pageerror', (err) => errors.push(err.message));

    await gotoAnalyticsMap(page);
    await page.waitForTimeout(3_000); // let the worker spin up and the source parse

    const mapErrors = errors.filter((e) =>
      /worker|content security policy|maplibre/i.test(e),
    );
    expect(mapErrors, `map errors in console: ${JSON.stringify(mapErrors)}`).toEqual([]);
  });

  test('map renders country geometry that responds to hover', async ({ page }) => {
    await gotoAnalyticsMap(page);

    const canvas = page.locator(MAP_CANVAS);
    // The countries panel sits below the chart: bring the map into view first.
    await canvas.scrollIntoViewIfNeeded();
    const box = await canvas.boundingBox();
    expect(box).not.toBeNull();
    if (!box) return;

    // The map fits the whole world into the canvas, so these fractional offsets
    // land on large landmasses. Hovering a country only produces a popup when
    // the worker has parsed the GeoJSON source and the fill layer is rendered —
    // with a broken worker the map is all ocean and every hover is a miss.
    const targets: [number, number][] = [
      [0.55, 0.62], // Africa
      [0.72, 0.35], // Asia
      [0.20, 0.30], // North America
      [0.50, 0.30], // Europe / North Africa
    ];

    let popupText: string | null = null;
    for (const [fx, fy] of targets) {
      await page.mouse.move(box.x + box.width * fx, box.y + box.height * fy);
      const popup = page.locator('.wm-popup');
      try {
        await expect(popup).toBeVisible({ timeout: 5_000 });
        popupText = await popup.innerText();
        break;
      } catch {
        // Miss (ocean, or map still settling) — try the next landmass.
      }
    }

    expect(
      popupText,
      'no country popup appeared on hover — the map rendered no country geometry',
    ).not.toBeNull();
    expect(popupText).toContain('Requests');
  });
});
