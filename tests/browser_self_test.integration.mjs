import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tempRoot = await mkdtemp(path.join(os.tmpdir(), 'sentryiq-browser-self-test-'));
const dataDir = path.join(tempRoot, 'private-data');
const sessionDir = path.join(tempRoot, 'sessions');
const sessionId = [...crypto.getRandomValues(new Uint8Array(16))].map(v => v.toString(16).padStart(2, '0')).join('');
const routerPath = path.join(tempRoot, 'router.php');
let server;
let browser;

async function freePort() {
  return await new Promise((resolve, reject) => {
    const socket = net.createServer();
    socket.once('error', reject);
    socket.listen(0, '127.0.0.1', () => {
      const port = socket.address().port;
      socket.close(() => resolve(port));
    });
  });
}

const routes = {
  '/gallery_settings.php': 'app/Gallery/Settings.php',
  '/passkey_auth.php': 'app/Auth/PasskeyAuth.php',
  '/passkey_login.php': 'app/Auth/PasskeyLogin.php',
  '/passkey_setup.php': 'app/Auth/PasskeySetup.php',
  '/passkeys.php': 'app/Auth/Passkeys.php',
  '/document_delete.php': 'app/Documents/Delete.php',
  '/document_download.php': 'app/Documents/Download.php',
  '/document_upload.php': 'app/Documents/Upload.php',
  '/gallery_album.php': 'app/Gallery/AlbumActions.php',
  '/gallery_bulk_delete.php': 'app/Gallery/BulkDelete.php',
  '/gallery_delete.php': 'app/Gallery/Delete.php',
  '/gallery_image.php': 'app/Gallery/Image.php',
  '/gallery_upload.php': 'app/Gallery/Upload.php',
  '/record_actions.php': 'app/Vault/RecordActions.php',
  '/records_category_actions.php': 'app/Vault/RecordsCategoryActions.php',
  '/records_view_data.php': 'app/Vault/RecordsViewData.php',
  '/security-features.php': 'app/Security/SecurityFeatures.php',
  '/security_log.php': 'app/Security/SecurityLog.php',
  '/system_log.php': 'app/Security/SystemLog.php',
  '/vault_actions.php': 'app/Vault/Actions.php',
  '/vault_category_actions.php': 'app/Vault/CategoryActions.php',
  '/vault_folder_data.php': 'app/Vault/FolderData.php',
};

try {
  const fixture = spawnSync('php', [path.join(root, 'tests/browser_self_test_fixture.php')], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      SENTRYIQ_TEST_DATA_DIR: dataDir,
      SENTRYIQ_TEST_SESSION_DIR: sessionDir,
      SENTRYIQ_TEST_SESSION_ID: sessionId,
    },
  });
  if (fixture.status !== 0) {
    throw new Error('Browser fixture setup failed: ' + fixture.stderr + fixture.stdout);
  }

  const routeEntries = Object.entries(routes)
    .map(([route, target]) => JSON.stringify(route) + ' => ' + JSON.stringify(target))
    .join(',\n');
  const router = `<?php
$root = ${JSON.stringify(root)};
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
if ($path === '/') $path = '/index.php';
$routes = [
${routeEntries}
];
$relative = $routes[$path] ?? ltrim(rawurldecode($path), '/');
$target = $root . '/' . $relative;
if (!is_file($target) || !str_ends_with(strtolower($target), '.php')) {
    if (is_file($target)) return false;
    http_response_code(404);
    echo 'Not found';
    return true;
}
$_SERVER['HTTPS'] = 'on';
$_SERVER['SERVER_PORT'] = '443';
$_SERVER['HTTP_HOST'] = 'localhost';
$_SERVER['SERVER_NAME'] = 'localhost';
$_SERVER['DOCUMENT_ROOT'] = $root;
$_SERVER['SCRIPT_NAME'] = $path;
$_SERVER['SCRIPT_FILENAME'] = $target;
require $target;
return true;
`;
  await writeFile(routerPath, router, { mode: 0o600 });
  const port = await freePort();
  server = spawn('php', [
    '-d', 'session.save_path=' + sessionDir,
    '-S', '127.0.0.1:' + port,
    '-t', root,
    routerPath,
  ], { cwd: root, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });

  let serverOutput = '';
  server.stdout.on('data', chunk => { serverOutput += chunk.toString(); });
  server.stderr.on('data', chunk => { serverOutput += chunk.toString(); });
  const baseUrl = 'http://127.0.0.1:' + port;
  let ready = false;
  for (let attempt = 0; attempt < 80; attempt++) {
    try {
      const response = await fetch(baseUrl + '/assets/css/sentryiq.css');
      if (response.ok) { ready = true; break; }
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert(ready, 'Isolated PHP application server did not become ready. ' + serverOutput);

  browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME_BIN || undefined, args: ['--no-sandbox'] });
  const context = await browser.newContext();
  await context.addCookies([{
    name: 'PHPSESSID',
    value: sessionId,
    url: baseUrl,
    secure: true,
    httpOnly: true,
    sameSite: 'Strict',
  }]);
  const page = await context.newPage();
  const pageErrors = [];
  page.on('pageerror', error => pageErrors.push(error.message));
  await page.goto(baseUrl + '/diagnostics/self_test.php', { waitUntil: 'domcontentloaded' });
  await page.locator('#run').waitFor();
  assert.match(await page.locator('h1').innerText(), /SentryIQ Self-Test/);

  const serverReport = await page.locator('#sentryiq-self-test-data').textContent();
  const parsedServerReport = JSON.parse(serverReport);
  const failedServerChecks = parsedServerReport.serverChecks.filter(check => check.ok !== true);
  assert.deepEqual(failedServerChecks, [], 'Installed fixture has failing server diagnostics: ' + JSON.stringify(failedServerChecks));

  await page.locator('#run').click();
  await page.waitForFunction(() => {
    const text = document.querySelector('#report')?.textContent || '';
    try {
      const report = JSON.parse(text);
      return Array.isArray(report.browserChecks) && report.browserChecks.length === JSON.parse(document.querySelector('#sentryiq-self-test-data').textContent).tests.length;
    } catch { return false; }
  }, { timeout: 30000 });

  const report = JSON.parse(await page.locator('#report').textContent());
  const failedBrowserChecks = report.browserChecks.filter(check => check.ok === false);
  assert.deepEqual(
    failedBrowserChecks.map(check => ({ label: check.label, url: check.url, status: check.status, contentType: check.contentType, finalUrl: check.finalUrl, checks: check.checks, stylesheetDetail: check.stylesheetDetail, htmlReferenceResults: check.htmlReferenceResults })),
    [],
    'Real browser URL/DOM/CSS checks failed.'
  );
  const tested = report.browserChecks.filter(check => check.type !== 'not-tested');
  assert(tested.length > 0, 'No browser checks were executed.');
  assert(tested.every(check => check.ok === true), 'At least one tested browser route did not pass.');
  assert.equal(report.browserChecks.filter(check => check.type === 'not-tested').length, 12, 'Expected POST-only and ID-dependent endpoints to remain explicitly NOT TESTED.');
  assert.deepEqual(pageErrors, [], 'Browser JavaScript errors occurred: ' + pageErrors.join('; '));

  console.log('Installed authenticated browser self-test passed: ' + tested.length + ' browser checks; ' + report.browserChecks.filter(check => check.type === 'not-tested').length + ' unsafe/non-GET routes correctly marked NOT TESTED.');
  console.log('Server-side checks passed: ' + report.serverChecks.length + '.');
} finally {
  if (browser) await browser.close();
  if (server) {
    server.kill('SIGTERM');
    await new Promise(resolve => server.once('exit', resolve));
  }
  await rm(path.join(root, 'sentryiq_config.php'), { force: true });
  await rm(tempRoot, { recursive: true, force: true });
}
