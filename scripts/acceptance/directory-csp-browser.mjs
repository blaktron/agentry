// Real browser on the private pinned-directory fixture; not an operator account.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
import { randomBytes } from 'node:crypto';

const origin = process.env.DIRECTORY_CSP_ORIGIN;
const credentials = [process.env.CSP_PASSWORD].filter(Boolean);
const browser = await chromium.launch({headless: true});
const challenges = [];
const policyFailures = [];
// Certificate verification is relaxed only for this throwaway fixture's cert.
const context = async () => {
    const ctx = await browser.newContext({ignoreHTTPSErrors: true});
    ctx.on('page', page => page.on('response', async response => {
        if (!new URL(response.url()).pathname.startsWith('/api/v3/flows/executor/')) return;
        const challenge = await response.json().catch(() => ({}));
        // Report the stage and error field names, never submitted values.
        challenges.push({method: response.request().method(), status: response.status(), component: challenge.component,
            errors: Object.keys(challenge.response_errors ?? {})});
    }));
    return ctx;
};

async function enrollmentTerms() {
    const enrollment = await context();
    const page = await enrollment.newPage();
    let widgetLoaded = false;
    let blobFrames = 0;
    page.on('response', response => {
        const url = new URL(response.url());
        if (url.origin === 'https://challenges.cloudflare.com' && url.pathname.startsWith('/turnstile/v0/') && url.pathname.endsWith('/api.js') && response.ok()) widgetLoaded = true;
    });
    page.on('framenavigated', frame => { if (frame.url().startsWith('blob:' + origin + '/')) blobFrames++; });
    page.on('console', message => {
        if (message.type() === 'error' && /Content Security Policy/i.test(message.text())) {
            // Classify refusals without printing URLs, tokens or whole HTML.
            policyFailures.push({inline: /inline script/i.test(message.text()), frame: /frame-src/i.test(message.text()), handler: /event handler/i.test(message.text())});
        }
    });
    const response = await page.goto(origin + '/if/flow/agentry-enrollment/');
    assert.match(response.headers()['content-security-policy'], /script-src-attr 'none'/);
    // Real published-key widget and ordinary browser form, no API/token advance.
    await page.locator('ak-stage-prompt input[name="username"]').waitFor({timeout: 90000});
    assert.ok(widgetLoaded, 'the actual Turnstile frontend did not load');
    assert.equal(blobFrames, 0, 'interactive Turnstile still relies on a blob document');
    assert.deepEqual(policyFailures, [], 'interactive Turnstile encountered a CSP refusal');
    const user = 'dc-' + randomBytes(4).toString('hex');
    const password = 'Correct-Horse-' + randomBytes(8).toString('hex');
    credentials.push(password);
    await page.locator('input[name="username"]').fill(user);
    await page.locator('input[name="email"]').fill(user + '@example.test');
    await page.locator('input[name="password"]').fill(password);
    await page.locator('input[name="password_repeat"]').fill(password);
    await page.locator('button[name="continue"]').click();
    const agree = page.getByRole('checkbox', {name: 'I have read and agree to the Terms of Service', exact: true});
    await agree.waitFor({timeout: 15000});
    console.log('ok   real Turnstile test widget completes in the browser under strict CSP without a blob wrapper');
    return {enrollment, page, agree};
}

async function signIn(page, user, next = '') {
    await page.goto(origin + '/if/flow/default-authentication-flow/' + (next ? '?next=' + encodeURIComponent(next) : ''));
    await page.getByLabel('Email or Username', {exact: true}).fill(user);
    await page.locator('ak-stage-identification').getByRole('button', {name: 'Log in', exact: true}).click();
    // Identification also has a password-manager prefill input. Wait for
    // the password stage rather than filling that preceding stage's input.
    const password = page.locator('ak-stage-password').locator('input[name="password"]');
    await password.waitFor({timeout: 15000});
    await password.fill(process.env.CSP_PASSWORD);
    await page.locator('ak-stage-password').getByRole('button', {name: 'Continue', exact: true}).click();
}

async function widgetLifecycle() {
    const ctx = await context();
    const page = await ctx.newPage();
    let requests = 0;
    const frames = [];
    let release;
    const held = new Promise(resolve => { release = resolve; });
    // Delay only vendor frame documents, before a test token can be issued.
    // This lets the pinned public retry interface drive a real SDK reset.
    await page.route('https://challenges.cloudflare.com/cdn-cgi/challenge-platform/**', async route => {
        if (route.request().resourceType() === 'document') { requests++; await held; }
        // Reset cancels the first navigation while its response is held.
        await route.continue().catch(() => {});
    });
    page.on('response', response => {
        const url = new URL(response.url());
        if (url.origin === 'https://challenges.cloudflare.com' && url.pathname.startsWith('/cdn-cgi/challenge-platform/') && response.request().resourceType() === 'document') {
            frames.push({dark: url.pathname.includes('/dark/'), language: url.searchParams.get('lang')});
        }
    });
    try {
        await page.goto(origin + '/if/flow/agentry-enrollment/?theme=dark&locale=de', {waitUntil: 'domcontentloaded'});
        const container = page.locator('[data-agentry-turnstile="direct"]');
        await container.waitFor({state: 'attached', timeout: 30000});
        const waitFrames = async wanted => {
            const deadline = Date.now() + 15000;
            while (requests < wanted) {
                assert.ok(Date.now() < deadline, 'the real widget did not create its initial/reset frame');
                await page.waitForTimeout(100);
            }
        };
        await waitFrames(1);
        assert.equal(await container.evaluate(el => Boolean(el.closest('form'))), true, 'widget left the normal flow card');
        assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'dark');
        // This is the pinned stage's public retry signal, not a fabricated
        // controller or a token injected to advance the flow.
        await page.locator('ak-stage-captcha').evaluate(stage => { stage.refreshedAt = new Date(); });
        await waitFrames(2);
        release();
        await page.locator('ak-stage-prompt input[name="username"]').waitFor({timeout: 90000});
        assert.ok(frames.some(frame => frame.dark && frame.language === 'de-de'), 'the vendor did not receive the selected theme/language');
        assert.equal(await container.count(), 0, 'the finished stage retained its widget');
        console.log('ok   real widget reset, selected dark theme/language, normal-card placement and teardown work');
    } finally { release(); await ctx.close(); }
}

try {
    const initial = await context();
    const page = await initial.newPage();
    const violations = [];
    page.on('console', msg => {
        if (msg.type() === 'error' && /Content Security Policy/i.test(msg.text())) violations.push(msg.text());
    });
    const response = await page.goto(origin + '/if/flow/default-authentication-flow/');
    const csp = response.headers()['content-security-policy'];
    assert.match(csp, /script-src-attr 'none'/);
    assert.ok(!csp.split(';').find(d => d.trim().startsWith('script-src ')).includes('unsafe-inline'));
    await page.getByLabel('Email or Username', {exact: true}).waitFor({timeout: 15000});
    await page.locator('#agentry-injected-click').click();
    const state = await page.evaluate(() => ({
        script: window.agentryInjectedScript,
        handler: window.agentryInjectedHandler,
        click: window.agentryInjectedClick,
        bootstrap: typeof window.authentik?.api?.base === 'string',
    }));
    assert.equal(state.script, undefined);
    assert.equal(state.handler, undefined);
    assert.equal(state.click, undefined);
    assert.equal(state.bootstrap, true);
    assert.ok(violations.length >= 2, 'the browser did not report the denied fixture injections');
    console.log('ok   directory bootstrap works; arbitrary inline script and event handlers are refused');
    await initial.close();

    if (process.argv[2] === 'on') {
        await widgetLifecycle();
        const {enrollment, page: terms, agree} = await enrollmentTerms();
        const region = terms.getByRole('region', {name: 'Terms of Service', exact: true});
        const waitDisabled = async (wanted) => {
            const deadline = Date.now() + 5000;
            while (await agree.isDisabled() !== wanted) {
                assert.ok(Date.now() < deadline, `terms agreement did not become ${wanted ? 'disabled' : 'enabled'}`);
                await terms.waitForTimeout(100);
            }
        };
        await waitDisabled(true);
        assert.equal(await agree.isChecked(), false);
        await region.press('PageDown');
        assert.equal(await agree.isDisabled(), true, 'reading only part of the terms enabled agreement');
        await region.press('End');
        await waitDisabled(false);
        assert.equal(await agree.evaluate(el => el.checkValidity()), false, 'an unticked agreement is not required');
        await region.press('Home');
        assert.equal(await agree.isDisabled(), false, 'reading the terms was forgotten after scrolling back');
        await agree.check();
        assert.equal(await agree.evaluate(el => el.checkValidity()), true);
        await terms.locator('button[name="continue"]').click();
        await terms.locator('input[name="agentry_authenticator_choice"]').first().waitFor({timeout: 15000});
        console.log('ok   strict-CSP terms scroll courtesy, required agreement and continuation work');
        await enrollment.close();

        const remembered = await context();
        const code = await remembered.newPage();
        await signIn(code, 'dc-mfa');
        await code.locator('ak-stage-authenticator-validate-code').locator('input[name="code"]').waitFor({timeout: 15000});
        const remember = code.getByRole('checkbox', {name: 'Remember this device for 30 days', exact: true});
        await remember.waitFor({timeout: 15000});
        assert.equal(await remember.isChecked(), false);
        assert.ok(!(await remembered.cookies(origin)).some(c => c.name === '__Host-agentry_remember_intent'));
        await remember.check();
        let intent = (await remembered.cookies(origin)).find(c => c.name === '__Host-agentry_remember_intent');
        assert.ok(intent, 'a ticked remembered-browser choice did not write the intent');
        assert.equal(intent.value, '1');
        assert.equal(intent.secure, true);
        assert.equal(intent.sameSite, 'Lax');
        assert.equal(intent.path, '/');
        assert.ok(intent.expires <= Date.now() / 1000 + 601);
        await remember.uncheck();
        assert.ok(!(await remembered.cookies(origin)).some(c => c.name === '__Host-agentry_remember_intent'));
        console.log('ok   strict-CSP remembered-browser choice is unticked, host-bound, short-lived and cleared');
        await remembered.close();

        const names = await context();
        const admin = await names.newPage();
        await signIn(admin, 'dc-admin', '/if/admin/');
        await admin.waitForURL('**/if/admin/**', {timeout: 15000});
        await admin.goto(origin + '/if/admin/#/identity/users');
        const name = '<img src=x onerror=window.agentryNameExecuted=true>';
        await admin.getByRole('row').filter({hasText: name}).first().waitFor({timeout: 15000});
        assert.equal(await admin.locator('img[src="x"]').count(), 0);
        assert.equal(await admin.evaluate(() => window.agentryNameExecuted), undefined);
        console.log('ok   the authenticated directory user list renders an HTML-shaped name as text');
        await names.close();

        const recovery = await context();
        const recoveryPage = await recovery.newPage();
        await recoveryPage.goto(origin + '/if/flow/agentry-recovery/');
        await recoveryPage.locator('input[name="uidField"]').waitFor({timeout: 15000});
        console.log('ok   the recovery identification page loads under strict CSP');
        await recovery.close();
    } else if (process.argv[2] === 'missing') {
        const {enrollment, page: terms, agree} = await enrollmentTerms();
        await terms.getByText('The Terms of Service could not be loaded, so an account cannot be created right now. Please try again later.', {exact: true}).waitFor({timeout: 15000});
        await agree.check();
        const answer = terms.waitForResponse(r => r.url().includes('/api/v3/flows/executor/agentry-enrollment/') && r.request().method() === 'POST');
        await terms.locator('button[name="continue"]').click();
        const denied = await (await answer).json();
        assert.equal(denied.component, 'ak-stage-prompt');
        assert.match(JSON.stringify(denied.response_errors), /Terms of Service could not be loaded/);
        console.log('ok   strict-CSP browser shows unavailable terms and refuses a ticked submission');
        await enrollment.close();
    }
} catch (error) {
    const pages = [];
    for (const ctx of browser.contexts()) {
        for (const page of ctx.pages()) {
            const controls = await page.evaluate(() => {
                const result = {stages: [], inputs: [], buttons: []};
                const walk = root => {
                    for (const el of root.querySelectorAll('*')) {
                        if (el.localName.startsWith('ak-stage-')) result.stages.push(el.localName);
                        if (el.localName === 'input') result.inputs.push({name: el.name, type: el.type});
                        if (el.localName === 'button') result.buttons.push(el.textContent.trim());
                        if (el.shadowRoot) walk(el.shadowRoot);
                    }
                };
                walk(document);
                return result;
            }).catch(() => ({}));
            pages.push({path: new URL(page.url()).pathname, ...controls});
        }
    }
    // Fixture credentials do not belong in failure logs either.
    for (const ctx of browser.contexts()) {
        for (const cookie of await ctx.cookies().catch(() => [])) {
            if (cookie.value.length >= 16) credentials.push(cookie.value);
        }
    }
    let message = (error.stack ?? String(error)) + '\n' + JSON.stringify({challenges, pages, policyFailures});
    for (const credential of credentials) message = message.split(credential).join('[fixture credential]');
    console.error(message);
    process.exitCode = 1;
} finally {
    await browser.close();
}
