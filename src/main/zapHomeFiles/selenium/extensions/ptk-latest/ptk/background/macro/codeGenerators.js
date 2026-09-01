/* Author: Denis Podgurskii */

import { normalizeFlow, selectFlowLocator } from './flow.js'

const JS_UNSAFE_CHAR_MAP = {
    '<': '\\u003C',
    '>': '\\u003E',
    '\u2028': '\\u2028',
    '\u2029': '\\u2029'
}

const JS_UNSAFE_CHARS_RE = /[<>\u2028\u2029]/g

function js(value) {
    return JSON.stringify(String(value ?? '')).replace(
        JS_UNSAFE_CHARS_RE,
        (character) => JS_UNSAFE_CHAR_MAP[character]
    )
}

function dataExpression(data, envPrefix = 'PTK_SECRET_') {
    if (!data) return "''"
    if (data.kind === 'literal') return js(data.value)
    const prefix = data.kind === 'secret' ? envPrefix : 'PTK_VAR_'
    return `process.env.${prefix}${data.name}`
}

function cypressData(data) {
    if (!data) return { expression: "''", command: null }
    if (data.kind === 'literal') return { expression: js(data.value), command: null }
    const name = `${data.kind === 'secret' ? 'PTK_SECRET_' : 'PTK_VAR_'}${data.name}`
    return { expression: 'value', command: `cy.then(() => Cypress.env(${js(name)})).then((value) => { ` }
}

function diagnostic(diagnostics, step, code, message) {
    diagnostics.push({
        level: step.enabled ? 'error' : 'info',
        code,
        message,
        stepId: step.id,
        stepType: step.type,
        impact: 'omitted'
    })
}

function sourceComment(comment, indent = '') {
    const lines = String(comment || '').split(/\r?\n/)
    return lines.map((line) => `${indent}// ${line.replace(/[\u2028\u2029]/g, ' ')}`)
}

function handleNonExecutableStep(step, diagnostics, lines, indent = '') {
    if (!step.enabled) {
        diagnostic(diagnostics, step, 'disabled_step_omitted', `Disabled ${step.type} step was intentionally omitted.`)
        return true
    }
    if (step.type === 'comment') {
        lines.push(...sourceComment(step.comment, indent))
        return true
    }
    return false
}

function preferredLocator(step, options = {}) {
    return selectFlowLocator(step, options.element_path || options.elementPath || 'css')
}

function keyName(data) {
    if (!data || data.kind !== 'literal') return null
    const raw = String(data.value || '')
    const token = raw.match(/^\$\{KEY_([^}]+)\}$/)?.[1] || raw.match(/^KEY_(.+)$/)?.[1]
    if (!token) return raw
    return ({
        ENTER: 'Enter', TAB: 'Tab', ESC: 'Escape', ESCAPE: 'Escape',
        BACKSPACE: 'Backspace', DELETE: 'Delete', ARROW_LEFT: 'ArrowLeft',
        ARROW_RIGHT: 'ArrowRight', ARROW_UP: 'ArrowUp', ARROW_DOWN: 'ArrowDown'
    })[token.toUpperCase()] || token
}

function browserKeyExpression(data) {
    const name = keyName(data)
    return name === null ? dataExpression(data) : js(name)
}

function seleniumKeyExpression(data) {
    const name = keyName(data)
    const key = ({
        Enter: 'ENTER', Tab: 'TAB', Escape: 'ESCAPE', Backspace: 'BACK_SPACE',
        Delete: 'DELETE', ArrowLeft: 'ARROW_LEFT', ArrowRight: 'ARROW_RIGHT',
        ArrowUp: 'ARROW_UP', ArrowDown: 'ARROW_DOWN'
    })[name]
    return key ? `Key.${key}` : dataExpression(data)
}

function cypressKeyData(data) {
    const name = keyName(data)
    const key = ({
        Enter: '{enter}', Tab: '{tab}', Escape: '{esc}', Backspace: '{backspace}',
        Delete: '{del}', ArrowLeft: '{leftarrow}', ArrowRight: '{rightarrow}',
        ArrowUp: '{uparrow}', ArrowDown: '{downarrow}'
    })[name]
    return key ? { expression: js(key), command: null } : cypressData(data)
}

function playwrightLocator(step, diagnostics, options = {}) {
    const locator = preferredLocator(step, options)
    if (!locator) {
        diagnostic(diagnostics, step, 'playwright_locator_missing', 'Playwright export requires an element locator.')
        return null
    }
    const targetSelector = locator.type === 'xpath'
        ? `xpath=${locator.value}`
        : locator.type === 'id'
            ? `#${locator.value}`
            : locator.type === 'name'
                ? `[name="${locator.value}"]`
                : locator.value
    let owner = 'page'
    for (const frame of step.frameChain) {
        const frameLocator = frame.locators[0]
        if (!frameLocator) continue
        const selector = frameLocator.type === 'xpath'
            ? `xpath=${frameLocator.value}`
            : frameLocator.type === 'id'
                ? `#${frameLocator.value}`
                : frameLocator.value
        owner += `.frameLocator(${js(selector)})`
    }
    return `${owner}.locator(${js(targetSelector)})`
}

function generatePlaywright(flow, options = {}) {
    const diagnostics = []
    const lines = [
        "import { chromium } from 'playwright'",
        '',
        'const browser = await chromium.launch({ headless: true })',
        'const page = await browser.newPage()',
        ''
    ]
    for (const step of flow.steps) {
        if (handleNonExecutableStep(step, diagnostics, lines)) continue
        const locator = step.locators.length ? playwrightLocator(step, diagnostics, options) : null
        if (step.type === 'navigate') lines.push(`await page.goto(${js(step.url)})`)
        else if (step.type === 'click' && locator) lines.push(`await ${locator}.click()`)
        else if (step.type === 'doubleClick' && locator) lines.push(`await ${locator}.dblclick()`)
        else if (step.type === 'fill' && locator) lines.push(`await ${locator}.fill(${dataExpression(step.data)})`)
        else if (step.type === 'select' && locator) lines.push(`await ${locator}.selectOption(${dataExpression(step.data)})`)
        else if (step.type === 'submit' && locator) lines.push(`await ${locator}.evaluate((element) => { const form = element instanceof HTMLFormElement ? element : element.closest('form'); if (!form) throw new Error('PTK submit target has no form'); form.requestSubmit ? form.requestSubmit() : form.submit() })`)
        else if (step.type === 'keyPress' && locator) lines.push(`await ${locator}.press(${browserKeyExpression(step.data)})`)
        else if (step.type === 'hover' && locator) lines.push(`await ${locator}.hover()`)
        else if (step.type === 'scroll' && step.scrollMode === 'intoView' && locator) lines.push(`await ${locator}.scrollIntoViewIfNeeded()`)
        else if (step.type === 'scroll' && step.scrollMode === 'to' && locator) lines.push(`await ${locator}.evaluate((element, { x, y }) => element.scrollTo(x, y), { x: ${step.x || 0}, y: ${step.y || 0} })`)
        else if (step.type === 'scroll' && step.scrollMode === 'by' && locator) lines.push(`await ${locator}.evaluate((element, { x, y }) => element.scrollBy(x, y), { x: ${step.x || 0}, y: ${step.y || 0} })`)
        else if (step.type === 'scroll' && step.scrollMode === 'to') lines.push(`await page.evaluate(({ x, y }) => window.scrollTo(x, y), { x: ${step.x || 0}, y: ${step.y || 0} })`)
        else if (step.type === 'waitForElement' && locator) lines.push(`await ${locator}.waitFor({ state: 'visible', timeout: ${step.timeoutMs || 30000} })`)
        else if (step.type === 'waitForNavigation') lines.push(`await page.waitForURL(${js(step.url)}, { timeout: ${step.timeoutMs || 30000} })`)
        else if (step.type === 'delay') lines.push(`await page.waitForTimeout(${step.durationMs})`)
        else if (step.type === 'setWindowSize') lines.push(`await page.setViewportSize({ width: ${step.width}, height: ${step.height} })`)
        else if (step.type === 'assertText' && locator) lines.push(`if (!(await ${locator}.textContent())?.includes(${js(step.expected)})) throw new Error('PTK assertText failed')`)
        else if (step.type === 'assertUrl') lines.push(`if (page.url() !== ${js(step.expected)}) throw new Error('PTK assertUrl failed')`)
        else if (step.type === 'assertElement' && locator) lines.push(`await ${locator}.waitFor({ state: 'attached' })`)
        else diagnostic(diagnostics, step, 'playwright_step_unsupported', `Playwright export does not support ${step.type}.`)
    }
    lines.push('', 'await browser.close()', '')
    return { text: lines.join('\n'), diagnostics }
}

function puppeteerSelector(locator) {
    if (locator.type === 'xpath') return `::-p-xpath(${locator.value})`
    if (locator.type === 'aria' || locator.type === 'linkText') return `::-p-aria(${locator.value})`
    if (locator.type === 'text') return `::-p-text(${locator.value})`
    if (locator.type === 'pierce') return locator.value
    if (locator.type === 'id') return `#${locator.value}`
    if (locator.type === 'name') return `[name="${locator.value}"]`
    if (locator.type === 'className') return `.${locator.value.trim().split(/\s+/).join('.')}`
    return locator.value
}

function generatePuppeteer(flow, options = {}) {
    const diagnostics = []
    const lines = [
        "import puppeteer from 'puppeteer'",
        '',
        'const browser = await puppeteer.launch({ headless: true })',
        'const page = await browser.newPage()',
        ''
    ]
    for (const step of flow.steps) {
        if (handleNonExecutableStep(step, diagnostics, lines)) continue
        if (step.frameChain.length) {
            diagnostic(diagnostics, step, 'puppeteer_frame_unsupported', 'Puppeteer export requires a reviewed frame-chain mapping.')
            continue
        }
        const selected = preferredLocator(step, options)
        const selector = selected ? puppeteerSelector(selected) : null
        const locator = selector ? `page.locator(${js(selector)})` : null
        if (step.type === 'navigate') lines.push(`await page.goto(${js(step.url)})`)
        else if (step.type === 'click' && locator) lines.push(`await ${locator}.click()`)
        else if (step.type === 'doubleClick' && locator) lines.push(`await ${locator}.click({ count: 2 })`)
        else if (step.type === 'fill' && locator) lines.push(`await ${locator}.fill(${dataExpression(step.data)})`)
        else if (step.type === 'select' && locator) lines.push(`await ${locator}.fill(${dataExpression(step.data)})`)
        else if (step.type === 'submit' && selector) lines.push(`await page.$eval(${js(selector)}, (element) => { const form = element instanceof HTMLFormElement ? element : element.closest('form'); if (!form) throw new Error('PTK submit target has no form'); form.requestSubmit ? form.requestSubmit() : form.submit() })`)
        else if (step.type === 'keyPress' && selector) lines.push(`await page.focus(${js(selector)}); await page.keyboard.press(${browserKeyExpression(step.data)})`)
        else if (step.type === 'hover' && locator) lines.push(`await ${locator}.hover()`)
        else if (step.type === 'scroll' && step.scrollMode === 'intoView' && selector) lines.push(`await page.$eval(${js(selector)}, (element) => element.scrollIntoView({ block: 'nearest', inline: 'nearest' }))`)
        else if (step.type === 'scroll' && step.scrollMode === 'to' && selector) lines.push(`await page.$eval(${js(selector)}, (element, { x, y }) => element.scrollTo(x, y), { x: ${step.x || 0}, y: ${step.y || 0} })`)
        else if (step.type === 'scroll' && step.scrollMode === 'by' && selector) lines.push(`await page.$eval(${js(selector)}, (element, { x, y }) => element.scrollBy(x, y), { x: ${step.x || 0}, y: ${step.y || 0} })`)
        else if (step.type === 'scroll' && step.scrollMode === 'to') lines.push(`await page.evaluate(({ x, y }) => window.scrollTo(x, y), { x: ${step.x || 0}, y: ${step.y || 0} })`)
        else if (step.type === 'waitForElement' && selector) lines.push(`await page.waitForSelector(${js(selector)}, { visible: true, timeout: ${step.timeoutMs || 30000} })`)
        else if (step.type === 'waitForNavigation') lines.push(`await page.waitForFunction((url) => location.href === url, { timeout: ${step.timeoutMs || 30000} }, ${js(step.url)})`)
        else if (step.type === 'delay') lines.push(`await new Promise((resolve) => setTimeout(resolve, ${step.durationMs}))`)
        else if (step.type === 'setWindowSize') lines.push(`await page.setViewport({ width: ${step.width}, height: ${step.height} })`)
        else if (step.type === 'assertText' && selector) lines.push(`if (!(await page.$eval(${js(selector)}, (element) => element.textContent || '')).includes(${js(step.expected)})) throw new Error('PTK assertText failed')`)
        else if (step.type === 'assertUrl') lines.push(`if (page.url() !== ${js(step.expected)}) throw new Error('PTK assertUrl failed')`)
        else if (step.type === 'assertElement' && selector) lines.push(`await page.waitForSelector(${js(selector)}, { timeout: ${step.timeoutMs || 30000} })`)
        else diagnostic(diagnostics, step, 'puppeteer_step_unsupported', `Puppeteer export does not support ${step.type}.`)
    }
    lines.push('', 'await browser.close()', '')
    return { text: lines.join('\n'), diagnostics }
}

function seleniumBy(locator) {
    if (!locator) return null
    const method = ({ css: 'css', xpath: 'xpath', id: 'id', name: 'name', className: 'className', linkText: 'linkText' })[locator.type]
    return method ? `By.${method}(${js(locator.value)})` : null
}

function generateSelenium(flow, options = {}) {
    const diagnostics = []
    const lines = [
        "import { Builder, By, Key, until } from 'selenium-webdriver'",
        '',
        "const driver = await new Builder().forBrowser('chrome').build()",
        'try {'
    ]
    for (const step of flow.steps) {
        if (handleNonExecutableStep(step, diagnostics, lines, '  ')) continue
        if (step.frameChain.length) {
            diagnostic(diagnostics, step, 'selenium_frame_unsupported', 'Selenium export requires a reviewed frame-chain mapping.')
            continue
        }
        const by = seleniumBy(preferredLocator(step, options))
        const element = by ? `await driver.findElement(${by})` : null
        if (step.type === 'navigate') lines.push(`  await driver.get(${js(step.url)})`)
        else if (step.type === 'click' && element) lines.push(`  await (${element}).click()`)
        else if (step.type === 'doubleClick' && element) lines.push(`  await driver.actions().doubleClick(${element}).perform()`)
        else if (step.type === 'fill' && element) lines.push(`  await (${element}).sendKeys(Key.chord(Key.CONTROL, 'a'), ${dataExpression(step.data)})`)
        else if (step.type === 'select' && element) lines.push(`  await (${element}).sendKeys(${dataExpression(step.data)})`)
        else if (step.type === 'keyPress' && element) lines.push(`  await (${element}).sendKeys(${seleniumKeyExpression(step.data)})`)
        else if (step.type === 'submit' && element) lines.push(`  await (${element}).submit()`)
        else if (step.type === 'hover' && element) lines.push(`  await driver.actions().move({ origin: ${element} }).perform()`)
        else if (step.type === 'scroll' && step.scrollMode === 'intoView' && element) lines.push(`  await driver.executeScript('arguments[0].scrollIntoView({block: "nearest", inline: "nearest"})', ${element})`)
        else if (step.type === 'scroll' && step.scrollMode === 'to' && element) lines.push(`  await driver.executeScript('arguments[0].scrollTo(arguments[1], arguments[2])', ${element}, ${step.x || 0}, ${step.y || 0})`)
        else if (step.type === 'scroll' && step.scrollMode === 'by' && element) lines.push(`  await driver.executeScript('arguments[0].scrollBy(arguments[1], arguments[2])', ${element}, ${step.x || 0}, ${step.y || 0})`)
        else if (step.type === 'scroll' && step.scrollMode === 'to') lines.push(`  await driver.executeScript('window.scrollTo(arguments[0], arguments[1])', ${step.x || 0}, ${step.y || 0})`)
        else if (step.type === 'waitForElement' && by) lines.push(`  await driver.wait(until.elementLocated(${by}), ${step.timeoutMs || 30000})`)
        else if (step.type === 'waitForNavigation') lines.push(`  await driver.wait(until.urlIs(${js(step.url)}), ${step.timeoutMs || 30000})`)
        else if (step.type === 'delay') lines.push(`  await driver.sleep(${step.durationMs})`)
        else if (step.type === 'setWindowSize') lines.push(`  await driver.manage().window().setRect({ width: ${step.width}, height: ${step.height} })`)
        else if (step.type === 'assertText' && element) lines.push(`  if (!(await (${element}).getText()).includes(${js(step.expected)})) throw new Error('PTK assertText failed')`)
        else if (step.type === 'assertUrl') lines.push(`  if ((await driver.getCurrentUrl()) !== ${js(step.expected)}) throw new Error('PTK assertUrl failed')`)
        else if (step.type === 'assertElement' && by) lines.push(`  await driver.wait(until.elementLocated(${by}), ${step.timeoutMs || 30000})`)
        else diagnostic(diagnostics, step, 'selenium_step_unsupported', `Selenium WebDriver export does not support ${step.type}.`)
    }
    lines.push('} finally {', '  await driver.quit()', '}', '')
    return { text: lines.join('\n'), diagnostics }
}

function cypressSelector(locator) {
    if (!locator) return null
    if (locator.type === 'css') return locator.value
    if (locator.type === 'id') return `#${locator.value}`
    if (locator.type === 'name') return `[name="${locator.value}"]`
    if (locator.type === 'className') return `.${locator.value.trim().split(/\s+/).join('.')}`
    return null
}

function generateCypress(flow, options = {}) {
    const diagnostics = []
    const lines = ["describe('PTK Flow', () => {", "  it('replays the recorded workflow', () => {"]
    for (const step of flow.steps) {
        if (handleNonExecutableStep(step, diagnostics, lines, '    ')) continue
        if (step.frameChain.length) {
            diagnostic(diagnostics, step, 'cypress_frame_unsupported', 'Cypress export requires a reviewed frame-chain mapping.')
            continue
        }
        const selected = preferredLocator(step, options)
        const selector = cypressSelector(selected)
        const element = selector ? `cy.get(${js(selector)})` : null
        const input = cypressData(step.data)
        const action = (body) => input.command ? `${input.command}${body} })` : body
        if (step.locators.length && !selector) {
            diagnostic(diagnostics, step, 'cypress_locator_unsupported', `Cypress export cannot represent the ${selected.type} locator without a plugin.`)
            continue
        }
        if (step.type === 'navigate') lines.push(`    cy.visit(${js(step.url)})`)
        else if (step.type === 'click' && element) lines.push(`    ${element}.click()`)
        else if (step.type === 'doubleClick' && element) lines.push(`    ${element}.dblclick()`)
        else if (step.type === 'fill' && element) lines.push(`    ${action(`${element}.clear().type(${input.expression})`)}`)
        else if (step.type === 'select' && element) lines.push(`    ${action(`${element}.select(${input.expression})`)}`)
        else if (step.type === 'keyPress' && element) {
            const keyInput = cypressKeyData(step.data)
            const keyAction = (body) => keyInput.command ? `${keyInput.command}${body} })` : body
            lines.push(`    ${keyAction(`${element}.type(${keyInput.expression})`)}`)
        }
        else if (step.type === 'submit' && element) lines.push(`    ${element}.submit()`)
        else if (step.type === 'hover' && element) lines.push(`    ${element}.trigger('mouseover')`)
        else if (step.type === 'scroll' && step.scrollMode === 'intoView' && element) lines.push(`    ${element}.scrollIntoView()`)
        else if (step.type === 'scroll' && step.scrollMode === 'to' && element) lines.push(`    ${element}.scrollTo(${step.x || 0}, ${step.y || 0})`)
        else if (step.type === 'scroll' && step.scrollMode === 'by' && element) lines.push(`    ${element}.then(($element) => $element[0].scrollBy(${step.x || 0}, ${step.y || 0}))`)
        else if (step.type === 'scroll' && step.scrollMode === 'to') lines.push(`    cy.scrollTo(${step.x || 0}, ${step.y || 0})`)
        else if (step.type === 'waitForElement' && element) lines.push(`    ${element}.should('be.visible')`)
        else if (step.type === 'waitForNavigation') lines.push(`    cy.url({ timeout: ${step.timeoutMs || 30000} }).should('eq', ${js(step.url)})`)
        else if (step.type === 'delay') lines.push(`    cy.wait(${step.durationMs})`)
        else if (step.type === 'setWindowSize') lines.push(`    cy.viewport(${step.width}, ${step.height})`)
        else if (step.type === 'assertText' && element) lines.push(`    ${element}.should('contain.text', ${js(step.expected)})`)
        else if (step.type === 'assertUrl') lines.push(`    cy.url().should('eq', ${js(step.expected)})`)
        else if (step.type === 'assertElement' && element) lines.push(`    ${element}.should('exist')`)
        else diagnostic(diagnostics, step, 'cypress_step_unsupported', `Cypress export does not support ${step.type}.`)
    }
    lines.push('  })', '})', '')
    return { text: lines.join('\n'), diagnostics }
}

function generator(id, label, extension, generate) {
    return Object.freeze({
        id,
        label,
        extensions: [extension],
        mimeType: 'text/javascript',
        editorMode: 'javascript',
        canImport: false,
        canExport: true,
        readOnly: true,
        generate(flow, options = {}) {
            return generate(normalizeFlow(flow), options)
        }
    })
}

export const codeGenerators = Object.freeze([
    generator('playwright', 'Playwright', '.playwright.mjs', generatePlaywright),
    generator('puppeteer', 'Puppeteer', '.puppeteer.mjs', generatePuppeteer),
    generator('selenium-webdriver', 'Selenium WebDriver', '.selenium.mjs', generateSelenium),
    generator('cypress', 'Cypress', '.cy.js', generateCypress)
])
