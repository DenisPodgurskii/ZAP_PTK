const ext = globalThis.browser ?? globalThis.chrome
const frame = document.getElementById('ptkFrame')
const menuWrapper = document.getElementById('mainMenuWrapper')
const version = ext.runtime.getManifest().version
const POPUP_HISTORY_ROUTES = new Set([
  'dashboard',
  'dast',
  'iast',
  'sast',
  'sca',
  'proxy',
  'rbuilder',
  'session',
  'jwt',
  'decoder',
  'macro',
  'traffic',
  'swagger',
  'portscanner',
  'xss',
  'sql'
])

const RELEASE_NOTE_HTML = `
  <div id="ptk_release_note" class="ptk-shell-release-note" role="status" aria-live="polite">
    <button id="ptk_release_note_close" class="ptk-shell-release-note-close" type="button" aria-label="Close release notes">x</button>
    <h3>Release notes - ${version}</h3>
    <ul>
      <li><strong>ZAP automation reliability:</strong> Hardened browser close handling, target scoping, and multi-browser Edge/Firefox scan coordination.</li>
      <li><strong>AngularJS and XSS checks:</strong> Improved AngularJS template-injection coverage and safer template-marker proof for noisy Angular contexts.</li>
      <li><strong>Accuracy fixes:</strong> Fixed JWT carrier false positives and improved SAST/IAST DOM taint coverage for message, storage, navigation, and form flows.</li>
      <li><strong>Agent workflows:</strong> Added stronger <code>ptk-scan</code> / Agent SDK workflows, scenario runs, matrices, and larger report exports.</li>
    </ul>
    <p>More details on <a href="https://pentestkit.co.uk/release_notes.html" target="_blank" rel="noopener">https://pentestkit.co.uk/release_notes.html</a></p>
  </div>
`

document.addEventListener('DOMContentLoaded', () => {
  if (!frame || !menuWrapper) return

  applyClipboardPermissions()
  renderShell()
  bindShell()

  resolveInitialPage().then((initialPage) => {
    requestAnimationFrame(() => {
      openPage(initialPage, { persistHistory: false })
    })
  }).catch(() => {
    requestAnimationFrame(() => {
      openPage('dashboard.html', { persistHistory: false })
    })
  })

  window.setTimeout(loadReleaseNote, 300)
})

function applyClipboardPermissions() {
  if (typeof navigator.userAgentData !== 'undefined' || !navigator.userAgent.includes('Firefox')) {
    frame.setAttribute('allow', 'clipboard-read; clipboard-write')
  }
}

function renderShell() {
  menuWrapper.innerHTML = `
    <div class="ptk-shell-bar">
      <nav id="mainMenu" class="ptk-shell-nav" aria-label="PTK sections">
        <a class="ptk-shell-brand ptk-shell-route" href="#" data-history="dashboard" data-route-link>
          <img src="assets/images/hacker_w1.png" alt="PTK" style="width: 32px; height: 32px;">
          <span class="ptk-shell-home-icon" aria-hidden="true">
            <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
              <path d="M12 3 4 9.4V21h6v-6h4v6h6V9.4z"></path>
            </svg>
          </span>
        </a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="dast" data-route-link>DAST</a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="iast" data-route-link>IAST</a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="sast" data-route-link>SAST</a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="sca" data-route-link>SCA</a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="proxy" data-route-link>Proxy</a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="rbuilder" data-route-link>R-Builder</a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="session" data-route-link>Cookies</a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="jwt" data-route-link>JWT</a>
        <a class="ptk-shell-link ptk-shell-route" href="#" data-history="decoder" data-route-link>Decoder</a>
      </nav>

      <div class="ptk-shell-actions">
        <div class="ptk-shell-dropdown" data-dropdown>
          <button class="ptk-shell-toggle" type="button" data-dropdown-toggle id="ptk_shell_cheatsheets_toggle">Cheat sheets</button>
          <div class="ptk-shell-dropdown-menu" role="menu">
            <a href="#" data-history="xss" data-route-link data-parent-toggle="ptk_shell_cheatsheets_toggle" role="menuitem">XSS</a>
            <a href="#" data-history="sql" data-route-link data-parent-toggle="ptk_shell_cheatsheets_toggle" role="menuitem">SQL</a>
          </div>
        </div>
        <div class="ptk-shell-dropdown" data-dropdown>
          <button class="ptk-shell-toggle" type="button" data-dropdown-toggle id="ptk_shell_tools_toggle">Tools</button>
          <div class="ptk-shell-dropdown-menu" role="menu">
            <a href="#" data-history="macro" data-route-link data-parent-toggle="ptk_shell_tools_toggle" role="menuitem">Macro</a>
            <a href="#" data-history="traffic" data-route-link data-parent-toggle="ptk_shell_tools_toggle" role="menuitem">Traffic</a>
            <a href="#" data-history="swagger" data-route-link data-parent-toggle="ptk_shell_tools_toggle" role="menuitem">Swagger</a>
          </div>
        </div>
        <div class="ptk-shell-dropdown ptk-shell-dropdown-right" data-dropdown>
          <button class="ptk-shell-icon-toggle" type="button" data-dropdown-toggle aria-label="More">
            <span class="ptk-shell-help-icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
                <path d="M12 2a10 10 0 1 0 10 10A10.011 10.011 0 0 0 12 2Zm0 17a1.25 1.25 0 1 1 1.25-1.25A1.25 1.25 0 0 1 12 19Zm1.47-7.09-.63.44A1.9 1.9 0 0 0 12 14.05v.2h-1.8v-.35a3.01 3.01 0 0 1 1.37-2.67l.87-.6a1.57 1.57 0 0 0 .73-1.28 1.68 1.68 0 0 0-3.35.15H8a3.48 3.48 0 0 1 6.95-.24 3.21 3.21 0 0 1-1.48 2.65Z"></path>
              </svg>
            </span>
          </button>
          <div class="ptk-shell-dropdown-menu" role="menu">
            <button type="button" data-modal-page="settings.html" role="menuitem">Settings</button>
            <hr class="ptk-shell-divider">
            <button type="button" data-action="reloadextension" role="menuitem">Reload PTK</button>
            <hr class="ptk-shell-divider">
            <a href="https://pentestkit.co.uk/howto.html" target="_blank" rel="noopener" role="menuitem">How to</a>
            <a href="https://pentestkit.co.uk/release_notes.html" target="_blank" rel="noopener" role="menuitem">Release notes</a>
            <hr class="ptk-shell-divider">
            <button type="button" data-modal-page="credits.html" role="menuitem">Credits</button>
            <button type="button" data-modal-page="disclaimer.html" role="menuitem">Disclaimer</button>
            <button type="button" data-modal-page="privacy.html" role="menuitem">Privacy Policy</button>
            <button type="button" data-modal-page="contact.html" role="menuitem">Contact Us</button>
            <hr class="ptk-shell-divider">
            <div class="ptk-shell-static">Version: ${version}</div>
          </div>
        </div>
      </div>
    </div>
  `

  document.body.insertAdjacentHTML(
    'beforeend',
    `
      <div id="ptk_shell_modal_backdrop" class="ptk-shell-modal-backdrop"></div>
      <div id="ptk_popup_dialog" class="ptk-shell-modal" aria-hidden="true">
        <div class="ptk-shell-modal-header">
          <button id="ptk_shell_modal_close" class="ptk-shell-modal-close" type="button" aria-label="Close dialog">x</button>
        </div>
        <iframe id="ptk_shell_modal_frame" class="ptk-shell-modal-frame" title="PTK dialog"></iframe>
      </div>
      ${RELEASE_NOTE_HTML}
    `
  )
}

function bindShell() {
  const modal = document.getElementById('ptk_popup_dialog')
  const modalBackdrop = document.getElementById('ptk_shell_modal_backdrop')
  const modalFrame = document.getElementById('ptk_shell_modal_frame')
  const modalClose = document.getElementById('ptk_shell_modal_close')
  const releaseNote = document.getElementById('ptk_release_note')
  const releaseNoteClose = document.getElementById('ptk_release_note_close')

  frame.addEventListener('load', () => {
    setActiveMenuByPage(getFramePageName())
    closeAllDropdowns()
    bindFrameInteractionDismissal()
  })

  frame.addEventListener('pointerdown', closeAllDropdowns)

  document.addEventListener('click', async (event) => {
    const toggle = event.target.closest('[data-dropdown-toggle]')
    if (toggle) {
      event.preventDefault()
      toggleDropdown(toggle.closest('[data-dropdown]'))
      return
    }

    const routeLink = event.target.closest('[data-history]')
    if (routeLink) {
      event.preventDefault()
      closeAllDropdowns()
      await openRouteFromElement(routeLink)
      return
    }

    const modalTrigger = event.target.closest('[data-modal-page]')
    if (modalTrigger) {
      event.preventDefault()
      closeAllDropdowns()
      openModal(modalTrigger.getAttribute('data-modal-page'))
      return
    }

    const actionTrigger = event.target.closest('[data-action]')
    if (actionTrigger) {
      event.preventDefault()
      closeAllDropdowns()
      if (actionTrigger.getAttribute('data-action') === 'reloadextension') {
        ext.runtime.sendMessage({
          channel: 'ptk_popup2background_app',
          type: 'reloadptk'
        }).catch(() => {})
      }
      return
    }

    if (!event.target.closest('[data-dropdown]')) {
      closeAllDropdowns()
    }
  })

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      closeAllDropdowns()
      if (modal?.classList.contains('is-open')) {
        closeModal()
      }
    }
  })

  modalBackdrop?.addEventListener('click', closeModal)
  modalClose?.addEventListener('click', closeModal)

  releaseNoteClose?.addEventListener('click', () => {
    releaseNote?.classList.remove('is-visible')
    ext.runtime.sendMessage({
      channel: 'ptk_popup2background_app',
      type: 'release_note_read'
    }).catch(() => {})
  })

  function openModal(page) {
    if (!modal || !modalBackdrop || !modalFrame) return
    modalFrame.src = page
    modal.classList.add('is-open')
    modalBackdrop.classList.add('is-open')
    modal.setAttribute('aria-hidden', 'false')
  }

  function closeModal() {
    if (!modal || !modalBackdrop || !modalFrame) return
    modal.classList.remove('is-open')
    modalBackdrop.classList.remove('is-open')
    modal.setAttribute('aria-hidden', 'true')
    modalFrame.removeAttribute('src')
  }
}

async function openRouteFromElement(routeLink) {
  const route = routeLink.getAttribute('data-history')
  if (!route) return
  await ext.runtime.sendMessage({
    channel: 'ptk_popup2background_app',
    type: 'history',
    route: route === 'rattacker' ? 'dast' : route,
    hash: ''
  }).catch(() => {})
  openPage(`${route}.html`, { persistHistory: false })
}

function toggleDropdown(dropdown) {
  if (!dropdown) return
  const shouldOpen = !dropdown.classList.contains('is-open')
  closeAllDropdowns()
  if (shouldOpen) {
    dropdown.classList.add('is-open')
    positionDropdown(dropdown)
  }
}

function closeAllDropdowns() {
  document.querySelectorAll('[data-dropdown].is-open').forEach((dropdown) => {
    dropdown.classList.remove('is-open')
    dropdown.classList.remove('ptk-shell-dropdown-flip')
    const menu = dropdown.querySelector('.ptk-shell-dropdown-menu')
    if (menu) {
      menu.style.left = ''
      menu.style.right = ''
    }
  })
}

function positionDropdown(dropdown) {
  const menu = dropdown?.querySelector('.ptk-shell-dropdown-menu')
  if (!menu) return

  dropdown.classList.remove('ptk-shell-dropdown-flip')
  menu.style.left = ''
  menu.style.right = ''

  const viewportPadding = 8
  let rect = menu.getBoundingClientRect()
  if (rect.right > (window.innerWidth - viewportPadding)) {
    dropdown.classList.add('ptk-shell-dropdown-flip')
    rect = menu.getBoundingClientRect()
  }

  if (rect.left < viewportPadding || rect.right > (window.innerWidth - viewportPadding)) {
    dropdown.classList.remove('ptk-shell-dropdown-flip')
    const dropdownRect = dropdown.getBoundingClientRect()
    const maxLeft = window.innerWidth - viewportPadding - rect.width - dropdownRect.left
    const minLeft = viewportPadding - dropdownRect.left
    const clampedLeft = Math.min(Math.max(0, minLeft), Math.max(minLeft, maxLeft))
    menu.style.left = `${Math.round(clampedLeft)}px`
    menu.style.right = 'auto'
  }
}

function bindFrameInteractionDismissal() {
  try {
    const doc = frame.contentWindow?.document
    if (!doc || doc.__ptkShellDismissBound) return
    doc.addEventListener('pointerdown', closeAllDropdowns, true)
    doc.addEventListener('focusin', closeAllDropdowns, true)
    doc.__ptkShellDismissBound = true
  } catch (_) {
    // ignore cross-document issues during transient iframe loads
  }
}

function resolvePage(page) {
  if (page === 'rattacker.html') return 'ptk/browser/dast.html'
  if (page.startsWith('ptk/')) return page
  return `ptk/browser/${page}`
}

async function resolveInitialPage() {
  try {
    const result = await ext.storage.local.get('pentestkit8_settings')
    const route = normalizeStoredHistoryRoute(result?.pentestkit8_settings?.history?.route)
    const hash = normalizeStoredHistoryHash(result?.pentestkit8_settings?.history?.hash)
    if (route === 'dashboard') {
      return 'dashboard.html'
    }
    return `${route}.html${hash}`
  } catch (_) {
    return 'dashboard.html'
  }
}

function normalizeStoredHistoryRoute(route) {
  const normalized = String(route || 'dashboard').trim().toLowerCase()
  if (normalized === 'index') return 'dashboard'
  if (normalized === 'rattacker') return 'dast'
  if (POPUP_HISTORY_ROUTES.has(normalized)) return normalized
  return 'dashboard'
}

function normalizeStoredHistoryHash(hash) {
  const normalized = String(hash || '').trim()
  if (!normalized) return ''
  return normalized.startsWith('#') ? normalized : `#${normalized}`
}

function openPage(page, { persistHistory = false } = {}) {
  try {
    const normalizedPage = String(page || 'dashboard.html')
    const pageWithoutHash = normalizedPage.split('#')[0]
    if (persistHistory) {
      const route = pageWithoutHash.replace(/\.html$/, '')
      ext.runtime.sendMessage({
        channel: 'ptk_popup2background_app',
        type: 'history',
        route: route === 'rattacker' ? 'dast' : route,
        hash: ''
      }).catch(() => {})
    }
    frame.src = ext.runtime.getURL(resolvePage(normalizedPage))
    setActiveMenuByPage(pageWithoutHash)
  } catch (error) {
    console.error('Failed to open page', page, error)
  }
}

function getFramePageName() {
  try {
    const frameUrl = frame.contentWindow?.location?.href || frame.getAttribute('src') || ''
    if (!frameUrl) return ''
    const url = new URL(frameUrl, window.location.href)
    const parts = url.pathname.split('/')
    return parts[parts.length - 1] || ''
  } catch (_) {
    return ''
  }
}

function setActiveMenuByPage(pageName) {
  if (!pageName) return

  const routeLinks = Array.from(document.querySelectorAll('[data-route-link]'))
  const dropdownToggles = Array.from(document.querySelectorAll('[data-dropdown-toggle]'))

  routeLinks.forEach((link) => link.classList.remove('is-active'))
  dropdownToggles.forEach((toggle) => toggle.classList.remove('is-active'))

  const matched = routeLinks.find((link) => {
    const route = link.getAttribute('data-history') || ''
    if (!route) return false
    const targets = route === 'dast' ? ['dast.html', 'rattacker.html'] : [`${route}.html`]
    return targets.includes(pageName)
  })

  if (!matched) return

  matched.classList.add('is-active')
  const parentToggleId = matched.getAttribute('data-parent-toggle')
  if (parentToggleId) {
    document.getElementById(parentToggleId)?.classList.add('is-active')
  }
}

function loadReleaseNote() {
  ext.runtime.sendMessage({
    channel: 'ptk_popup2background_app',
    type: 'release_note'
  }).then((response) => {
    if (response?.show) {
      document.getElementById('ptk_release_note')?.classList.add('is-visible')
    }
  }).catch(() => {})
}
