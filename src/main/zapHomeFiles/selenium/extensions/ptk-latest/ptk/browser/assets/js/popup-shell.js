const ext = globalThis.browser ?? globalThis.chrome
const frame = document.getElementById('ptkFrame')
const menuWrapper = document.getElementById('mainMenuWrapper')

document.addEventListener('DOMContentLoaded', () => {
  // Set clipboard permissions only in browsers that support them (Chrome)
  // Firefox doesn't support these permission policies and logs warnings
  const ptkFrame = document.getElementById('ptkFrame')
  if (ptkFrame && (typeof navigator.userAgentData !== 'undefined' || !navigator.userAgent.includes('Firefox'))) {
    ptkFrame.setAttribute('allow', 'clipboard-read; clipboard-write')
  }

  // Wire the menu clicks to load pages into the iframe
  const mainMenu = document.getElementById('mainMenu')
  if (mainMenu) {
    mainMenu.addEventListener('click', (e) => {
      const a = e.target.closest('a[data-history]') || e.target.closest('a[data-page]')
      if (!a) return
      const page = a.getAttribute('data-history') || a.getAttribute('data-page')
      if (!page) return
      e.preventDefault()
      openPage(`${page}.html`)
    })
  }
  // Default load
  //openPage('dashboard.html')
})

function resolvePage(page) {
  if (page.startsWith('ptk/')) return page
  return `ptk/browser/${page}`
}

function openPage(page) {
  try {
    frame.src = ext.runtime.getURL(resolvePage(page))
  } catch (e) {
    console.error('Failed to open page', page, e)
  }
}
let version = browser.runtime.getManifest().version
jQuery(function () {

  //Main menu
  $('#mainMenuWrapper').prepend(
    `<div class="ui small inverted borderless menu" style="height:12px">
            
            <div class="ui container" id="mainMenu">
                <a class="item" href="#" data-history="dashboard"><img src="assets/images/hacker_w1.png" id="ptkicon" title="OWASP Penetration Testing Kit">
                
                <i class="home icon" style="position: relative;top: -10px;padding: 0px;margin: -5px;"></i></a>
                <a class="item" href="#" data-history="rattacker">DAST</a>
                <a class="item" href="#" data-history="iast">IAST</a>
                <a class="item" href="#" data-history="sast">SAST</a>
                <a class="item" href="#" data-history="sca">SCA</a>
                <a class="item" href="#" data-history="proxy">Proxy</a>
                <a class="item" href="#" data-history="rbuilder">R-Builder</a>
                <a class="item" href="#" data-history="session">Cookies</a>
                <a class="item" href="#" data-history="jwt">JWT</a>
                <a class="item" href="#" data-history="decoder">Decoder</a>

                <div class="ui top left pointing dropdown item" style="margin-right: 0px !important;">Cheat sheets</i>
                    <div class="menu" style="width: 120px;top: 25px;">
                        <a class="item" href="#" data-history="xss">XSS</a>
                        <a class="item" href="#" data-history="sql">SQL</a>
                    </div>
                </div>

                <div class="ui top left pointing dropdown item" >Tools<i class="dropdown icon"></i>
                    <div class="menu" style="width: 120px;top: 25px;">
                    
                    <a class="item" href="#" data-history="macro">Macro</a>
                    <a class="item" href="#" data-history="traffic">Traffic</a>
                    <a class="item" href="#" data-history="swagger">Swagger</a>

                    <!--a class="item" href="portscanner.html" data-history="portscanner">Port Scanner</a-->
                    </div>
                </div>

                <a class="item" href="https://www.zaproxy.org/blog/2026-01-19-owasp-ptk-add-on/" target="_blank"><img src="assets/images/zap.svg" id="ZAP" title="OWASP PTK Integration with ZAP" style="position: absolute;width: 28px;height: 28px;right: 47px;top: 7px;"></a>
                <a class="item" href="https://athenaos.org/en/resources/browser-pentesting/#_top" target="_blank"><img src="assets/images/athenaos.svg" id="AthenaOS" title="Athena OS Integration" style="position: absolute;width: 30px;height: 30px;right: 32px;top: 6px;"></a>
   
    
                
                <!--div class="ui dropdown item " style="position: absolute;width: 30px;height: 30px;right: 34px;top: 3px;padding: 0px; ">
                    <i title="Profile" id="profile"></i>
                </div-->
                <div class="ui dropdown item notifications" style="position: absolute;width: 30px;height: 30px;right: 34px;top: 3px;padding: 0px; display:none">
                    <div><i title="Notifications" class=" red exclamation triangle big icon"></i></div>
                    <div class="menu">
                    <div class="ui error message" style="margin-top: 0px !important;">
                      <div class="header">Error</div>
                      <p>Cookie and storage access is disabled. Reinstall the extension or enable cookie/storage on the "Settings" page.</p>
                    </div>
                  </div>
                </div>

                <!--div class="ui dropdown item " style="position: absolute;width: 30px;height: 30px;right: 34px;top: 3px;padding: 0px; ">
                    <div><i title="Open in new window" class="external square alternate big icon" id="opennewwindow"></i></div>
                </div-->

                
                <div class="ui dropdown item" style="position: absolute;width: 30px;height: 30px;right: 3px;top: 3px;padding: 0px;">
                    <div ><i title="More" class="question circle outline big icon"></i></div>
                    <div class="menu top_right_icon" style="margin-top: 0px !important; min-height: 90px;top: 34px;">
                        <div class="ui fitted divider" style="margin-top: 0px;"></div>
                        <a class="item" href="#" id="opensettings">Settings</a>
                        <div class="ui fitted divider"></div>
                        
                        <a class="item" href="#" id="reloadextension">Reload PTK</a>
                        <div class="ui fitted divider"></div>
                        <a class="item" href="https://pentestkit.co.uk/howto.html" target="_blank">How to<i class="external square right floated icon"></i></a>
                        <a class="item" href="https://pentestkit.co.uk/release_notes.html" target="_blank">Release notes<i class="external square right floated icon"></i></a>
                        <div class="ui fitted divider"></div>
                        <a class="item" href="#" id="credits">Credits</a>
                        <a class="item" href="#" id="disclaimer">Disclaimer</a>
                        <a class="item" href="#" id="privacy">Privacy Policy</a>
                        <a class="item" href="#" id="contactus">Contact Us</a>
                        <div class="ui fitted divider"></div>
                        <a class="item disabled" href="#">Version: #${version}</a>
                    </div>
                </div>
            </div>
        </div>
        <div id='ptk_popup_dialog' class='ui fullscreen modal'>
        <i class="close icon" style="right: 2px;top: 2px;"></i>
        <iframe style="width:100%; height:100%; border:none; margin:0; padding:0; overflow:hidden; z-index:999999;"></iframe>
        </div>
        `
  )

  function getFramePageName() {
    try {
      const frame = document.getElementById('ptkFrame')
      if (!frame) return ''
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
    $('#mainMenu a.item').each(function (i, obj) {
      const route = $(obj).attr('data-history') || ''
      if (!route) return
      const target = `${route}.html`
      if (target === pageName) {
        $(obj).addClass('active').siblings().removeClass('active')
      }
    })
  }

  function resolvePage(page) {
    if (page.startsWith('ptk/')) return page
    return `ptk/browser/${page}`
  }

  function openPage(page) {
    try {
      let frame = document.getElementById('ptkFrame')
      frame.src = ext.runtime.getURL(resolvePage(page))
      setActiveMenuByPage(page)
    } catch (e) {
      console.error('Failed to open page', page, e)
    }
  }

  $('#ptkFrame').on('load', function () {
    setActiveMenuByPage(getFramePageName())
  })
  setActiveMenuByPage(getFramePageName())
  if (frame) {
    const observer = new MutationObserver(() => {
      setActiveMenuByPage(getFramePageName())
    })
    observer.observe(frame, { attributes: true, attributeFilter: ['src'] })
  }
  $('#mainMenu a.item').on('click', function (e) {
    let route = $(this).attr('data-history')
    let href = $(this).attr('href')
    if (route) {
      browser.runtime.sendMessage({
        channel: "ptk_popup2background_app",
        type: "history",
        route: route,
        hash: ""
      }).catch(() => {})
    }
    if(route)
      openPage(`${route}.html`)
  })

  //Submenu all pages
  $('.ui.menu a.item').on('click', function () {
    $(this).addClass('active').siblings().removeClass('active')
    let forItem = $(this).attr('forItem')
    $('.ui.menu a.item').each(function (i, obj) {
      let f = $(obj).attr('forItem')
      if (f != forItem) $('#' + f).hide()
    })
    $('#' + forItem).fadeIn("slow")
  })

  $("body").prepend(
    `
<div class="ui success tiny message" id="ptk_release_note" style="display:none;position: absolute;bottom: 0;right: 0;z-index: 2;margin:0; width:500px">
  <i class="close icon ptk_release_note"></i>
  <div class="header">
    Release notes - #${version}
  </div>
  <ul class="list">
    <li><strong>Reports export:</strong> Added export in <strong>PDF</strong> and <strong>Markdown</strong> formats.</li>
    <li><strong>Executive vs Technical:</strong> New report presets with a <strong>Summary</strong> section for quick high-level visibility.</li>
    <li><strong>Triage & correlation:</strong> Added <strong>severity filters</strong>, <strong>confidence scoring</strong>, and <strong>correlated findings</strong> across DAST/IAST/SAST/SCA.</li>
    <li><strong>Safer exports:</strong> Safe-by-default <strong>redaction</strong>, cleaner evidence (truncation), and Executive reports now <strong>group/dedupe</strong> noisy repeats.</li>
  </ul>
  <p>More details on <a href="https://pentestkit.co.uk/release_notes.html" target="_blank">https://pentestkit.co.uk/release_notes.html</a></p>
</div>

        `

  )

})
