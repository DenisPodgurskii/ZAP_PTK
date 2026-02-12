/* Author: Denis Podgurskii */
import { ptk_controller_settings } from "../../../controller/settings.js"
import { ptk_controller_rattacker } from "../../../controller/rattacker.js"


const controller = new ptk_controller_settings()
const rattacker = new ptk_controller_rattacker()

var loginLink, registerLink
var profileSettings = {}
var currentApiKey = ""

jQuery(function () {


    $('#mainMenu a.item').each(function (i, obj) {
        if (window.location.pathname.indexOf($(obj).attr('href')) > 0)
            $(obj).addClass('active').siblings().removeClass('active')
    });

    //Submenu all pages
    $('.ui.menu a.item').on('click', function () {
        $(this).addClass('active').siblings().removeClass('active')
        let forItem = $(this).attr('forItem')
        $('.ui.menu a.item').each(function (i, obj) {
            let f = $(obj).attr('forItem')
            if (f != forItem) $('#' + f).hide()
        })
        $('#' + forItem).fadeIn("slow")
        if (forItem == 'profile_form') {
            $('#settings_header').hide()
            $('#settings_footer').hide()
        }
        else {
            $('#settings_header').show()
            $('#settings_footer').show()
        }
    })

    //PTK+
    $('.ptk_login').on('click', function () {
        window.open(loginLink)
    })

    $('.ptk_register').on('click', function () {
        window.open(registerLink)
    })


    $('.clear_apikey').on('click', function () {
        let $form = $('#profile_form')
        $form.form('set value', "api_key", "")
        hideApiMessages()
        currentApiKey = ""
        if (profileSettings) profileSettings.api_key = ""
        controller.save('profile.api_key', "").then(function () {
            controller.restore().then(function (s) {
                controller.on_updated_settings(s)
            })
        })
        showApiInfo()
    })

    $('.save_apikey').on('click', function () {
        activateProToken()
    })

    $('#settings_save').on('click', function () {

        let $form = $('#main_form'), values = $form.form('get values')
        Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
        controller.save('main', values)

        $form = $('#proxy_form'), values = $form.form('get values')
        Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
        controller.save('proxy', values)

        $form = $('#recorder_form'), values = $form.form('get values')
        Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
        controller.save('recorder', values)

        $form = $('#privacy_form'), values = $form.form('get values')
        Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
        controller.save('privacy', values)

        const supported_types = ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other"]

        $form = $('#rattacker_form'), values = $form.form('get values')
        Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
        values['max_requests'] = parseInt(values['max_requests'])
        values['blacklist'] = values['blacklist'].split(',').filter(item => supported_types.includes(item))

        controller.save('rattacker', values)

        // Save automation settings via controller (stored in pentestkit8_settings.automation)
        // Explicitly get checkbox state since form('get values') may not return unchecked checkboxes
        const automationEnabled = $('#automation_form').find('input[name="enable"]').is(':checked')
        controller.save('automation', { enable: automationEnabled })

        controller.restore().then(function (s) {
            controller.on_updated_settings(s)
        })

        $(".modal").fadeIn("slow").delay(2000).fadeOut()
    })

    $('#settings_reset').on('click', function () {
        controller.reset().then(function (s) {
            $(document).trigger("init_forms", s.settings)
            $(".modal").fadeIn("slow").delay(2000).fadeOut()
        })
    })
    controller.restore().then(function (s) {
        $(document).trigger("init_forms", s)
    })
})


function formHasField($form, key) {
    return $form && $form.length && $form.find(`[name="${key}"]`).length > 0
}

function setFormValueIfExists($form, key, value) {
    if (formHasField($form, key)) {
        $form.form('set value', key, value)
    }
}

function checkApiKey(showError = true, apiKeyOverride = null) {
    let apiKey = apiKeyOverride
    if (!apiKey) {
        let $form = $('#profile_form'), values = $form.form('get values')
        Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
        apiKey = values['api_key']
    }
    apiKey = (apiKey || "").trim()
    if (!apiKey) {
        if (showError) showApiError("API key is empty.")
        else hideApiMessages()
        return Promise.resolve(false)
    }
    return rattacker.checkApiKey(apiKey).then(function (response) {
        let msg = ""
        if (typeof response == "object" && response.rules?.modules?.json) {
            try {
                let modules = JSON.parse(response.rules.modules.json).modules
                let attacksNum = 0
                let dt = new Array()
                modules.map(item => {
                    dt.push([item.metadata.module_name, Object.keys(item.attacks).length])
                })
                bindTable('#tbl_modules', { data: dt })
                currentApiKey = apiKey
                if (profileSettings) profileSettings.api_key = apiKey
                updateApiTokenDisplay(apiKey)
                showApiSuccess(msg || "API token validated successfully.")
            }catch(er){
                if (showError) {
                    msg = er.message
                    showApiError(msg)
                    return false
                }
            }
            return true
        } else if (showError) {
            msg = response?.json?.message || response?.message || "Unable to validate API key."
            showApiError(msg)
            return false
        }
        return false
    })
}

function hideApiMessages() {
    $('#api_error').hide()
    $('#api_success').hide()
    $('#api_info').hide()
    $('#api_token').text("")
}

function showApiError(message) {
    $('#api_response_error').text(message || "Something went wrong.")
    $('#api_token').text("")
    $('#api_success').hide()
    $('#api_info').hide()
    $('#api_error').show()
}

function showApiSuccess(message, token = null) {
    if (token) updateApiTokenDisplay(token)
    $('#api_response_success').text(message || "")
    $('#api_error').hide()
    $('#api_info').hide()
    $('#api_success').show()
}

function showApiInfo() {
    $('#api_error').hide()
    $('#api_success').hide()
    $('#api_token').text("")
    $('#api_info').show()
}

function updateApiTokenDisplay(token) {
    const masked = maskApiToken(token)
    $('#api_token').text(masked)
}

function maskApiToken(token) {
    if (!token) return ""
    const visibleLength = token.length < 8 ? token.length : Math.min(10, token.length)
    const visiblePart = token.slice(0, visibleLength)
    const maskedPart = '*'.repeat(Math.max(0, token.length - visibleLength))
    return visiblePart + maskedPart
}

async function activateProToken() {
    hideApiMessages()
    let $form = $('#profile_form'), values = $form.form('get values')
    Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
    const activationToken = (values['api_key'] || "").trim()
    if (!activationToken) {
        showApiError("Activation token is required.")
        return
    }

    const activationUrl = buildActivationUrl()
    if (!activationUrl) {
        showApiError("Activation endpoint is not configured. Please check PTK Pro settings.")
        return
    }

    try {
        const response = await fetch(activationUrl, {
            method: "POST",
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            cache: "no-cache",
            body: JSON.stringify({
                activation_token: activationToken,
                ptk_agent: "ptk-browser-extension"
            })
        })

        let payload = {}
        const rawBody = await response.text()
        if (rawBody) {
            try {
                payload = JSON.parse(rawBody)
            } catch (err) {
                payload = { message: rawBody }
            }
        }

        if (!response.ok || !payload?.token) {
            let message = payload?.message || payload?.error || payload?.json?.message || "Unable to activate token."
            showApiError(message)
            return
        }

        await controller.save('profile.api_key', payload.token)
        if (profileSettings) profileSettings.api_key = payload.token
        currentApiKey = payload.token
        $form.form('set value', "api_key", "")
        showApiSuccess("API token activated successfully.", payload.token)
        await checkApiKey(false, payload.token)

        controller.restore().then(function (s) {
            controller.on_updated_settings(s)
        })
    } catch (err) {
        showApiError(err.message)
    }
}

function buildActivationUrl() {
    if (!profileSettings) return null
    const baseUrl = (profileSettings.base_url || "").trim()
    const apiBase = (profileSettings.api_base || "").trim()
    if (!baseUrl || !apiBase) return null
    const normalizedBase = baseUrl.replace(/\/+$/, "")
    let normalizedApiBase = apiBase.replace(/\/+$/, "")
    if (!normalizedApiBase.startsWith('/')) normalizedApiBase = '/' + normalizedApiBase
    return normalizedBase + normalizedApiBase + '/tokens/activate'
}

function buildValidationUrl() {
    if (!profileSettings) return null
    const baseUrl = (profileSettings.base_url || "").trim()
    const apiBase = (profileSettings.api_base || "").trim()
    if (!baseUrl || !apiBase) return null
    const normalizedBase = baseUrl.replace(/\/+$/, "")
    let normalizedApiBase = apiBase.replace(/\/+$/, "")
    if (!normalizedApiBase.startsWith('/')) normalizedApiBase = '/' + normalizedApiBase
    return normalizedBase + normalizedApiBase + '/tokens/validate'
}

async function validateStoredToken(token) {
    const normalizedToken = (token || "").trim()
    currentApiKey = normalizedToken
    if (!normalizedToken) {
        showApiInfo()
        return
    }
    const validationUrl = buildValidationUrl()
    if (!validationUrl) {
        showApiError("Validation endpoint is not configured. Please check PTK Pro settings.")
        return
    }
    hideApiMessages()
    try {
        const response = await fetch(validationUrl, {
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + normalizedToken,
                'Accept': 'application/json'
            },
            cache: 'no-cache'
        })
        let payload = null
        try {
            payload = await response.json()
        } catch (err) {
            payload = null
        }
        if (response.ok) {
            showApiSuccess("API token validated successfully.", normalizedToken)
        } else {
            const message = payload?.message || payload?.error || payload?.json?.message || "Token validation failed."
            showApiError(message)
        }
    } catch (err) {
        showApiError(err.message)
    }
}

$(document).on("check_api_key", async function (e) {
    let apiKey = arguments.length > 1 ? arguments[1] : null
    checkApiKey(true, apiKey)
})

$(document).on("init_forms", function (e, s) {

    const $mainForm = $('#main_form')
    const $proxyForm = $('#proxy_form')
    const $recorderForm = $('#recorder_form')
    const $rattackerForm = $('#rattacker_form')
    const $privacyForm = $('#privacy_form')
    const $profileForm = $('#profile_form')

    Object.entries(s.main).forEach(([key, value]) => {
        setFormValueIfExists($mainForm, key, value)
    })

    Object.entries(s.proxy).forEach(([key, value]) => {
        setFormValueIfExists($proxyForm, key, value)
    })

    Object.entries(s.recorder).forEach(([key, value]) => {
        if (!['recorderFile', 'trackerFile', 'popupFile', 'replayerFile', 'icons'].includes(key)) {
            setFormValueIfExists($recorderForm, key, value)
        }
    })

    Object.entries(s.rattacker).forEach(([key, value]) => {
        setFormValueIfExists($rattackerForm, key, value)
    })

    Object.entries(s.privacy).forEach(([key, value]) => {
        setFormValueIfExists($privacyForm, key, value)
    })


    profileSettings = s.profile || {}
    currentApiKey = profileSettings.api_key || ""
    if (!currentApiKey) {
        showApiInfo()
    }

    Object.entries(s.profile).forEach(([key, value]) => {
        if (key === "api_key") {
            setFormValueIfExists($profileForm, key, "")
            validateStoredToken(value)
            return
        }
        setFormValueIfExists($profileForm, key, value)
    })
    loginLink = profileSettings.login_url
    registerLink = profileSettings.register_url

    // Load automation settings from pentestkit8_settings.automation
    // Use Semantic UI checkbox methods for proper toggle state
    const automationEnabled = s.automation?.enable === true
    const $automationCheckbox = $('#automation_form').find('.ui.checkbox')
    if ($automationCheckbox.length) {
        // Ensure checkbox is initialized, then set state
        $automationCheckbox.checkbox()
        $automationCheckbox.checkbox(automationEnabled ? 'check' : 'uncheck')
    }

})
