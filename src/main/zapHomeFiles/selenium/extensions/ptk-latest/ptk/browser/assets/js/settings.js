/* Author: Denis Podgurskii */
import { ptk_controller_settings } from "../../../controller/settings.js"
import { ptk_controller_secrets } from "../../../controller/secrets.js"
import {
    buildPortalLoginUrl,
    buildPortalRegisterUrl,
    initializePortalRuntimeConfig
} from "../../../common/portalConfig.js"

const controller = new ptk_controller_settings()
const secrets = new ptk_controller_secrets()
const portalConfigReady = initializePortalRuntimeConfig()

var loginLink, registerLink
var profileSettings = {}

function refreshPortalLinks() {
    loginLink = buildPortalLoginUrl()
    registerLink = buildPortalRegisterUrl()
}

refreshPortalLinks()
portalConfigReady.finally(function () {
    refreshPortalLinks()
})

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
        secrets.clear().then(function (result) {
            if (result?.success) showApiInfo()
            else showApiError(result?.message || 'Unable to clear API token.')
        })
    })

    $('.save_apikey').on('click', function () {
        activateProToken()
    })

    $('.clear_sensitive_artifacts').on('click', function () {
        if (!window.confirm('Clear saved JWTs, Request Builder history, macros, session profiles, and evidence packages?')) return
        browser.runtime.sendMessage({
            channel: 'ptk_popup2background_app',
            type: 'clear_sensitive_artifacts'
        }).then((result) => {
            if (!result?.success) {
                window.alert(result?.error === 'recording_or_replay_active'
                    ? 'Stop the active recording or replay before clearing saved testing data.'
                    : 'Saved testing data could not be cleared.')
                return
            }
            window.alert('Saved testing data was cleared.')
        }).catch(() => window.alert('Saved testing data could not be cleared.'))
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

        $form = $('#profile_form'), values = $form.form('get values')
        Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
        delete values['api_key']
        delete values['enable']
        profileSettings = Object.assign({}, profileSettings || {}, values)
        controller.save('profile', profileSettings)

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
    return secrets.validate().then(function (result) {
        if (result?.success) {
            showApiSuccess(result.message || "API token validated successfully.", result.status)
            return true
        }
        if (showError) showApiError(result?.message || "Unable to validate API key.")
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

function showApiSuccess(message, status = null) {
    updateApiTokenDisplay(status)
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

function updateApiTokenDisplay(status) {
    $('#api_token').text(status?.fingerprint || "Configured")
}

async function activateProToken() {
    await portalConfigReady
    hideApiMessages()
    let $form = $('#profile_form'), values = $form.form('get values')
    Object.keys(values).map((k) => { if (values[k] === 'on') values[k] = true })
    const activationToken = (values['api_key'] || "").trim()
    if (!activationToken) {
        showApiError("Activation token is required.")
        return
    }

    try {
        const result = await secrets.activate(activationToken)
        $form.form('set value', "api_key", "")
        if (!result?.success) {
            showApiError(result?.message || "Unable to activate token.")
            return
        }
        showApiSuccess(result.message || "API token activated successfully.", result.status)
    } catch (err) {
        showApiError("Unable to activate token.")
    }
}

$(document).on("check_api_key", async function (e) {
    checkApiKey(true)
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

    Object.entries(s.profile).forEach(([key, value]) => {
        setFormValueIfExists($profileForm, key, value)
    })
    setFormValueIfExists($profileForm, "api_key", "")
    secrets.getStatus().then(function (result) {
        const status = result?.status
        if (!status?.configured) showApiInfo()
        else if (status.valid === false) showApiError("Stored API token requires validation.")
        else showApiSuccess(
            status.valid === true ? "API token validated successfully." : "API token is configured.",
            status
        )
    }).catch(() => showApiError("Unable to read API token status."))
    portalConfigReady.finally(function () {
        refreshPortalLinks()
    })

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
