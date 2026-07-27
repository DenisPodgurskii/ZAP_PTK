/* Author: Denis Podgurskii */
import { ptk_controller_secrets } from '../../../controller/secrets.js'

const secrets = new ptk_controller_secrets()

function renderStatus(result) {
    const status = result?.status || {}
    const message = result?.message
        || (status.configured ? `API token configured (${status.fingerprint || 'fingerprint unavailable'})` : 'No API key found')
    $('#api_response').text(message)
}

jQuery(function () {
    $('.clear_apikey').on('click', async function () {
        $('#profile_form').form('set value', 'api_key', '')
        renderStatus(await secrets.clear())
    })

    $('.save_apikey').on('click', async function () {
        const values = $('#profile_form').form('get values')
        const activationToken = String(values?.api_key || '').trim()
        if (!activationToken) {
            $('#api_response').text('Activation token is required.')
            return
        }
        const result = await secrets.activate(activationToken)
        $('#profile_form').form('set value', 'api_key', '')
        renderStatus(result)
    })

    $('#settings_reset').on('click', async function () {
        renderStatus(await secrets.clear())
    })

    secrets.getStatus().then(renderStatus).catch(() => {
        $('#api_response').text('Unable to read API token status.')
    })
})
