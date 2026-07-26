/* Author: Denis Podgurskii */

jQuery(function () {
    const extensionOrigin = window.location.origin
    const macroFrame = document.getElementById('macro_frame')
    const trafficFrame = document.getElementById('traffic_frame')

    $('.menu .item').tab()

    $('.parent_url').on('change', function (evt) {
        const message = { channel: 'ptk_recording_url', url: $('.parent_url').val() }
        macroFrame.contentWindow.postMessage(message, extensionOrigin)
        trafficFrame.contentWindow.postMessage(message, extensionOrigin)
    })

    $('.button.traffic').on('click', function (evt) {
        document.getElementById('traffic_frame').src = 'traffic.html'
    })

    window.addEventListener('message', function (msg) {
        const trustedFrame = msg.source === macroFrame.contentWindow || msg.source === trafficFrame.contentWindow
        if (msg.origin !== extensionOrigin || !trustedFrame) return
        if (msg.data?.channel === 'ptk_recording_url' && typeof msg.data.url === 'string')
            $('.parent_url').val(msg.data.url)
    })
})
