
(() => {
    if (typeof browser === 'undefined') {
        // Extension context not available (e.g., page reload before injection)
        return
    }

    if (document.getElementById('ptk_recording_control') || window.opener || window.__ptkRecordingTrackerActive) return
    window.__ptkRecordingTrackerActive = true

    let pendingRecordingLog = null
    let earlyShowMessage = null
    const earlyStorageListener = function (changes, namespace) {
        if (namespace !== 'local' || !changes?.ptk_recording_log) return
        pendingRecordingLog = changes.ptk_recording_log.newValue || ''
        if (earlyShowMessage) earlyShowMessage(pendingRecordingLog)
    }
    browser.storage.onChanged.addListener(earlyStorageListener)

    browser.storage.local.get([
        'ptk_recording',
        'ptk_replay',
        'ptk_recording_items',
        'ptk_replay_step',
        'ptk_replay_result',
        'ptk_replay_last_result',
        'ptk_recording_log',
        'ptk_recording_confirm_required',
        'ptk_path_to_icons'
    ]).then(async function (result) {
        const activeSession = result.ptk_replay?.mode === 'replay'
            ? result.ptk_replay
            : result.ptk_recording?.mode === 'recording'
                ? result.ptk_recording
                : null
        if (!activeSession?.sessionId) {
            browser.storage.onChanged.removeListener(earlyStorageListener)
            window.__ptkRecordingTrackerActive = false
            return
        }
        let iconPath = result.ptk_path_to_icons
        if (result.ptk_recording_confirm_required) {
            const claim = await browser.runtime.sendMessage({
                channel: 'ptk_content2background_recorder',
                type: 'claim_confirmation',
                sessionId: activeSession.sessionId
            }).catch(() => null)
            if (claim?.show) {
                const confirmation = claim.mode === 'replay'
                    ? 'You are now starting a macro replay'
                    : 'You are now recording a macro/traffic sequence'
                alert(confirmation)
            }
        }

        let popupHtml = document.getElementById('ptk_recording_control')

        let icon = browser.runtime.getURL(iconPath + '/icon_rec.png')
        let icons_replay = '';
        const replayStep = Number.isSafeInteger(result.ptk_replay_step) ? result.ptk_replay_step : 0
        const replayItem = Array.isArray(result.ptk_replay_items) ? result.ptk_replay_items[replayStep] : null
        const replayEventName = String(replayItem?.EventTypeName || replayItem?.EventType || 'Replay')
        let msg = pendingRecordingLog || result.ptk_recording_log || "Recording"
        if (result.ptk_replay?.mode == 'replay') {
            msg = pendingRecordingLog || result.ptk_recording_log
                || `Step #${replayStep + 1}: ${replayEventName}<br/>`
            icon = browser.runtime.getURL(iconPath + '/icon_play.png')
            icons_replay = `
            <div id="ptk_recording_control_icon_pause" title="Pause"></div>
            <div id="ptk_recording_control_icon_forward" title="Next step"></div>
            `
        }

        popupHtml = document.createElement('div')
        popupHtml.id = 'ptk_recording_control';
        popupHtml.innerHTML = `
        <style>
        #ptk_recording_control {
            position: fixed;
            top: 10px;
            left: 10px;
            min-width: 250px;
            min-height: 98px;
            border-radius: 15px;
            z-index: 10000;
            background: rgb(214, 201, 201);
            display: flex;
            resize: both;
            overflow:hidden;

        }

        #ptk_recording_control_icons {
            width: 100%;
            cursor: move;
            height: 34px;
            position: absolute;
            background: black;
            opacity: 0.2;
            z-index: 1;
        }

        #ptk_recording_control_icon {
            width: 90px;
            height: 30px;
            border-radius: 25px;
            z-index: 0;
            animation: 3s blinker linear infinite;
            -webkit-animation: 3s blinker linear infinite;
            -moz-animation: 3s blinker linear infinite;
            background-image: url('${icon}');
            background-color: gray;
            background-position: center;
            background-repeat: no-repeat;
            background-size: 75px 25px;
            text-align: center;
            position: absolute;
            top: 2px;
            right: 2px;
        }


        #ptk_recording_control_icon_stop {
            border-radius: 25px;
            background-image: url('${browser.runtime.getURL(iconPath + '/stop.png')}');
            background-position: center;
            background-repeat: no-repeat;
            background-size: 30px 30px;
            position: absolute;
            width: 30px;
            height: 30px;
            top: 2px;
            left: 2px;
            cursor: pointer;
            background-color: gray;
            z-index: 10;
        }

        #ptk_recording_control_icon_pause {
            border-radius: 25px;
            background-image: url('${browser.runtime.getURL(iconPath + '/pause.png')}');
            background-position: center;
            background-repeat: no-repeat;
            background-size: 30px 30px;
            position: absolute;
            width: 30px;
            height: 30px;
            top: 2px;
            left: 36px;
            cursor: pointer;
            background-color: gray;
            z-index: 10;
        }

        #ptk_recording_control_icon_forward {
            border-radius: 25px;
            background-image: url('${browser.runtime.getURL(iconPath + '/forward.png')}');
            background-position: center;
            background-repeat: no-repeat;
            background-size: 30px 30px;
            position: absolute;
            width: 30px;
            height: 30px;
            top: 2px;
            left: 70px;
            cursor: pointer;
            background-color: gray;
            z-index: 10;
        }

        #ptk_recording_wrapper{
            min-width: 250px;
            max-height: 100%;
            overflow: scroll;
            padding-left: 7px;
            position: relative;
            z-index: 0;
            top: 45px;
            scrollbar-width: none;
        }

        #ptk_recording_message {
            display: block;
            font-size: 13px;
            font-family: monospace;
            width: 95%;
            position: absolute;
            padding-bottom: 55px;
            line-height: 15px;
        }

        #ptk_recording_wrapper::-webkit-scrollbar {
            width: 0px;   
        }


        @-moz-keyframes blinker {
            0% {
                opacity: 1.0;
            }

            50% {
                opacity: 0.0;
            }

            100% {
                opacity: 1.0;
            }
        }

        @-webkit-keyframes blinker {
            0% {
                opacity: 1.0;
            }

            50% {
                opacity: 0.0;
            }

            100% {
                opacity: 1.0;
            }
        }

        @keyframes blinker {
            0% {
                opacity: 1.0;
            }

            50% {
                opacity: 0.0;
            }

            100% {
                opacity: 1.0;
            }
        }
    </style>

        <div id="ptk_recording_control_icons"></div>
        <div id="ptk_recording_control_icon_stop" title="Stop"></div>
        ${icons_replay}
        <div id="ptk_recording_control_icon"></div>
        <div id="ptk_recording_wrapper">
            <div id="ptk_recording_message"></div>
        </div>
        `;

        (document.documentElement).appendChild(popupHtml)
        if (typeof window.__ptkBindRecordingPopupDrag === 'function') {
            window.__ptkBindRecordingPopupDrag()
        }
        showMessage(msg)

        document.getElementById("ptk_recording_control_icon_stop").addEventListener('click', function (e) {
            const isReplay = result.ptk_replay?.mode == 'replay'
            browser.runtime.sendMessage({
                channel: "ptk_popup2background_recorder",
                type: isReplay ? "stop_replay" : "stop_recording",
                sessionId: activeSession.sessionId
            }).catch(e => e)
        })

        document.getElementById("ptk_recording_control_icon_forward")?.addEventListener('click', function (e) {
            window.ptk_replayer.stepForward()
        })

        document.getElementById("ptk_recording_control_icon_pause")?.addEventListener('click', function (e) {
            if (window.ptk_replayer.paused) {
                window.ptk_replayer.run()
                if (window.ptk_replayer.step == -1) {
                    forceClosing()
                }

                document.getElementById("ptk_recording_control_icon_forward").style.display = 'block'
                document.getElementById("ptk_recording_control_icon_pause").style.backgroundImage = "url('" + browser.runtime.getURL(iconPath + '/pause.png') + "')"
                document.getElementById("ptk_recording_control_icon_pause").title = 'Pause'
            } else {
                if (window.ptk_recording_timer) clearTimeout(window.ptk_recording_timer)
                if (window.ptk_recording_interval) clearInterval(window.ptk_recording_interval)
                window.ptk_replayer.pause()
                document.getElementById("ptk_recording_control_icon_forward").style.display = 'none'
                document.getElementById("ptk_recording_control_icon_pause").style.backgroundImage = "url('" + browser.runtime.getURL(iconPath + '/play.png') + "')"
                document.getElementById("ptk_recording_control_icon_pause").title = 'Play'
            }
        })


        function showMessage(text) {
            let el = document.getElementById('ptk_recording_message')
            if (!el) return
            el.replaceChildren()
            const parts = String(text || '').split(/<br\s*\/?>/i)
            parts.forEach((part, index) => {
                if (index > 0) el.appendChild(document.createElement('br'))
                el.appendChild(document.createTextNode(part))
            })
            const wrapper = document.getElementById('ptk_recording_wrapper')
            if (wrapper) wrapper.scrollTop = wrapper.scrollHeight
        }

        function replayResultMessage(replayResult) {
            if (!replayResult || typeof replayResult !== 'object') return ''
            const completed = Number(replayResult.completedSteps) || 0
            const total = Number(replayResult.totalSteps) || 0
            if (replayResult.status === 'completed') return `Replay completed (${completed}/${total}).`
            if (replayResult.status === 'failed') {
                const message = String(replayResult.error?.message || 'Replay failed.').slice(0, 300)
                return `Replay failed at step ${Number(replayResult.currentStep) || 0}: ${message}`
            }
            if (replayResult.status === 'stopped') return `Replay stopped (${completed}/${total}).`
            return ''
        }

        earlyShowMessage = showMessage
        if (pendingRecordingLog !== null) showMessage(pendingRecordingLog)

        function forceClosing(replayResult = null) {
            browser.storage.local.get(['ptk_recording_log', 'ptk_replay_result', 'ptk_replay_last_result']).then(function (result) {
                clearTimeout(window.ptk_recording_timer)
                clearInterval(window.ptk_recording_interval)
                const terminalResult = replayResult || result.ptk_replay_result || result.ptk_replay_last_result
                const terminalMessage = replayResultMessage(terminalResult)
                const message = [result.ptk_recording_log || '', terminalMessage]
                    .filter(Boolean)
                    .join('<br/>')
                showMessage(message)
                const messageElement = document.getElementById('ptk_recording_message')
                if (!messageElement) return
                if (message) messageElement.appendChild(document.createElement('br'))
                messageElement.appendChild(document.createTextNode('Closing in: '))
                const countdown = document.createElement('span')
                countdown.id = 'ptk_recording_timer'
                countdown.textContent = '10'
                messageElement.appendChild(countdown)
                window.ptk_recording_interval = setInterval(function () {

                    var timer = document.getElementById('ptk_recording_timer')
                    if (!timer) {
                        clearInterval(window.ptk_recording_interval)
                        return
                    }
                    var val = parseInt(timer.innerText, 10)
                    if (!Number.isFinite(val)) val = 0
                    val = val - 1
                    if (val <= 0) {
                        timer.innerText = 0
                        clearInterval(window.ptk_recording_interval)
                        browser.runtime.sendMessage({
                            channel: "ptk_popup2background_recorder",
                            type: "stop_replay",
                            sessionId: activeSession.sessionId
                        }).catch(e => e)
                        return
                    }
                    timer.innerText = val
                }, 1000)
                window.ptk_recording_timer = setTimeout(function () {
                    browser.runtime.sendMessage({
                        channel: "ptk_popup2background_recorder",
                        type: "stop_replay",
                        sessionId: activeSession.sessionId
                    }).catch(e => e)
                }, 10000)
            })
        }

        window.ptk_recording_timer = null
        window.ptk_recording_interval = null

    browser.storage.onChanged.removeListener(earlyStorageListener)
    const trackerStorageListener = function (changes, namespace) {
        if (changes['ptk_recording'] || changes['ptk_replay']) {
            const recordingStopped = changes['ptk_recording']?.oldValue?.mode === 'recording'
                && !changes['ptk_recording'].newValue
            const replayStopped = changes['ptk_replay']?.oldValue?.mode === 'replay'
                && !changes['ptk_replay'].newValue
            if (recordingStopped || replayStopped) {
                const popup = document.getElementById('ptk_recording_control')
                if (popup) popup.remove()
                if (window.ptk_recording_timer) clearTimeout(window.ptk_recording_timer)
                if (window.ptk_recording_interval) clearInterval(window.ptk_recording_interval)
                window.__ptkRecordingTrackerActive = false
                browser.storage.onChanged.removeListener(trackerStorageListener)
                return
            }
        }
        if (changes['ptk_recording_log']) {
            showMessage(changes['ptk_recording_log'].newValue)
        }

            const replayResult = changes['ptk_replay_result']?.newValue
            if (replayResult && ['completed', 'failed', 'stopped'].includes(replayResult.status)) {
                forceClosing(replayResult)
                return
            }

            if (changes['ptk_replay_step']) {
                let changedValue = changes['ptk_replay_step'].newValue
                if (changedValue == -1) {
                    forceClosing()
                }
            }
        }
    browser.storage.onChanged.addListener(trackerStorageListener)
    }).catch(() => {
        browser.storage.onChanged.removeListener(earlyStorageListener)
        window.__ptkRecordingTrackerActive = false
    })
})();
