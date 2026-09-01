/* Author: Denis Podgurskii */

import { ptk_controller_macro } from '../../../controller/macro.js'
import { PTK_FLOW_LIMITS } from '../../../background/macro/flow.js'

const controller = new ptk_controller_macro()
const extensionOrigin = window.location.origin

jQuery(function () {
    if ($('.menu .item[data-tab]').length) $('.menu .item').tab()

    const editor = CodeMirror.fromTextArea(document.getElementById('recording_output'), {
        lineNumbers: true,
        lineWrapping: true,
        mode: 'application/xml',
        indentUnit: 3,
        scrollbarStyle: null,
        extraKeys: { 'Ctrl-Y': (cm) => cm.foldCode(cm.getCursor()) },
        foldGutter: true,
        gutters: ['CodeMirror-linenumbers', 'CodeMirror-foldgutter']
    })
    editor.setSize('auto', '100%')

    const $form = $('#macro_form')
    const formats = controller.formats()
    const formatById = new Map(formats.map((format) => [format.id, format]))
    const importFormats = formats.filter((format) => format.canImport)
    let waiting = true
    let applyingEditor = false
    let editorInvalid = false
    let editorTimer = null
    let currentSerialization = null
    let pendingImportText = ''
    let pendingImportFileName = ''

    function showError(message) {
        $('#macro_error_message').text(String(message || 'Operation failed'))
        $('.mini.modal.error').modal('show')
    }

    function currentFormatId() {
        const selected = String(controller.settings.export_format || controller.settings.format || 'xml')
        return formatById.has(selected) ? selected : 'xml'
    }

    function setEditor(text, format) {
        applyingEditor = true
        editor.setOption('mode', format?.editorMode || 'text/plain')
        editor.setOption('readOnly', format?.readOnly ? 'nocursor' : false)
        editor.setValue(String(text || ''))
        applyingEditor = false
        editorInvalid = false
    }

    function diagnosticText(diagnostics = []) {
        return diagnostics.map((entry) => {
            const prefix = entry.level === 'error' ? 'Error' : entry.level === 'warning' ? 'Warning' : 'Info'
            const step = entry.stepId ? ` (${entry.stepId})` : ''
            return `${prefix}${step}: ${entry.message}`
        }).join('\n')
    }

    function exportSummaryText(summary) {
        if (!summary) return ''
        const parts = [
            `${summary.sourceSteps} source ${summary.sourceSteps === 1 ? 'step' : 'steps'}`,
            `${summary.preservedSteps} ${summary.preservedSteps === 1 ? 'step' : 'steps'} preserved`
        ]
        if (summary.requiredOmitted) parts.push(`${summary.requiredOmitted} required omitted`)
        if (summary.optionalOmitted) parts.push(`${summary.optionalOmitted} optional ${summary.optionalOmitted === 1 ? 'helper' : 'helpers'} omitted`)
        if (summary.disabledOmitted) parts.push(`${summary.disabledOmitted} disabled omitted`)
        if (summary.informationalOmitted) parts.push(`${summary.informationalOmitted} ${summary.informationalOmitted === 1 ? 'note' : 'notes'} omitted`)
        return parts.join(' · ')
    }

    function renderExportDiagnosticDetails(serialization = null) {
        const groups = Array.isArray(serialization?.diagnosticGroups) ? serialization.diagnosticGroups : []
        const summary = exportSummaryText(serialization?.summary)
        $('.macro_export_dialog_summary').text(summary).toggle(Boolean(summary))
        const $container = $('.macro_export_dialog_groups').empty()
        groups.forEach((group) => {
            const label = group.level === 'error' ? 'Error' : group.level === 'warning' ? 'Warning' : 'Info'
            const type = group.stepType === 'workflow' ? 'workflow' : `${group.stepType} ${group.count === 1 ? 'step' : 'steps'}`
            const $group = $('<div class="macro_export_diagnostic_group"></div>')
            $group.append($('<div class="macro_export_diagnostic_title"></div>')
                .text(`${label} · ${group.count} ${type}: ${group.message}`))
            if (group.visibleStepIds?.length) {
                $group.append($('<div class="macro_export_diagnostic_steps"></div>')
                    .text(`Steps: ${group.visibleStepIds.join(', ')}`))
            }
            if (group.hiddenStepIds?.length) {
                const $details = $('<details class="macro_export_diagnostic_details"></details>')
                $details.append($('<summary></summary>').text(`Show ${group.hiddenStepIds.length} more step IDs`))
                $details.append($('<div></div>').text(group.hiddenStepIds.join(', ')))
                $group.append($details)
            }
            $container.append($group)
        })
    }

    function showExportDiagnostics(serialization = null) {
        const $message = $('.macro_export_diagnostics')
        const diagnostics = Array.isArray(serialization?.diagnostics) ? serialization.diagnostics : []
        const hasError = diagnostics.some((entry) => entry.level === 'error')
        if (!hasError) {
            $message.hide().text('')
            renderExportDiagnosticDetails()
            return
        }
        renderExportDiagnosticDetails(serialization)
        $message.text('Export blocked. See details').show()
    }

    function updateElementPathState() {
        const imported = controller.usesImportedLocators()
        const $controls = $('.macro_element_path_controls input[name="element_path"]')
        $controls.prop('disabled', imported)
        $controls.closest('.checkbox').toggleClass('disabled', imported)
        $('.macro_element_path_lock').toggle(imported)
        $('.macro_element_path_controls').toggleClass('disabled', imported)
    }

    function updateActionState() {
        const exportErrors = currentSerialization?.diagnostics?.some((entry) => entry.level === 'error') === true
        const empty = !controller.flow?.steps?.length
        $('.macro_download').toggleClass('disabled', editorInvalid || exportErrors || empty)
        $('.macro_replay, .macro_replay_clean_cookie').toggleClass('disabled', editorInvalid || empty)
        $('.content .segment').dimmer(empty ? 'show' : 'hide')
    }

    function renderRuntimeSecrets() {
        const $container = $('.macro_runtime_secrets').empty()
        const names = (controller.flow?.variables || []).filter((entry) => entry.secret).map((entry) => entry.name)
        if (!names.length) return
        const missing = names.filter((name) => !Object.prototype.hasOwnProperty.call(controller.secrets, name))
        if (!missing.length) {
            $container.append($('<div class="ui tiny positive message"></div>')
                .text('Explicit runtime references are ready for this session.'))
            return
        }
        $container.append($('<div class="ui tiny header"></div>').text('Required runtime secrets'))
        missing.forEach((name) => {
            const $field = $('<div class="field macro_runtime_secret"></div>')
            const $label = $('<label></label>').attr('data-secret-label', name).text(name)
            const $input = $('<input type="password" autocomplete="off" />')
                .attr('data-secret-name', name)
                .attr('placeholder', 'Required before replay')
            $field.append($label, $input)
            $container.append($field)
        })
    }

    async function persistFlow() {
        if (!controller.flow) return
        const response = await controller.save()
        if (response?.success === false) throw new Error(response.error || 'Could not save macro')
        $(document).trigger('saved')
    }

    async function renderCurrent({ save = false } = {}) {
        if (!controller.flow) {
            currentSerialization = null
            setEditor('', formatById.get(currentFormatId()))
            showExportDiagnostics()
            updateElementPathState()
            renderRuntimeSecrets()
            updateActionState()
            return
        }
        const result = controller.export()
        currentSerialization = result
        setEditor(result.text, formatById.get(result.format))
        showExportDiagnostics(result)
        updateElementPathState()
        renderRuntimeSecrets()
        $(document).trigger('check_macro')
        updateActionState()
        if (save) await persistFlow()
    }

    function populateFormats() {
        const $export = $('#macro_export_format').empty()
        formats.filter((format) => format.canExport).forEach((format) => {
            $('<option></option>').attr('value', format.id).text(format.label).appendTo($export)
        })
        const $import = $('#macro_import_format').empty()
        $('<option value="auto">Auto-detect</option>').appendTo($import)
        importFormats.forEach((format) => {
            $('<option></option>').attr('value', format.id).text(format.label).appendTo($import)
        })
        $('.ui.dropdown').dropdown()
    }

    $form.form({
        inline: true,
        selector: {
            field: 'input[name]:not(.search):not([type="reset"]):not([type="button"]):not([type="submit"]), textarea[name], select[name]'
        },
        fields: {
            url: {
                identifier: 'url',
                rules: [{
                    prompt: 'URL is required in the format http://example.com or https://127.0.0.1',
                    type: 'regExp',
                    value: /^https?:\/\/[A-Za-z0-9._~%!$&'()*+,;=:@\-[\]]+(?::[0-9]+)?(?:[/?#].*)?$/i
                }]
            }
        }
    })

    controller.init().then(async (result) => {
        await controller.getSettings()
        controller.settings.event_type = 'driverclick'
        const requestedFormat = controller.settings.export_format || controller.settings.format || 'xml'
        controller.settings.export_format = formatById.has(requestedFormat) ? requestedFormat : 'xml'
        controller.settings.format = controller.settings.export_format
        populateFormats()
        $('#macro_export_format').val(controller.settings.export_format)
        const restored = controller.restore(result)
        $(document).trigger('init_form')
        await renderCurrent({ save: restored.source === 'xml' })
        waiting = false
        $('.loader.macro').hide()
    }).catch((error) => {
        waiting = false
        $('.loader.macro').hide()
        showError(error?.message || error)
    })

    $('.start, .start_clean_cookie').on('click', function () {
        $form.form('validate form')
        if (!$form.form('is valid')) return
        try {
            const url = new URL($form.form('get value', 'url'))
            if (url.protocol !== 'http:' && url.protocol !== 'https:') throw new Error('URL must use HTTP or HTTPS')
            controller.start(this.attributes['data-value'].value === 'true', url.toString())
        } catch (error) {
            showError(`Could not start recording: ${error.message}`)
        }
    })

    $('.reset_recording').on('click', async function () {
        const values = $form.form('get values')
        controller.flow = null
        controller.recording = null
        controller.flowOrigin = 'empty'
        controller.secrets = Object.create(null)
        controller.pendingImport = null
        currentSerialization = null
        $('form').form('reset')
        $form.form('set value', 'url', values.url)
        $('#macro_export_format').val(currentFormatId())
        $('.iframeSign').removeClass('display')
        await controller.reset()
        await renderCurrent()
    })

    $(document).on('init_form', function () {
        browser.tabs.query({ currentWindow: true, active: true }).then((tabs) => {
            const tab = tabs[0]
            if (tab?.url && !tab.url.startsWith('chrome://')) {
                $form.form('set value', 'url', tab.url)
                window.parent.postMessage({ channel: 'ptk_recording_url', url: tab.url }, extensionOrigin)
            }
        })
        $form.form('set value', 'element_path', controller.settings.element_path)
        $form.form('set value', 'min_duration', controller.settings.min_duration)
        $form.form('set value', 'enable_extra_delay', controller.settings.enable_extra_delay)
        updateElementPathState()
        $('.content .segment').dimmer(controller.flow?.steps?.length ? 'hide' : 'show')
    })

    $(document).on('saved', function () {
        $('.savedMacro').fadeIn().addClass('display')
        setTimeout(() => $('.savedMacro').fadeOut('slow', function () { $(this).removeClass('display') }), 2500)
    })

    $(document).on('check_macro', function () {
        const hasFrames = controller.flow?.steps?.some((step) => step.frameChain?.length)
        $('.iframeSign').toggleClass('display', hasFrames === true)
    })

    $('#macro_export_format').on('change', async function () {
        const format = String(this.value || 'xml')
        if (!formatById.has(format)) return
        controller.settings.export_format = format
        controller.settings.format = format
        if (waiting) return
        try {
            await controller.updateSettings()
            await renderCurrent()
        } catch (error) {
            showError(error?.message || error)
        }
    })

    $(document).on('click', '.macro_export_diagnostics', function () {
        $('#macroExportDiagnosticsDialog').modal('show')
    })

    $(document).on('keydown', '.macro_export_diagnostics', function (event) {
        if (event.key !== 'Enter' && event.key !== ' ') return
        event.preventDefault()
        $('#macroExportDiagnosticsDialog').modal('show')
    })

    $(document).on('change', '[name="enable_extra_delay"],[name="element_path"],[name="min_duration"]', async function (event) {
        if (event.target.name === 'element_path' && controller.usesImportedLocators()) return
        const values = $form.form('get values')
        controller.settings[event.target.name] = values[event.target.name]
        controller.settings.enable_extra_delay = values.enable_extra_delay === 'on'
        if (waiting) return
        try {
            await controller.updateSettings()
            if (controller.recording?.items) controller.setRecording(controller.recording)
            await renderCurrent({ save: true })
        } catch (error) {
            showError(error?.message || error)
        }
    })

    editor.on('change', () => {
        if (applyingEditor || waiting) return
        clearTimeout(editorTimer)
        const format = formatById.get(currentFormatId())
        if (!format?.canImport || format.readOnly) return
        editorTimer = setTimeout(async () => {
            try {
                const imported = controller.updateFromText(editor.getValue(), format.id)
                if (!imported.acceptable) throw new Error(diagnosticText(imported.diagnostics))
                editorInvalid = false
                currentSerialization = controller.export()
                showExportDiagnostics(currentSerialization)
                updateElementPathState()
                renderRuntimeSecrets()
                updateActionState()
                await persistFlow()
            } catch (error) {
                editorInvalid = true
                showExportDiagnostics({
                    diagnostics: [{ level: 'error', message: error?.message || String(error) }],
                    diagnosticGroups: [{
                        level: 'error', code: 'invalid_editor_document', stepType: 'workflow',
                        message: error?.message || String(error), count: 1,
                        visibleStepIds: [], hiddenStepIds: []
                    }]
                })
                updateActionState()
            }
        }, 500)
    })

    $(document).on('input', '.macro_runtime_secret input', function () {
        const name = String($(this).attr('data-secret-name') || '')
        if (!name) return
        if (this.value) controller.secrets[name] = this.value
        else delete controller.secrets[name]
        const ready = Object.prototype.hasOwnProperty.call(controller.secrets, name)
        $(this).closest('.field').find('[data-secret-label]').text(`${name}${ready ? ' — ready for this session' : ''}`)
    })

    function resetImportDialog() {
        pendingImportText = ''
        pendingImportFileName = ''
        controller.cancelImport()
        $('#macrofileimport').val('')
        $('#macro_import_format').dropdown('set selected', 'auto')
        $('#macro_import_scope_confirm').prop('checked', false)
        $('.macro_import_summary, .macro_import_diagnostics, .macro_import_scope').hide()
        $('.macro_import_summary, .macro_import_diagnostics, .macro_import_origin').text('')
        $('.macro_import_secrets').empty().append($('<div class="ui tiny warning message"></div>')
            .text('Macro files may contain credentials. Store and share them securely.'))
        $('.macro_import_accept').addClass('disabled')
        $('#importerrordlg').hide()
        $('#importerrormsg').text('')
    }

    function updateImportAccept() {
        const accepted = controller.pendingImport?.acceptable === true
            && $('#macro_import_scope_confirm').prop('checked') === true
        $('.macro_import_accept').toggleClass('disabled', !accepted)
    }

    function showImportResult(result) {
        const counts = new Map()
        result.flow.steps.forEach((step) => counts.set(step.type, (counts.get(step.type) || 0) + 1))
        const disabled = result.flow.steps.filter((step) => !step.enabled).length
        const summary = [
            `Format: ${result.formatLabel}${result.flow.metadata?.sourceVersion ? ` (${result.flow.metadata.sourceVersion})` : ''}`,
            `Start URL: ${result.flow.startUrl || 'Missing'}`,
            `Steps: ${result.flow.steps.length}${disabled ? ` (${disabled} disabled)` : ''}`,
            `Types: ${[...counts.entries()].map(([type, count]) => `${type} ${count}`).join(', ') || 'none'}`
        ].join('\n')
        $('.macro_import_summary').text(summary).show()
        const diagnostics = diagnosticText(result.diagnostics)
        $('.macro_import_diagnostics').text(diagnostics).toggle(Boolean(diagnostics))
        $('.macro_import_secrets').empty()
        const secretNames = result.flow.variables.filter((entry) => entry.secret).map((entry) => entry.name)
        if (secretNames.length) {
            const supplied = secretNames.filter((name) => Object.prototype.hasOwnProperty.call(result.secretValues || {}, name))
            const missing = secretNames.filter((name) => !Object.prototype.hasOwnProperty.call(result.secretValues || {}, name))
            if (supplied.length) {
                $('.macro_import_secrets').append($('<div class="ui tiny positive message"></div>')
                    .text('Explicit runtime references supplied by this file are ready for this session.'))
            }
            if (missing.length) {
                $('.macro_import_secrets').append($('<div class="ui tiny header"></div>').text('Required runtime secrets'))
            }
            missing.forEach((name) => {
                const $field = $('<div class="field"></div>')
                $field.append($('<label></label>').text(name))
                $field.append($('<input type="password" autocomplete="off" class="macro_import_secret" />').attr('data-secret-name', name).attr('placeholder', 'Required before replay'))
                $('.macro_import_secrets').append($field)
            })
        }
        $('.macro_import_secrets').append($('<div class="ui tiny warning message"></div>')
            .text('Macro files may contain credentials. Store and share them securely.'))
        let origin = 'No executable HTTP/HTTPS start URL'
        try { origin = new URL(result.flow.startUrl).origin } catch (_) { }
        $('.macro_import_origin').text(`Target scope: ${origin}`)
        $('.macro_import_scope').show()
        updateImportAccept()
    }

    function parsePendingImport() {
        if (!pendingImportText) return
        try {
            const selected = String($('#macro_import_format').val() || 'auto')
            const result = controller.prepareImport(pendingImportText, { format: selected, fileName: pendingImportFileName })
            $('#macro_import_format').dropdown('set selected', result.format)
            $('#importerrordlg').hide()
            showImportResult(result)
        } catch (error) {
            controller.cancelImport()
            $('#importerrormsg').text(error?.message || String(error))
            $('#importerrordlg').show()
            $('.macro_import_accept').addClass('disabled')
        }
    }

    $('.import_recording').on('click', function () {
        resetImportDialog()
        $('#dialogImportRecording').modal({ closable: true, onHidden: () => controller.cancelImport() }).modal('show')
    })

    function loadImportFile(file) {
        if (!file) return
        if (file.size > PTK_FLOW_LIMITS.maxInputBytes) {
            $('#importerrormsg').text('The selected file exceeds the 10 MiB import limit')
            $('#importerrordlg').show()
            $('.macro_import_accept').addClass('disabled')
            return
        }
        pendingImportFileName = file.name
        const reader = new FileReader()
        reader.onload = () => {
            pendingImportText = String(reader.result || '')
            $('#macro_import_format').dropdown('set selected', 'auto')
            parsePendingImport()
        }
        reader.onerror = () => {
            $('#importerrormsg').text('Could not read the selected file')
            $('#importerrordlg').show()
        }
        reader.readAsText(file)
    }

    $('#macrofileimport').on('change', function (event) {
        loadImportFile(event.target.files?.[0])
    })

    $('.macro_import_drop_zone').on('dragenter dragover', function (event) {
        event.preventDefault()
        event.originalEvent.dataTransfer.dropEffect = 'copy'
        $(this).addClass('primary')
    }).on('dragleave', function () {
        $(this).removeClass('primary')
    }).on('drop', function (event) {
        event.preventDefault()
        $(this).removeClass('primary')
        loadImportFile(event.originalEvent.dataTransfer?.files?.[0])
    })

    $('#macro_import_format').on('change', function () { if (pendingImportText) parsePendingImport() })
    $('#macro_import_scope_confirm').on('change', updateImportAccept)
    $('.macro_import_cancel').on('click', function () { $('#dialogImportRecording').modal('hide') })
    $('.macro_import_accept').on('click', async function () {
        if ($(this).hasClass('disabled') || !controller.pendingImport) return
        try {
            const secrets = Object.create(null)
            $('.macro_import_secret').each(function () {
                const name = String($(this).attr('data-secret-name') || '')
                if (name && this.value) secrets[name] = this.value
            })
            const imported = controller.acceptImport(secrets)
            if (imported.flow.startUrl) $form.form('set value', 'url', imported.flow.startUrl)
            $('#dialogImportRecording').modal('hide')
            await renderCurrent({ save: true })
        } catch (error) {
            $('#importerrormsg').text(error?.message || String(error))
            $('#importerrordlg').show()
        }
    })

    $('.macro_replay, .macro_replay_clean_cookie').on('click', function () {
        if ($(this).hasClass('disabled')) return
        try {
            const { startUrl, events } = controller.compile()
            if (!startUrl || !events.length) throw new Error('Recorded macro is empty. Record or import a macro before replay.')
            const values = $form.form('get values')
            controller.replay(this.attributes['data-value'].value === 'true', startUrl, events, values.enable_regex === 'on' ? values.validate_regex : null)
        } catch (error) {
            showError(error?.message || error)
        }
    })

    $('.macro_download').on('click', function () {
        if ($(this).hasClass('disabled')) return
        try {
            const result = controller.export()
            if (!result?.text || result.diagnostics.some((entry) => entry.level === 'error')) {
                throw new Error(diagnosticText(result?.diagnostics || []) || 'The macro cannot be exported in this format')
            }
            const blob = new Blob([result.text], { type: result.mimeType })
            const objectUrl = window.URL.createObjectURL(blob)
            const link = document.createElement('a')
            link.download = controller.downloadName(result.format)
            link.href = objectUrl
            link.click()
            setTimeout(() => window.URL.revokeObjectURL(objectUrl), 0)
        } catch (error) {
            showError(error?.message || error)
        }
    })

    window.__ptkMacroRefresh = async (recording) => {
        controller.setRecording(recording)
        await renderCurrent({ save: true })
    }

    $('.question').popup()
    $('.ui.accordion').accordion()
})

window.addEventListener('message', function (msg) {
    if (msg.origin !== extensionOrigin || msg.source !== window.parent) return
    if (msg.data?.channel === 'ptk_recording_url' && typeof msg.data.url === 'string') $('[name="url"]').val(msg.data.url)
})

browser.runtime.onMessage.addListener(function (message) {
    if (message.channel === 'ptk_background2popup_recorder' && message.type === 'recording_completed') {
        window.__ptkMacroRefresh?.(message.recording).catch(() => {})
    }
})
