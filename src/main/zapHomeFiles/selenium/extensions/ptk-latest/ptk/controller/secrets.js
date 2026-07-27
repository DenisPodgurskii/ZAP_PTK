export class ptk_controller_secrets {
    send(type, payload = {}) {
        return browser.runtime.sendMessage({
            channel: 'ptk_popup2background_secrets',
            type,
            ...payload
        })
    }

    getStatus() {
        return this.send('get_status')
    }

    activate(activationToken) {
        return this.send('activate', { activationToken })
    }

    validate() {
        return this.send('validate')
    }

    clear() {
        return this.send('clear')
    }
}
