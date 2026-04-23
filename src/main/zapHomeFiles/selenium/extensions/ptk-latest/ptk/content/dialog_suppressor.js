(function () {
    try {
        window.alert = function () {}
        window.confirm = function () { return false }
        window.prompt = function () { return null }
        window.onbeforeunload = null
    } catch (_) {}
}())
