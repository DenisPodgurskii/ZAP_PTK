(() => {
    function bindRecordingPopupDrag() {
        const control = document.getElementById('ptk_recording_control')
        const handle = document.getElementById('ptk_recording_control_icons')
        if (!control || !handle) return false
        if (handle.dataset.ptkDragBound === 'true') return true

        handle.dataset.ptkDragBound = 'true'
        let moving = false
        const offset = { x: 0, y: 0 }

        function mouseUp() {
            moving = false
            window.removeEventListener('mousemove', popupMove, true)
            window.removeEventListener('mouseup', mouseUp, true)
        }

        function mouseDown(event) {
            if (!control.isConnected) return
            moving = true
            offset.x = event.clientX - control.offsetLeft
            offset.y = event.clientY - control.offsetTop
            window.addEventListener('mousemove', popupMove, true)
            window.addEventListener('mouseup', mouseUp, true)
        }

        function popupMove(event) {
            if (!moving || !control.isConnected) {
                mouseUp()
                return
            }
            control.style.position = 'fixed'
            control.style.top = `${event.clientY - offset.y}px`
            control.style.left = `${event.clientX - offset.x}px`
        }

        handle.addEventListener('mousedown', mouseDown, false)
        return true
    }

    // tracker.js creates the overlay asynchronously after reading extension
    // storage. Expose an idempotent binder so either injection order is safe:
    // popup.js binds immediately when the DOM already exists, while tracker.js
    // calls the same function after appending a newly-created overlay.
    window.__ptkBindRecordingPopupDrag = bindRecordingPopupDrag
    bindRecordingPopupDrag()
})()
