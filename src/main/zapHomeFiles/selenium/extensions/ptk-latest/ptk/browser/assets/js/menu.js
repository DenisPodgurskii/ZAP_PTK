/* Author: Denis Podgurskii */


const dashboardText = `Reload the tab to activate tracking &nbsp;<i class="exclamation red circle icon" style="font-size: 1em; margin-bottom: 1px;"></i>`



function bindTable(id, params) {
    params.paging = false
    params.ordering = false
    params.info = false
    params.searching = params.searching ? params.searching : false
    params.sorting = false
    params.dom = 'frtip'
    // Enable deferred rendering for better performance with large datasets
    params.deferRender = true

    let table
    if ($.fn.dataTable.isDataTable(id)) {
        table = $(id).DataTable()

        // Support incremental updates if keyColumn is specified
        // This avoids destroying and rebuilding the entire table
        if (params.incremental && params.keyColumn !== undefined && Array.isArray(params.data)) {
            const existingKeys = new Set()
            table.rows().every(function() {
                const data = this.data()
                if (data && data[params.keyColumn] !== undefined) {
                    existingKeys.add(data[params.keyColumn])
                }
            })

            // Only add rows that don't exist yet
            const newRows = params.data.filter(row =>
                row && !existingKeys.has(row[params.keyColumn])
            )

            if (newRows.length > 0) {
                table.rows.add(newRows).draw(false) // false = maintain scroll position
            }
        } else {
            // Full rebuild (existing behavior)
            table.clear().rows.add(params.data).draw()
        }
    } else {
        table = $(id).DataTable(params)
    }
    return table
}

jQuery(function () {

    const isIframePage = !document.getElementById('mainMenuWrapper')

    // (debug nav links removed)


    // $('.ui.sidebar')
    //     .sidebar('toggle')
    //     ;






        $('#footer_menu').prepend(
        `
        <div class=""
            style="position: fixed; bottom: -6px;  z-index:1; ">
            <a href="https://www.paypal.com/donate/?hosted_button_id=RNE87MVGX576E" target="_blank"><img
            src="assets/images/paypal.png" title="Donation" style="width: 160px;"></a>
        </div>

        <div class="ui mini message" style="height: 25px;position: fixed; bottom: 0px; right:0px; z-index:1; padding-top: 1px;padding-left: 4px; padding-right: 4px;">            
            <a href="https://www.youtube.com/channel/UCbEcTounPkV1aitE1egXfqw/" target="_blank"><i
            class="youtube big icon" title="PTK on youtube" style="margin-top: -18px;"></i></a>
            <a href="https://pentestkit.co.uk" target="_blank"><i class="globe big icon" title="PTK website"
                    style="margin-top: -18px;"></i></a>
            <a href="https://twitter.com/pentestkit" target="_blank"><i class="twitter big icon" title="PTK on Twitter"
                    style="margin-top: -18px;"></i></a>
            <a href="https://owasp.org/www-project-penetration-testing-kit/" target="_blank"><img
                    src="assets/images/owasp.png" title="PTK on OWASP" style="width: 24px; padding:1px"></a>
        </div>
  


        <!--div class="ui mini message"
            style="height: 25px;padding-top: 4px;position: fixed; bottom: -11px; left:130px; z-index:1">
            <a href="mailto:info@pentestkit.co.uk">info@pentestkit.co.uk</a>
        </div>
        <div class="ui mini message"
            style="height: 25px;padding-top: 4px;position: fixed; bottom: -11px; left:130px; z-index:1">
            <a href="mailto:info@pentestkit.co.uk">info@pentestkit.co.uk</a>
        </div>
        <div class="ui mini orange message"
            style="height: 25px;padding-top: 4px;position: fixed; bottom: -11px; left:269px; z-index:1">
            <i class="exclamation circle icon"></i><a target="_blank"
                href="https://www.true-positives.com/ptk-community">Please help us
                improve the PTK</a>
        </div>

        <div class="ui mini message"
            style="height: 25px;padding-top: 4px;position: fixed; bottom: -11px; right:100px; z-index:1">
            <div class="ui form">
                <div class=" fields">
                    <div class="eight wide field" style="margin-top: -1px;"><b style="font-size: .78571429em;">Trusted
                            by</b> &nbsp;</div>
                    <div class="four wide field ui icon right corner" style="padding-left: 10px;padding-right:0px">
                        <a href="https://www.invicti.com/" target="_blank"><img class="logo"
                                src="assets/images/invicti-logo-black.svg"
                                title="The Largest Dynamic Application Security Solutions Provider In The World"
                                style="width: 60px; margin-top: -4px;float: right;"></a>
                    </div>
                    <div class="one wide field" style="padding-left: 3px;"> <sup><i class="trademark icon"></i></sup>
                    </div>
                </div>
            </div>

        </div>

        <div class=""
            style="height: 25px;position: fixed; bottom: 3px; right:0px; z-index:1; padding-left: 4px;">
            <a href="https://www.paypal.com/donate/?hosted_button_id=RNE87MVGX576E" target="_blank"><img
            src="assets/images/paypal.png" title="Donation" style="width: 140px;"></a>
        </div-->


        `
        )
  






    if (!isIframePage) {
        if (window.opener) {
            $('#opennewwindow').hide()
        }

        //Settings page
        $('#opensettings').on('click', function () {
            $('#ptk_popup_dialog iframe').attr('src', 'settings.html')
            $('#ptk_popup_dialog').modal('show')
        })

        //Privacy page
        $('#privacy').on('click', function () {
            $('#ptk_popup_dialog iframe').attr('src', 'privacy.html')
            $('#ptk_popup_dialog').modal('show')
        })

        //Contact page
        $('#contactus').on('click', function () {
            $('#ptk_popup_dialog iframe').attr('src', 'contact.html')
            $('#ptk_popup_dialog').modal('show')
        })

        //Disclaimer page
        $('#disclaimer').on('click', function () {
            $('#ptk_popup_dialog iframe').attr('src', 'disclaimer.html')
            $('#ptk_popup_dialog').modal('show')
        })

        //Credits page
        $('#credits').on('click', function () {
            $('#ptk_popup_dialog iframe').attr('src', 'credits.html')
            $('#ptk_popup_dialog').modal('show')
        })

        //Profile page
        $('#profile').on('click', function () {
            $('#ptk_popup_dialog iframe').attr('src', 'profile.html')
            $('#ptk_popup_dialog').modal('show')
        })

        //New window
        $('#opennewwindow').on('click', function () {
            browser.windows.create({ url: window.location.href, type: "popup", width: 900, height: 650 })
            window.close();
        });

        //Reload
        $('#reloadextension').on('click', function () {
            browser.runtime.sendMessage({
                channel: "ptk_popup2background_app",
                type: "reloadptk"
            }).catch(e => e)
        });
    }

    //Semantic UI 
    $('.ui.dropdown').dropdown({ on: 'click' })
    $('.ui.checkbox').checkbox()
    $('.dropdown.allowAdditions')
        .dropdown({
            allowAdditions: true
        })

    if (!isIframePage) {
        setTimeout(function () {
            browser.runtime.sendMessage({
                channel: "ptk_popup2background_app",
                type: "release_note"
            }).then(response => {
                if (response?.show) {
                    $('#ptk_release_note').show()
                }
            })
        }, 300)

        $('.close.icon.ptk_release_note').on('click', function () {
            $('#ptk_release_note').hide()
            browser.runtime.sendMessage({
                channel: "ptk_popup2background_app",
                type: "release_note_read"
            })
        })
    }

})
