/* Author: Denis Podgurskii */
import { ptk_decoder } from "../../../background/decoder.js"
const decoder = new ptk_decoder()


jQuery(function () {

    let params = new URLSearchParams(window.location.search)
    if (params.has('s')) {
        let content = decoder.base64url_decode(params.get('s'))

        // console.log(content)
        $('#showhtmlFrame').prop('srcdoc', decodeURI(content))

    }


})