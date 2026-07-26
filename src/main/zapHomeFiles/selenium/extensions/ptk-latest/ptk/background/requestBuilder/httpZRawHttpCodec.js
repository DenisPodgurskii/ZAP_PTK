/* Author: Denis Podgurskii */
import { httpZ } from "../lib/httpZ.esm.js"

export class HttpZRawHttpCodec {
    parseRequest(raw, opts) {
        return Object.assign(httpZ.parse(raw, opts))
    }

    buildRequest(request, opts) {
        return httpZ.build(request, opts)
    }
}

export const requestBuilderRawHttpCodec = new HttpZRawHttpCodec()
