# Copyright 2015-2016 Yoshihiro Tanaka
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

  # http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Yoshihiro Tanaka <contact@cordea.jp>
# date  :2016-03-03

## This module supports access to resources by OAuth 1.0.
## signature method supports only HMAC-SHA1.
## | Please refer to `OAuth Core 1.0a<http://oauth.net/core/1.0a>`_ details.

import times
import math
import random
import strutils
import sha1
import base64
import uri
import tables
import algorithm
import sequtils
import asyncdispatch
import httpclient

const 
    signatureMethod = "HMAC-SHA1"
    version = "1.0"

type
    OAuth1Parameters* = ref object
        realm*, consumerKey*, nonce*, signature*, signatureMethod*, timestamp*, token*, callback*, verifier*: string
        isIncludeVersionToHeader*: bool

# ref. https://github.com/nim-lang/Nim/blob/master/lib/pure/cgi.nim#L34.
proc percentEncode*(str: string): string =
    ## Escape the character by using the percent encoding.
    result = ""
    for s in str:
        case s
        of 'a'..'z', 'A'..'Z', '0'..'9', '-', '.', '_', '~':
            result = result & s
        else:
            result = result & '%' & toHex(ord s, 2)

# ref.
# https://www.ietf.org/rfc/rfc2104.txt
# https://github.com/OpenSystemsLab/hmac.nim/blob/master/hmac.nim#L41-L63
proc hmacSha1(key, text: string): string =
    const
        blockLength  = 64
        ipadByte: uint8 = 0x36
        opadByte: uint8 = 0x5C
        zeroByte: uint8 = 0x00

    var
        byte: seq[uint8]  = @[]
        ipad: string = ""
        opad: string = ""

    if len(key) > blockLength:
        for b in compute(key):
            byte.add b
    else:
        for k in key:
            byte.add k.uint8

    for _ in 0..(blockLength - len(byte) - 1):
        byte.add zeroByte

    assert len(byte) == blockLength

    for i in 0..len(byte) - 1:
        ipad = ipad & char(byte[i] xor ipadByte)
        opad = opad & char(byte[i] xor opadByte)

    for b in compute(ipad & text):
        opad = opad & char(b)

    result = compute(opad).toBase64

proc createNonce(): string =
    ## Generate a nonce of 32byte.
    let epoch = $epochTime()
    var
        rst = ""
        r = 0

    randomize()
    for i in 0..(23 - len(epoch)):
        r = rand(26)
        rst = rst & chr(97 + r)

    result = encode(rst & epoch)

proc toArray(params: OAuth1Parameters): seq[array[2, string]] =
    result = @[]
    result.add(["oauth_consumer_key", params.consumerKey])
    result.add(["oauth_nonce", params.nonce])
    result.add(["oauth_signature_method", params.signatureMethod])
    result.add(["oauth_timestamp", $params.timestamp])
    if params.isIncludeVersionToHeader:
        result.add(["oauth_version", version])
    if len(params.callback) > 0:
        result.add(["oauth_callback", params.callback])
    if len(params.token) > 0:
        result.add(["oauth_token", params.token])
    if len(params.verifier) > 0:
        result.add(["oauth_verifier", params.verifier])

proc parameterNormarization(parameters: seq[array[2, string]]): string =
    var
        parameters = parameters
        joinParams: seq[string] = @[]

    parameters.sort do (x, y: array[2, string]) -> int:
        result = cmp(x[0], y[0])
        if result == 0:
            result = cmp(x[1], y[1])

    for p in parameters:
        joinParams.add(p[0] & "=" & p[1])

    result = joinParams.join "&"

iterator parseQuery(queries: string): array[2, string] =
    for r in queries.split("&"):
        if r.contains "=":
            let fd = r.find("=")
            yield [r[0..fd-1], r[fd+1..len(r)-1]]

proc getSignatureBaseString(httpMethod: HttpMethod, url, body: string,
    params: OAuth1Parameters): string =
    ## Generate a signature base string.
    var url = url
    var requests: seq[array[2, string]] = params.toArray()
    requests = requests.map(proc (x: array[2, string]): array[2, string] =
        [percentEncode(x[0]), percentEncode(x[1])])

    let parsed = parseUri(url)
    if parsed.port == "":
        url = parsed.scheme & "://" & parsed.hostname & parsed.path
    else:
        url = parsed.scheme & "://" & parsed.hostname & ":" & parsed.port & parsed.path
    let queries = parsed.query

    for r in queries.parseQuery():
        requests.add(r)
    for r in body.parseQuery():
        requests.add(r)

    let param = parameterNormarization(requests)
    result = $httpMethod & "&" & percentEncode(url) & "&" & percentEncode(param)

proc getSignatureKey(consumerKey: string, token: string): string =
    ## Generate a signature key.
    result = percentEncode(consumerKey) & "&" & percentEncode(token)

proc getSignature*(HttpMethod: HttpMethod, url, body: string,
    params: OAuth1Parameters, consumerKey, token: string): string =
    ## Generate a signature.
    let
        signatureKey = getSignatureKey(consumerKey, token)
        signatureBaseString = getSignatureBaseString(HttpMethod, url, body, params)

    result = hmacSha1(signatureKey, signatureBaseString)

proc getOAuth1RequestHeader*(params: OAuth1Parameters, extraHeaders: HttpHeaders = nil): HttpHeaders =
    ## Generate the necessary header to a OAuth1 request.
    result = newHttpHeaders()
    result["Content-Type"] = "application/x-www-form-urlencoded"
    var oauth: string
    if len(params.realm) > 0:
        oauth = "OAuth realm=\"" & params.realm & "\", "
    else:
        oauth = "OAuth "
    oauth = oauth & "oauth_consumer_key=\"" & params.consumerKey & "\", oauth_signature_method=\"" &
      params.signatureMethod & "\", oauth_timestamp=\"" & params.timestamp & "\", oauth_nonce=\"" &
      params.nonce & "\", oauth_signature=\"" & params.signature & "\""
    if len(params.token) > 0:
        oauth = oauth & ", oauth_token=\"" & params.token & "\""
    if len(params.callback) > 0:
        oauth = oauth & ", oauth_callback=\"" & percentEncode(params.callback) & "\""
    if len(params.verifier) > 0:
        oauth = oauth & ", oauth_verifier=\"" & params.verifier & "\""
    if params.isIncludeVersionToHeader:
        oauth = oauth & ", oauth_version=\"" & version & "\""
    result["Authorization"] = oauth
    if extraHeaders != nil:
      for k, v in extraHeaders.table:
        result[k] = v

proc oAuth1Request(client: HttpClient | AsyncHttpClient,
    url, consumerKey, consumerSecret: string,
    callback, token, verifier: string = "", tokenSecret = "",
    isIncludeVersionToHeader = false, httpMethod = HttpGET,
    extraHeaders: HttpHeaders = nil, body = "",
    nonce: string = "", realm: string = ""): Future[Response | AsyncResponse] {.multisync.} =
    let
        timestamp = int(round(epochTime()))
        nonce = if len(nonce) == 0: createNonce() else: nonce
        params = OAuth1Parameters(
            realm: realm,
            consumerKey: consumerKey,
            nonce: nonce,
            signatureMethod: signatureMethod,
            timestamp: $timestamp,
            isIncludeVersionToHeader: isIncludeVersionToHeader,
            callback: callback,
            token: token,
            verifier: verifier
        )
        signature = getSignature(httpMethod, url, body, params, consumerSecret, tokenSecret)

    params.signature = percentEncode(signature)
    let header = getOAuth1RequestHeader(params, extraHeaders)
    result = await client.request(url, httpMethod = httpMethod, headers = header, body = body)

proc getOAuth1RequestToken*(client: HttpClient | AsyncHttpClient,
    url, consumerKey, consumerSecret: string,
    callback = "oob", isIncludeVersionToHeader = false,
    httpMethod = HttpPOST, extraHeaders: HttpHeaders = nil, body = "",
    realm: string = "", nonce: string = ""): Future[Response | AsyncResponse] {.multisync.} =
    ## A temporary credential requests.
    ## You will receive a request token. Not the access token.
    ##
    ## | If ``relam`` parameter is not empty, add the ``realm`` to the header.
    ## | If the ``nonce`` is empty, ``nonce`` is generated by ``createNonce``.
    ## | If ``isIncludeVersionToHeader`` is ``true``, including the ``oauth_version`` in the header.
    ## | If the client can not receive a ``callback``, set "oob" to ``callback``.
    result = await client.oAuth1Request(url, consumerKey, consumerSecret,
        callback, "", "", "", isIncludeVersionToHeader,
        httpMethod, extraHeaders, body, realm, nonce)

proc getAuthorizeUrl*(url, requestToken: string): string =
    ## It returns the url for authentication.
    ## This URL may need to access by such as a browser.
    result = url & "?oauth_token=" & requestToken

proc getOAuth1AccessToken*(client: HttpClient | AsyncHttpClient,
    url, consumerKey, consumerSecret,
    requestToken, requestTokenSecret, verifier: string,
    isIncludeVersionToHeader = false, httpMethod = HttpPOST,
    extraHeaders: HttpHeaders = nil, body = "",
    nonce: string = "", realm: string = ""): Future[Response | AsyncResponse] {.multisync.} =
    ## Get the access token.
    result = await client.oAuth1Request(url, consumerKey, consumerSecret,
        "", requestToken, verifier, requestTokenSecret,
        isIncludeVersionToHeader, httpMethod, extraHeaders, body, nonce, realm)

proc oAuth1Request*(client: HttpClient | AsyncHttpClient,
    url, consumerKey, consumerSecret, token, tokenSecret: string,
    isIncludeVersionToHeader = false, httpMethod = HttpGET,
    extraHeaders: HttpHeaders = nil, body = "",
    nonce: string = "", realm: string = ""): Future[Response | AsyncResponse] {.multisync.} =
    ## Send an authenticated request to access a protected resource.
    result = await client.oAuth1Request(url, consumerKey, consumerSecret,
        "", token, "", tokenSecret,
        isIncludeVersionToHeader, httpMethod, extraHeaders, body, nonce, realm)

when defined(testing):
    # Create nonce
    assert len(createNonce()) == 32

when not defined(ssl):
    echo "SSL support is required."
    quit 1
