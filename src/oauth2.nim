# Copyright 2016 Yoshihiro Tanaka
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

## This module supports access to resources by OAuth 2.0.
## | Please refer to `OAuth Core 2.0<http://oauth.net/2/>`_ details.

import uri
import base64
import random
import cgi
import math
import times
import tables
import strtabs
import strutils
import asynchttpserver
import asyncdispatch
import asyncnet
import httpclient

type
    GrantType = enum
        AuthorizationCode = "authorization_code",
        Implicit,
        ResourceOwnerPassCreds = "password",
        ClientCreds = "client_credentials",
        RefreshToken = "refresh_token"

proc setRequestHeaders(headers: HttpHeaders, body: string) =
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers["Content-Length"] = $len(body)

proc getGrantUrl(url, clientId: string, grantType: GrantType,
    redirectUri, state: string, scope: openarray[string] = []): string =
    var url = url
    let parsed = parseUri(url)
    url = url & (if parsed.query == "": "?" else: "&")
    url = url & "response_type=" & (if grantType == AuthorizationCode: "code" else: "token") &
      "&client_id=" & encodeUrl(clientId) & "&state=" & state
    if len(redirectUri) > 0:
        url = url & "&redirect_uri=" & encodeUrl(redirectUri)
    if len(scope) > 0:
        url = url & "&scope=" & encodeUrl(scope.join(" "))
    result = url

proc getAuthorizationCodeGrantUrl*(url, clientId: string,
    redirectUri, state: string = "", scope: openarray[string] = []): string =
    ## Returns the URL for sending authorization requests in "Authorization Code Grant" type.
    result = getGrantUrl(url, clientId, AuthorizationCode, redirectUri, state, scope)

proc getImplicitGrantUrl*(url, clientId: string,
    redirectUri, state: string = "", scope: openarray[string] = []): string =
    ## Returns the URL for sending authorization requests in "Implicit Grant" type.
    result = getGrantUrl(url, clientId, Implicit, redirectUri, state, scope)

proc getBasicAuthorizationHeader*(clientId, clientSecret: string): HttpHeaders =
    ## Returns a header necessary to basic authentication.
    var auth = encode(clientId & ":" & clientSecret)
    auth = auth.replace("\c\L", "")
    result = newHttpHeaders({"Authorization": "Basic " & auth})

proc getBasicAuthorizationHeader(clientId, clientSecret, body: string): HttpHeaders =
    result = getBasicAuthorizationHeader(clientId, clientSecret)
    result.setRequestHeaders(body)

proc getBearerRequestHeader*(accessToken: string): HttpHeaders =
    ## Returns a header necessary to bearer request.
    result = newHttpHeaders({"Authorization": "Bearer " & accessToken})

proc getBearerRequestHeader(accessToken: string,
    extraHeaders: HttpHeaders, body: string): HttpHeaders =
    result = getBearerRequestHeader(accessToken)
    result.setRequestHeaders(body)
    if extraHeaders != nil:
      for k, v in extraHeaders.table:
        result[k] = v

proc accessTokenRequest(client: HttpClient | AsyncHttpClient,
    url, clientId, clientSecret: string,
    grantType: GrantType, useBasicAuth: bool,
    code, redirectUri, username, password, refreshToken: string = "",
    scope: seq[string] = @[]): Future[Response | AsyncResponse] {.multisync.} =
    var body = "grant_type=" & $grantType
    case grantType
    of ResourceOwnerPassCreds:
        body = body & "&username=" & username & "&password=" & password
        if len(scope) > 0:
            body = body & "&scope=" & encodeUrl(scope.join(" "))
    of AuthorizationCode:
        body = body & "&code=" & encodeUrl(code)
        if len(redirectUri) > 0:
            body = body & "&redirect_uri=" & encodeUrl(redirectUri)
    of ClientCreds:
        if len(scope) > 0:
            body = body & "&scope=" & encodeUrl(scope.join(" "))
    of RefreshToken:
        body = body & "&refresh_token=" & encodeUrl(refreshToken)
        if len(scope) > 0:
            body = body & "&scope=" & encodeUrl(scope.join(" "))
    else: discard

    var header: HttpHeaders
    if useBasicAuth:
        header = getBasicAuthorizationHeader(clientId, clientSecret, body)
    else:
        body = body & "&client_id=" & encodeUrl(clientId) & "&client_secret=" & encodeUrl(clientSecret)
        header = newHttpHeaders()
        header.setRequestHeaders(body)

    result = await client.request(url, httpMethod = HttpPOST, headers = header, body = body)

proc getAuthorizationCodeAccessToken*(client: HttpClient | AsyncHttpClient,
    url, code, clientId, clientSecret: string,
    redirectUri: string = "", useBasicAuth: bool = true): Future[Response | AsyncResponse] {.multisync.}=
    ## Send the access token request for "Authorization Code Grant" type.
    result = await client.accessTokenRequest(url, clientId, clientSecret,
        AuthorizationCode, useBasicAuth, code, redirectUri)

# ref. https://github.com/nim-lang/Nim/blob/master/lib/pure/asynchttpserver.nim#L154
proc getCallbackParamters(port: Port, html: string): Future[Uri] {.async, deprecated.} =
    let socket = newAsyncSocket()
    socket.bindAddr(port)
    socket.listen()

    proc processClient(client: AsyncSocket): Future[string] {.async.} =
        var request = Request()
        request.headers = newHttpHeaders()
        result = ""
        while not client.isClosed:
            assert client != nil
            request.client = client
            var line = await client.recvLine()
            if line == "":
                client.close()
            else:
                var url =line.split(" ")[1]
                request.url = parseUri url
                while true:
                    line = await client.recvLine()
                    if line == "\c\L":
                        break
                    let fd = line.find(":")
                    request.headers[line[0..fd-1].strip()] = line[fd+1..len(line)-1].strip()
                await request.respond(Http200, html)
                result = url
                client.close()

    var url: string
    while true:
        var fut = await socket.acceptAddr()
        url = await processClient(fut.client)
        if len(url) > 0:
            break
    result = parseUri url

proc generateState*(): string =
    var r = 0
    result = ""
    randomize()
    for i in 0..4:
        r = rand(26)
        result = result & chr(97 + r)

proc parseResponseBody(body: string): StringTableRef =
    let responses = body.split("&")
    result = newStringTable(modeCaseInsensitive)
    for response in responses:
        let fd = response.find("=")
        result[response[0..fd-1]] = response[fd+1..len(response)-1]

proc authorizationCodeGrant*(client: HttpClient | AsyncHttpClient,
    authorizeUrl, accessTokenRequestUrl, clientId, clientSecret: string,
    html: string = "", scope: seq[string] = @[],
    port: int = 8080): Future[Response | AsyncResponse] {.multisync, deprecated.} =
    ## Send a request for "Authorization Code Grant" type.
    ## | This method, outputs a URL for the authorization request at first.
    ## | Then, wait for the callback at "http://localhost:${port}".
    ## | When receiving the callback, check the state, and request an access token to the server.
    ## | Returns the request result of the access token.
    let
        state = generateState()
        redirectUri = "http://localhost:" & $port
        authorizeUrl = getAuthorizationCodeGrantUrl(authorizeUrl, clientId, redirectUri, state, scope)

    echo authorizeUrl
    let
        uri = waitFor getCallbackParamters(Port(port), html)
        params = parseResponseBody(uri.query)
    assert params["state"] == state
    result = await client.getAuthorizationCodeAccessToken(accessTokenRequestUrl, params["code"],
        clientId, clientSecret, redirectUri)

proc implicitGrant*(url, clientId: string, html: string = "",
    scope: openarray[string] = [], port: int = 8080): string {.deprecated.} =
    ## Send a request for "Implicit Grant" type.
    ## | This method, outputs a URL for the authorization request at first.
    ## | Then, wait for the callback at "http://localhost:${port}".
    ## | When receiving the callback, check the state, returns the Uri.query as a result.
    let
        state = generateState()
        redirectUri = "http://localhost:" & $port
        url = getImplicitGrantUrl(url, clientId, redirectUri, state, scope)

    echo url
    let
        uri = waitFor getCallbackParamters(Port(port), html)
        query = uri.query
        params = parseResponseBody(query)
    assert params["state"] == state
    result = query

proc resourceOwnerPassCredsGrant*(client: HttpClient | AsyncHttpClient,
    url, clientId, clientSecret, username, password: string,
    scope: seq[string] = @[],
    useBasicAuth: bool = true): Future[Response | AsyncResponse] {.multisync.} =
    ## Send a request for "Resource Owner Password Credentials Grant" type.
    ##
    ##  | The client MUST discard the credentials once an access token has been obtained.
    ##  | -- https://tools.ietf.org/html/rfc6749#section-4.3
    result = await client.accessTokenRequest(url, clientId, clientSecret, ResourceOwnerPassCreds,
        useBasicAuth, username = username, password = password, scope = scope)

proc clientCredsGrant*(client: HttpClient | AsyncHttpClient,
    url, clientid, clientsecret: string,
    scope: seq[string] = @[],
    useBasicAuth: bool = true): Future[Response | AsyncResponse] {.multisync.} =
    ## Send a request for "Client Credentials Grant" type.
    result = await client.accessTokenRequest(url, clientId, clientSecret, ClientCreds,
        useBasicAuth, scope = scope)

proc refreshToken*(client: HttpClient | AsyncHttpClient,
    url, clientId, clientSecret, refreshToken: string,
    scope: seq[string] = @[],
    useBasicAuth: bool = true): Future[Response | AsyncResponse] {.multisync.} =
    ## Send an update request of the access token.
    result = await client.accessTokenRequest(url, clientId, clientSecret, RefreshToken,
        useBasicAuth, refreshToken = refreshToken, scope = scope)

proc bearerRequest*(client: HttpClient | AsyncHttpClient,
    url, accessToken: string, httpMethod = HttpGET,
    extraHeaders: HttpHeaders = nil,
    body = ""): Future[Response | AsyncResponse] {.multisync.} =
    ## Send a request using the bearer token.
    let header = getBearerRequestHeader(accessToken, extraHeaders, body)
    result = await client.request(url, httpMethod = httpMethod, headers = header, body = body)

when defined(testing):
    # parseResponseBody test
    var
        original = "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true"
        src = parseResponseBody(original)
    assert src["oauth_token"] == "hh5s93j4hdidpola"
    assert src["oauth_token_secret"] == "hdhd0244k9j7ao03"
    assert src["oauth_callback_confirmed"] == "true"

    original = "oauth_token=6253282-eWudHldSbIaelX7swmsiHImEL4KinwaGloHANdrY&oauth_token_secret=2EEfA6BG3ly3sR3RjE0IBSnlQu4ZrUzPiYKmrkVU&user_id=6253282&screen_name=twitterapi"
    src = parseResponseBody(original)
    assert src["oauth_token"] == "6253282-eWudHldSbIaelX7swmsiHImEL4KinwaGloHANdrY"
    assert src["oauth_token_secret"] == "2EEfA6BG3ly3sR3RjE0IBSnlQu4ZrUzPiYKmrkVU"
    assert src["user_id"] == "6253282"
    assert src["screen_name"] == "twitterapi"

    original = "oauth_token=Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik&oauth_token_secret=Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM&oauth_callback_confirmed=true"
    src = parseResponseBody(original)
    assert src["oauth_token"] == "Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik"
    assert src["oauth_token_secret"] == "Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM"
    assert src["oauth_callback_confirmed"] == "true"

    # generateState test
    echo generateState()
    assert len(generateState()) == 5

    # setRequestHeaders test
    let header = newHttpHeaders()
    header.setRequestHeaders("aaaaa")
    assert len(header) == 2
    assert header["Content-Type"] == "application/x-www-form-urlencoded"
    assert header["Content-Length"] == "5"
    header.setRequestHeaders("")
    assert len(header) == 2
    assert header["Content-Length"] == "0"

when not defined(ssl):
    echo "SSL support is required."
    quit 1
