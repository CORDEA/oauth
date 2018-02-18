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

import uri, base64
import random, math, times
import asynchttpserver, asyncdispatch, asyncnet
import httpclient, cgi
import subexes, strtabs, strutils

type
    GrantType = enum
        AuthorizationCode = "authorization_code",
        Implicit,
        ResourceOwnerPassCreds = "password",
        ClientCreds = "client_credentials",
        RefreshToken = "refresh_token"

proc concatHeader(h0, h1: string): string =
    result = ""
    for h in @[h0, h1]:
        result = result & h
        if len(h) > 0 and not h.endsWith("\c\L"):
            result = result & "\c\L"

proc createRequestHeader(extraHeaders: string, body: string): string =
    result = "Content-Type: application/x-www-form-urlencoded\c\L"
    result = "$#Content-Length: $#\c\L" % [ result, $len(body) ]
    result = concatHeader(result, extraHeaders)

proc getGrantUrl(url, clientId: string, grantType: GrantType,
    redirectUri, state: string, scope: openarray[string] = []): string = 
    var url = url
    let parsed = parseUri(url)
    url = url & (if parsed.query == "": "?" else: "&")
    url = url & subex("response_type=$#&client_id=$#&state=$#") % [ (if grantType == AuthorizationCode: "code" else: "token"), encodeUrl(clientId), state ]
    if redirectUri != nil:
        url = url & subex("&redirect_uri=$#") % [ encodeUrl(redirectUri) ]
    if len(scope) != 0:
        url = url & subex("&scope=$#") % [ encodeUrl(scope.join(" ")) ]
    result = url

proc getAuthorizationCodeGrantUrl*(url, clientId: string,
    redirectUri, state: string = nil, scope: openarray[string] = []): string =
    ## Returns the URL for sending authorization requests in "Authorization Code Grant" type.
    result = getGrantUrl(url, clientId, AuthorizationCode, redirectUri, state, scope)

proc getImplicitGrantUrl*(url, clientId: string,
    redirectUri, state: string = nil, scope: openarray[string] = []): string =
    ## Returns the URL for sending authorization requests in "Implicit Grant" type.
    result = getGrantUrl(url, clientId, Implicit, redirectUri, state, scope)

proc getBasicAuthorizationHeader*(clientId, clientSecret: string): string =
    ## Returns a header necessary to basic authentication.
    var auth = encode(clientId & ":" & clientSecret)
    auth = auth.replace("\c\L", "")
    result = "Authorization: Basic " & auth & "\c\L"

proc getBasicAuthorizationHeader(clientId, clientSecret, body: string): string =
    let header = getBasicAuthorizationHeader(clientId, clientSecret)
    result = createRequestHeader(header, body)

proc getBearerRequestHeader*(accessToken: string): string =
    ## Returns a header necessary to bearer request.
    result = "Authorization: Bearer " & accessToken  & "\c\L"

proc getBearerRequestHeader(accessToken, extraHeaders, body: string): string =
    let
        bearerHeader = getBearerRequestHeader(accessToken)
        header = concatHeader(bearerHeader, extraHeaders)
    result = createRequestHeader(header, body)

proc accessTokenRequest(url, clientId, clientSecret: string, grantType: GrantType, useBasicAuth: bool,
    code, redirectUri, username, password, refreshToken: string = nil, scope: openarray[string] = []): Response =
    var body = "grant_type=" & $grantType
    case grantType
    of ResourceOwnerPassCreds:
        body = body & subex("&username=$#&password=$#") % [ username, password ]
        if len(scope) != 0:
            body = body & subex("&scope=$#") % [ encodeUrl(scope.join(" ")) ]
    of AuthorizationCode:
        body = body & subex("&code=$#") % [ encodeUrl(code) ]
        if redirectUri != nil:
            body = body & subex("&redirect_uri=$#") % [ encodeUrl(redirectUri) ]
    of ClientCreds:
        if len(scope) != 0:
            body = body & subex("&scope=$#") % [ encodeUrl(scope.join(" ")) ]
    of RefreshToken:
        body = body & subex("&refresh_token=$#") % [ encodeUrl(refreshToken) ]
        if len(scope) != 0:
            body = body & subex("&scope=$#") % [ encodeUrl(scope.join(" ")) ]
    else: discard

    var header: string
    if useBasicAuth:
        header = getBasicAuthorizationHeader(clientId, clientSecret, body)
    else:
        body = body & "&client_id=$#&client_secret=$#" % [ encodeUrl(clientId), encodeUrl(clientSecret) ]
        header = createRequestHeader("", body)

    result = request(url, httpMethod = httpPOST,
        extraHeaders = header, body = body)

proc getAuthorizationCodeAccessToken*(url, code, clientId, clientSecret: string,
    redirectUri: string = nil, useBasicAuth: bool = true): Response =
    ## Send the access token request for "Authorization Code Grant" type.
    result = accessTokenRequest(url, clientId, clientSecret, AuthorizationCode, useBasicAuth, code, redirectUri)

# ref. https://github.com/nim-lang/Nim/blob/master/lib/pure/asynchttpserver.nim#L154
proc getCallbackParamters(port: Port, html: string): Future[Uri] {.async.} =
    let socket = newAsyncSocket()
    socket.bindAddr(port)
    socket.listen()

    proc processClient(client: AsyncSocket): Future[string] {.async.} =
        var request = Request()
        request.headers = newHttpHeaders()
        result = nil
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
                    request.headers[line[0..fd-1].strip()] = line[fd+1..len(line)].strip()
                await request.respond(Http200, html)
                result = url
                client.close()

    var url: string
    while true:
        var fut = await socket.acceptAddr()
        url = await processClient(fut.client)
        if url != nil:
            break
    result = parseUri url

proc createState(): string =
    var r = 0
    result = ""
    randomize()
    for i in 0..4:
        r = random(26)
        result = result & chr(97 + r)

proc parseResponseBody(body: string): StringTableRef =
    let responses = body.split("&")
    result = newStringTable(modeCaseInsensitive)
    for response in responses:
        let fd = response.find("=")
        result[response[0..fd-1]] = response[fd+1..len(response)-1]

proc authorizationCodeGrant*(authorizeUrl, accessTokenRequestUrl, clientId, clientSecret: string,
    html: string = nil, scope: openarray[string] = [], port: int = 8080): Response =
    ## Send a request for "Authorization Code Grant" type.
    ## | This method, outputs a URL for the authorization request at first.
    ## | Then, wait for the callback at "http://localhost:${port}".
    ## | When receiving the callback, check the state, and request an access token to the server.
    ## | Returns the request result of the access token.
    var html = html
    if html == nil:
        html = ""
    let
        state = createState()
        redirectUri = "http://localhost:" & $port
        authorizeUrl = getAuthorizationCodeGrantUrl(authorizeUrl, clientId, redirectUri, state, scope)

    echo authorizeUrl
    let
        uri = waitFor getCallbackParamters(Port(port), html)
        params = parseResponseBody(uri.query)
    assert params["state"] == state
    result = getAuthorizationCodeAccessToken(accessTokenRequestUrl, params["code"], clientId, clientSecret, redirectUri)

proc implicitGrant*(url, clientId: string, html: string = nil,
    scope: openarray[string] = [], port: int = 8080): string =
    ## Send a request for "Implicit Grant" type.
    ## | This method, outputs a URL for the authorization request at first.
    ## | Then, wait for the callback at "http://localhost:${port}".
    ## | When receiving the callback, check the state, returns the Uri.query as a result.
    var html = html
    if html == nil:
        html = ""
    let
        state = createState()
        redirectUri = "http://localhost:" & $port
        url = getImplicitGrantUrl(url, clientId, redirectUri, state, scope)

    echo url
    let
        uri = waitFor getCallbackParamters(Port(port), html)
        query = uri.query
        params = parseResponseBody(query)
    assert params["state"] == state
    result = query

proc resourceOwnerPassCredsGrant*(url, clientId, clientSecret, username, password: string,
    scope: openarray[string] = [], useBasicAuth: bool = true): Response = 
    ## Send a request for "Resource Owner Password Credentials Grant" type.
    ##
    ##  | The client MUST discard the credentials once an access token has been obtained.
    ##  | -- https://tools.ietf.org/html/rfc6749#section-4.3
    result = accessTokenRequest(url, clientId, clientSecret, ResourceOwnerPassCreds, useBasicAuth,
        username = username, password = password, scope = scope)
    
proc clientCredsGrant*(url, clientid, clientsecret: string,
    scope: openarray[string] = [], useBasicAuth: bool = true): Response = 
    ## Send a request for "Client Credentials Grant" type.
    result = accessTokenRequest(url, clientId, clientSecret, ClientCreds, useBasicAuth, scope = scope)

proc refreshToken*(url, clientId, clientSecret, refreshToken: string,
    scope: openarray[string] = [], useBasicAuth: bool = true): Response =
    ## Send an update request of the access token.
    result = accessTokenRequest(url, clientId, clientSecret, RefreshToken, useBasicAuth, refreshToken = refreshToken, scope = scope)
    
proc bearerRequest*(url, accessToken: string, httpMethod = httpGET, extraHeaders = "", body = ""): Response =
    ## Send a request using the bearer token.
    let header = getBearerRequestHeader(accessToken, extraHeaders, body)
    result = request(url, httpMethod = httpMethod, extraHeaders = header, body = body)

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

    # createState test
    assert len(createState()) == 5

    # concatHeader test
    assert concatHeader("test1\c\L", "test2\c\L") == "test1\c\Ltest2\c\L"
    assert concatHeader("test1", "test2\c\L") == "test1\c\Ltest2\c\L"
    assert concatHeader("test1\c\L", "test2") == "test1\c\Ltest2\c\L"
    assert concatHeader("test1", "test2") == "test1\c\Ltest2\c\L"

    # createRequestHeader test
    assert createRequestHeader("", "aaaaa") == "Content-Type: application/x-www-form-urlencoded\c\LContent-Length: 5\c\L"
    assert createRequestHeader("", "") == "Content-Type: application/x-www-form-urlencoded\c\LContent-Length: 0\c\L"
    assert createRequestHeader("test2", "aaaaa") == "Content-Type: application/x-www-form-urlencoded\c\LContent-Length: 5\c\Ltest2\c\L"

when not defined(ssl):
    echo "SSL support is required."
    quit 1
