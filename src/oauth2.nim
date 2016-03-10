# Copyright [2016] [Yoshihiro Tanaka]
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

import uri, base64
import math, times
import asynchttpserver, asyncdispatch, asyncnet
import httpclient
import subexes, strtabs, strutils
import oauthutils

type
    GrantType = enum
        AuthorizationCode = "authorization_code",
        Implicit,
        ResourceOwnerPassCreds = "password",
        ClientCreds = "client_credentials"

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
    redirectUri, state: string = nil, scope: seq[string] = nil): string = 
    var url = url
    let parsed = parseUri(url)
    url = url & (if parsed.query == "": "?" else: "&")
    url = url & subex("response_type=$#&client_id=$#&state=$#") % [ (if grantType == AuthorizationCode: "code" else: "token"), percentEncode(clientId), state ]
    if redirectUri != nil:
        url = url & subex("&redirect_uri=$#") % [ percentEncode(redirectUri) ]
    if scope != nil:
        url = url & subex("&scope=$#") % [ percentEncode(scope.join(" ")) ]
    result = url

proc getAuthorizationCodeGrantUrl*(url, clientId: string,
    redirectUri, state: string = nil, scope: seq[string] = nil): string =
    result = getGrantUrl(url, clientId, AuthorizationCode, redirectUri, state, scope)

proc getImplicitGrantUrl*(url, clientId: string,
    redirectUri, state: string = nil, scope: seq[string] = nil): string =
    result = getGrantUrl(url, clientId, Implicit, redirectUri, state, scope)

proc basicAuthorizationHeader(clientId, clientSecret: string): string =
    result = encode(clientId & ":" & clientSecret)
    result = result.replace("\c\L", "")
    result = "Authorization: Basic " & result & "\c\L"

proc accessTokenRequest(url, clientId, clientSecret: string, grantType: GrantType,
    code, redirectUri, username, password: string = nil, scope: seq[string] = nil): Response =
    var body = "grant_type=" & $grantType
    if grantType == ResourceOwnerPassCreds:
        body = subex("&username=$#&password=$#") % [ username, password ]
        if scope != nil:
            body = body & subex("&scope=$#") % [ percentEncode(scope.join(" ")) ]
    elif grantType == AuthorizationCode:
        body = body & subex("&code=$#") % [ percentEncode(code) ]
        if redirectUri != nil:
            body = body & subex("&redirect_uri=$#") % [ percentEncode(redirectUri) ]
    elif grantType == ClientCreds:
        if scope != nil:
            body = body & subex("&scope=$#") % [ percentEncode(scope.join(" ")) ]

    let extraHeaders = basicAuthorizationHeader(clientId, clientSecret)
    let header = createRequestHeader(extraheaders, body)
    echo header
    result = request(url, httpMethod = httpPOST,
        extraHeaders = header, body = body)

proc getAuthorizationCodeAccessToken*(url, code, clientId, clientSecret: string, redirectUri: string = nil): Response =
    result = accessTokenRequest(url, clientId, clientSecret, AuthorizationCode, code, redirectUri)

proc getCallbackParamters(port: Port, html: string): Future[Uri] {.async.} =
    let socket = newAsyncSocket()
    socket.bindAddr(port)
    socket.listen()

    proc processClient(client: AsyncSocket): Future[string] {.async.} =
        var request = Request()
        request.headers = newStringTable()
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
    for i in 0..5:
        r = random(26)
        result = result & chr(97 + r)

proc authorizationCodeGrant*(authorizeUrl, accessTokenRequestUrl, clientId, clientSecret: string,
    html: string = nil, scope: seq[string] = nil, port: int = 8080): Response =
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
    result = getAuthorizationCodeAccessToken(accessTokenRequestUrl, params["code"], clientId, clientSecret, redirectUri)

proc implicitGrant*(url, clientId: string, html: string = nil, scope: seq[string] = nil, port: int = 8080): string =
    var html = html
    if html == nil:
        html = ""
    let
        state = createState()
        redirectUri = "http://localhost:" & $port
        url = getImplicitGrantUrl(url, clientId, redirectUri, state, scope)

    echo url
    let uri = waitFor getCallbackParamters(Port(port), html)
    result = uri.query

proc resourceOwnerPassCredsGrant*(url, clientId, clientSecret, username, password: string, scope: seq[string] = nil): Response = 
    result = accessTokenRequest(url, clientId, clientSecret, ResourceOwnerPassCreds, username = username, password = password, scope = scope)
    
proc clientCredsGrant*(url, clientid, clientsecret: string, scope: seq[string] = nil): Response = 
    result = accessTokenRequest(url, clientId, clientSecret, ClientCreds, scope = scope)
    
proc bearerRequest*(url, accessToken: string, httpMethod = httpGET, extraHeaders = "", body = ""): Response =
    let
        extraHeaders = "Authorization: Bearer " & accessToken  & "\c\L" & extraHeaders
        header = createRequestHeader(extraHeaders, body)
    result = request(url, httpMethod = httpMethod, extraHeaders = header, body = body)

when isMainModule:
    let header = basicAuthorizationHeader("Aladdin", "open sesame")
    doAssert header == "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\c\L"
