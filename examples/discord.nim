# Copyright 2019 Yoshihiro Tanaka
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
# Modified for Discord by William Hatcher @williamhatcher
# date  : 2021-03-27

import base64, uri, json, sequtils, std/sysrand, strutils, httpclient
import oauth2

const
    authorizeUrl = "https://discord.com/api/oauth2/authorize"
    accessTokenUrl = "https://discord.com/api/oauth2/token"
    redirectUri = "http://localhost:8080"
    userInfoUrl = "https://discord.com/api/users/@me"
    scopes = ["identify"]

echo "Please enter the client id: "
let clientId = readLine(stdin)
echo "Please enter the client secret: "
let clientSecret = readLine(stdin)

let
  state = encodeUrl(encode(urandom(128), safe = true))
  grantUrl = getAuthorizationCodeGrantUrl(authorizeUrl, clientId, redirectUri, state, scopes)
echo "Please go to this url."
echo grantUrl

# Receives redirect url. You can also handle directly from server that was launched.
echo "Please enter the received redirect url."
let
  receivedUri = readLine(stdin)
  grantResponse = receivedUri.parseAuthorizationResponse()

doAssert state == grantResponse.state

let
  client = newHttpClient()
  response = client.getAuthorizationCodeAccessToken(
    accessTokenUrl,
    grantResponse.code,
    clientid,
    clientSecret,
    redirectUri
  )

  accessToken = response.body.parseJson["access_token"].getStr

  r = client.bearerRequest(
    userInfoUrl,
    accessToken
  )

echo r.body
