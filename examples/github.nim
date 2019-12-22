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
# date  : 2019-12-22

import uri
import json
import oauth2
import sequtils
import strutils
import httpclient

const
    authorizeUrl = "https://github.com/login/oauth/authorize"
    accessTokenUrl = "https://github.com/login/oauth/access_token"
    redirectUri = "http://localhost:8080"
    url = "https://api.github.com/user"

echo "Please enter the client id."
let clientId = readLine(stdin)
echo "Please enter the client secret."
let clientSecret = readLine(stdin)

let
  state = generateState()
  grantUrl = getAuthorizationCodeGrantUrl(authorizeUrl, clientId, redirectUri, state, @["channels:read"])
echo "Please go to this url."
echo grantUrl

# Receives redirect url. You can also handle directly from server that was launched.
echo "Please enter the received redirect url."
let
  receivedUri = readLine(stdin)
  grantResponse = receivedUri.parseAuthorizationResponse()

assert state == grantResponse.state

let
  client = newHttpClient()
  response = client.getAuthorizationCodeAccessToken(
    accessTokenUrl,
    grantResponse.code,
    clientid,
    clientSecret,
    redirectUri
  )
  accessToken = response.body
    .split("&")
    .mapIt(it.split("="))
    .filterIt(it[0] == "access_token")[0][1]
  r = client.bearerRequest(
    url,
    accessToken
  )

echo r.body
