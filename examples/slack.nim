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
# date  :2016-03-08

import base64
import uri
import json
import oauth/oauth2
import std/sysrand
import httpclient

const
    authorizeUrl = "https://slack.com/oauth/authorize"
    accessTokenUrl = "https://slack.com/api/oauth.access"
    redirectUri = "http://localhost:8080"
    url = "https://slack.com/api/conversations.list"

echo "Please enter the client id."
let clientId = readLine(stdin)
echo "Please enter the client secret."
let clientSecret = readLine(stdin)

let
  state = encodeUrl(encode(urandom(128), safe = true))
  grantUrl = getAuthorizationCodeGrantUrl(authorizeUrl, clientId, redirectUri, state, @["channels:read"])
echo "Please go to this url."
echo grantUrl

# Receives redirect url. You can also handle directly from server that was launched.
echo "Please enter the received redirect url."
# ex. https://example.com?code=xxxxxxxxxx&state=xxxxx
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
  obj = parseJson(response.body)
  accessToken = obj["access_token"].str
  r = client.getContent(url & "?token=" & accessToken)
echo r
