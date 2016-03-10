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
# date  :2016-03-08

import oauth2
import strutils, httpclient
import json

const
    authorizeUrl = "https://accounts.google.com/o/oauth2/v2/auth"
    accessTokenUrl = "https://accounts.google.com/o/oauth2/token"

let html = "index.html".readFile()

echo "Please enter the client id."
let clientId = readLine(stdin)
echo "Please enter the client secret."
let clientSecret = readLine(stdin)

let response = authorizationCodeGrant(authorizeUrl, accessTokenUrl,
    clientId, clientSecret, html, scope = @["https://www.googleapis.com/auth/gmail.readonly"])

echo "Please enter your email address."
let
    address = readLine(stdin)
    url = "https://www.googleapis.com/gmail/v1/users/$#/messages?maxResults=5" % [ address ]
    obj = parseJson(response.body)
    accessToken = obj["access_token"].str
    tokenType = obj["token_type"].str
    refreshToken = obj["refresh_token"].str

if tokenType == "Bearer":
    let r = bearerRequest(url, accessToken)
    echo r.body
