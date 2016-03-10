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
import httpclient
import json

const
    authorizeUrl = "https://slack.com/oauth/authorize"
    accessTokenUrl = "https://slack.com/api/oauth.access"
    url = "https://slack.com/api/channels.list"

let html = "resources/index.html".readFile()

echo "Please enter the client id."
let clientId = readLine(stdin)
echo "Please enter the client secret."
let clientSecret = readLine(stdin)

let response = authorizationCodeGrant(authorizeUrl, accessTokenUrl,
    clientId, clientSecret, html, scope = @["channels:read"])

let
    obj = parseJson(response.body)
    accessToken = obj["access_token"].str

let r = getContent(url & "?token=" & accessToken)
echo r
