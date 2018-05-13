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
# date  :2016-03-14

import oauth2
import json, httpclient

## This is an example to get the access token by "Resource Owner Password Credentials Grant".
## Gitlab API also supports "Web Application Flow". 
## For more information http://doc.gitlab.com/ce/api/oauth2.html.

const
    accessTokenUrl = "https://gitlab.com/oauth/token"
    url = "https://gitlab.com/api/v3/projects/owned?visibility=private"

echo "Please enter the application id."
let clientId = readLine(stdin)
echo "Please enter the secret."
let clientSecret = readLine(stdin)
echo "Please enter the your id."
let userId = readLine(stdin)
echo "Please enter the your password."
let userPassword = readLine(stdin)

let
    response = resourceOwnerPassCredsGrant(accessTokenUrl, clientId, clientSecret,
        userId, userPassword)
    obj = parseJson(response.body)
    accessToken = obj["access_token"].str
    tokenType = obj["token_type"].str
    refreshToken = obj["refresh_token"].str

if tokenType == "bearer":
    let r = bearerRequest(url, accessToken)
    echo r.body
