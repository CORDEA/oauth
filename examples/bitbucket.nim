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
# date  :2016-03-07

import oauth1
import tables
import strutils
import httpclient

const
    requestTokenUrl = "https://bitbucket.org/api/1.0/oauth/request_token"
    authorizeUrl = "https://bitbucket.org/api/1.0/oauth/authenticate"
    accessTokenUrl = "https://bitbucket.org/api/1.0/oauth/access_token"
    requestUrl = "https://api.bitbucket.org/2.0/user/emails"

proc parseResponseBody(body: string): Table[string, string] =
    let responses = body.split("&")
    result = initTable[string, string]()
    for response in responses:
        let r = response.split("=")
        result[r[0]] = r[1]

when isMainModule:
    echo "Please enter the key."
    let consumerKey = readLine stdin
    echo "Please enter the secret."
    let consumerSecret = readLine stdin

    let requestToken = getOAuth1RequestToken(requestTokenUrl, consumerKey, consumerSecret, isIncludeVersionToHeader = true)

    if requestToken.status == "200 OK":
        var response = parseResponseBody requestToken.body
        let 
            requestToken = response["oauth_token"]
            requestTokenSecret = response["oauth_token_secret"]
        echo "Access the url, please obtain the verifier key."
        echo getAuthorizeUrl(authorizeUrl, requestToken)
        echo "Please enter a verifier key."
        let
            verifier = readLine stdin
            accessToken = getOAuth1AccessToken(accessTokenUrl,
                consumerKey, consumerSecret, requestToken, requestTokenSecret, verifier, isIncludeVersionToHeader = true)
        if accessToken.status == "200 OK":
            response = parseResponseBody accessToken.body
            let
                accessToken = response["oauth_token"]
                accessTokenSecret = response["oauth_token_secret"]

            let emails = oAuth1Request(requestUrl, consumerKey, consumerSecret, accessToken, accessTokenSecret, isIncludeVersionToHeader = true)
            echo emails.body 
