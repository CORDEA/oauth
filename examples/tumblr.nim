# Copyright 2018 Yoshihiro Tanaka
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
# date  : 2018-07-01

import oauth/oauth1
import httpclient
import strutils
import tables
import uri

const
  requestTokenUrl = "https://www.tumblr.com/oauth/request_token"
  authorizeUrl = "https://www.tumblr.com/oauth/authorize"
  accessTokenUrl = "https://www.tumblr.com/oauth/access_token"
  requestUrl = "https://api.tumblr.com/v2/user/info"

proc parseResponseBody(body: string): Table[string, string] =
  let responses = body.split("&")
  result = initTable[string, string]()
  for response in responses:
    let r = response.split("=")
    result[r[0]] = r[1]

when isMainModule:
  echo "Please enter the consumer key."
  let consumerKey = readLine stdin
  echo "Please enter the consumer key secret."
  let consumerSecret = readLine stdin

  let
    client = newHttpClient()
    requestToken = client.getOAuth1RequestToken(requestTokenUrl, consumerKey,
      consumerSecret, callback = "http://localhost")

  if requestToken.status == "200 OK":
    var response = parseResponseBody requestToken.body
    let
      requestToken = response["oauth_token"]
      requestTokenSecret = response["oauth_token_secret"]
    echo "Access the url, please obtain the redirect url."
    echo getAuthorizeUrl(authorizeUrl, requestToken)
    echo "Please enter a redirect url."
    let
      verifierUrl = readLine stdin
      verifierUri = parseUri verifierUrl
    response = parseResponseBody verifierUri.query
    let
      verifier = response["oauth_verifier"]
      accessToken = client.getOAuth1AccessToken(accessTokenUrl, consumerKey,
        consumerSecret, requestToken, requestTokenSecret, verifier)
    if accessToken.status == "200 OK":
      response = parseResponseBody accessToken.body
      let
        accessToken = response["oauth_token"]
        accessTokenSecret = response["oauth_token_secret"]
        info = client.oAuth1Request(requestUrl, consumerKey, consumerSecret,
          accessToken, accessTokenSecret)
      echo info.body
