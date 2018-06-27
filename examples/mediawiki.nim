# Copyright 2017 Yoshihiro Tanaka
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
# date  : 2017-06-09

import oauth1
import tables
import strutils
import httpclient
import uri

const
  mediaWikiBaseUrl = "<MediaWiki url>/index.php"
  requestTokenUrl = mediaWikiBaseUrl & "?title=Special%3AOAuth%2Finitiate"
  authorizeUrl = mediaWikiBaseUrl & "/Special:OAuth/authorize"
  accessTokenUrl = mediaWikiBaseUrl & "?title=Special%3AOAuth%2Ftoken"
  identifyUrl = mediaWikiBaseUrl & "?title=Special%3AOAuth%2Fidentify"

proc parseResponseBody(body: string): Table[string, string] =
  let responses = body.split("&")
  result = initTable[string, string]()
  for response in responses:
    let r = response.split("=")
    result[r[0]] = r[1]

when isMainModule:
  echo "Please enter the consumer token."
  let consumerKey = readLine stdin
  echo "Please enter the secret token."
  let consumerSecret = readLine stdin

  let requestToken = getOAuth1RequestToken(requestTokenUrl, consumerKey, consumerSecret)

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
      accessToken = getOAuth1AccessToken(accessTokenUrl,
        consumerKey, consumerSecret, requestToken, requestTokenSecret, verifier)
    if accessToken.status == "200 OK":
      response = parseResponseBody accessToken.body
      let
        accessToken = response["oauth_token"]
        accessTokenSecret = response["oauth_token_secret"]
        identify = oAuth1Request(identifyUrl, consumerKey, consumerSecret, accessToken, accessTokenSecret)
      if identify.status == "200 OK":
        echo "\n--- Success ---"
        echo identify.body
