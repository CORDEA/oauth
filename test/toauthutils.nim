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
# date  :2016-03-14

import ../src/oauthutils
import unittest
import httpclient, strtabs

suite "OAuth utils test":
    suite "Percent encoding test":
        test "Twitter example 1":
            let original = "Ladies + Gentlemen"
            check(percentEncode(original) == "Ladies%20%2B%20Gentlemen")

        test "Twitter example 2":
            let original = "An encoded string!"
            check(percentEncode(original) == "An%20encoded%20string%21")

        test "Twitter example 3":
            let original = "Dogs, Cats & Mice"
            check(percentEncode(original) == "Dogs%2C%20Cats%20%26%20Mice")

        test "Twitter example 4":
            let original = "☃"
            check(percentEncode(original) == "%E2%98%83")

    test "Create nonce":
        check(len(createNonce()) == 32)

    suite "HttpMethod to string test":
        test "HEAD":
            check(httpMethod2String(httpHEAD) == "HEAD")

        test "GET":
            check(httpMethod2String(httpGET) == "GET")

        test "POST":
            check(httpMethod2String(httpPOST) == "POST")

        test "PUT":
            check(httpMethod2String(httpPUT) == "PUT")

        test "DELETE":
            check(httpMethod2String(httpDELETE) == "DELETE")

        test "TRACE":
            check(httpMethod2String(httpTRACE) == "TRACE")

        test "OPTIONS":
            check(httpMethod2String(httpOPTIONS) == "OPTIONS")

        test "CONNECT":
            check(httpMethod2String(httpCONNECT) == "CONNECT")

    suite "Parse response body test":
        test "rfc5849 example":
            let
                original = "oauth_token=hh5s93j4hdidpola&oauth_token_secret=hdhd0244k9j7ao03&oauth_callback_confirmed=true"
                src = parseResponseBody(original)
            check(src["oauth_token"] == "hh5s93j4hdidpola")
            check(src["oauth_token_secret"] == "hdhd0244k9j7ao03")
            check(src["oauth_callback_confirmed"] == "true")

        test "Twitter access token response":
            let
                original = "oauth_token=6253282-eWudHldSbIaelX7swmsiHImEL4KinwaGloHANdrY&oauth_token_secret=2EEfA6BG3ly3sR3RjE0IBSnlQu4ZrUzPiYKmrkVU&user_id=6253282&screen_name=twitterapi"
                src = parseResponseBody(original)
            check(src["oauth_token"] == "6253282-eWudHldSbIaelX7swmsiHImEL4KinwaGloHANdrY")
            check(src["oauth_token_secret"] == "2EEfA6BG3ly3sR3RjE0IBSnlQu4ZrUzPiYKmrkVU")
            check(src["user_id"] == "6253282")
            check(src["screen_name"] == "twitterapi")

        test "Twitter request token response":
            let
                original = "oauth_token=Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik&oauth_token_secret=Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM&oauth_callback_confirmed=true"
                src = parseResponseBody(original)
            check(src["oauth_token"] == "Z6eEdO8MOmk394WozF5oKyuAv855l4Mlqo7hhlSLik")
            check(src["oauth_token_secret"] == "Kd75W4OQfb2oJTV0vzGzeXftVAwgMnEK9MumzYcM")
            check(src["oauth_callback_confirmed"] == "true")
