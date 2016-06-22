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

import unittest
import ../src/oauth1
import hmac, sha1
import httpclient
import strtabs

suite "OAuth1 test":
    setup:
        const
            url1 = "https://api.twitter.com/1/statuses/update.json?include_entities=true"
            body1 = "status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21"
            consumerSecret1 = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw"
            tokenSecret1 = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE"
            url2 = "http://photos.example.net/photos?file=vacation.jpg&size=original"
            consumerSecret2 = "kd94hf93k423kf44"
            tokenSecret2 = "pfkkdhi9sl3r4s00"

        let
            table1 = OAuth1Parameters(
                consumerKey: "xvz1evFS4wEEPTGEFPHBog",
                nonce: "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg",
                signatureMethod: "HMAC-SHA1",
                timestamp: "1318622958",
                token: "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
                isIncludeVersionToHeader: true
            )
            table2 = OAuth1Parameters(
                consumerKey: "dpf43f3p2l4k3l03",
                nonce: "chapoH",
                signatureMethod: "HMAC-SHA1",
                timestamp: "137131202",
                token: "nnch734d00sl2jdk"
            )

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

        test "Twitter example 5":
            let body = "Hello Ladies + Gentlemen, a signed OAuth request!"
            check(percentEncode(body) == "Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21")

    # https://dev.twitter.com/oauth/overview/authorizing-requests
    suite "twitter example":
        test "Signature key":
            let signatureBaseString = getSignatureBaseString(httpPOST, url1, body1, table1)
            check(signatureBaseString == "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521")

        test "Request header":
            let signatureKey = getSignatureKey(consumerSecret1, tokenSecret1)
            check(signatureKey == "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE")

        test "Signature":
            let
                signatureBaseString = getSignatureBaseString(httpPOST, url1, body1, table1)
                signatureKey = getSignatureKey(consumerSecret1, tokenSecret1)
                oauthSignature = hmac_sha1(signatureKey, signatureBaseString).toBase64

            check(oauth_signature == "tnnArxj06cWHq44gCs1OSKk/jLY=")

    test "rfc5849 example":
        # https://tools.ietf.org/html/rfc5849
        let
            signatureBaseString = getSignatureBaseString(httpGET, url2, "", table2)
            signatureKey = getSignatureKey(consumerSecret2, tokenSecret2)
            oauthSignature = hmac_sha1(signatureKey, signatureBaseString).toBase64

        check(percentEncode(oauthSignature) == "MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D")
