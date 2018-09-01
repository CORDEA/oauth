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
import httpclient
import strtabs

proc mockOAuth1Parameters(
        realm = "_realm", token = "_token",
        callback = "_callback", verifier = "_verifier",
        isIncludeVersion = true): OAuth1Parameters =
    result = OAuth1Parameters(
        realm: realm,
        consumerKey: "_consumerKey",
        nonce: "_nonce",
        signature: "_signature",
        signatureMethod: "_signatureMethod",
        timestamp: "_timestamp",
        token: token,
        callback: callback,
        verifier: verifier,
        isIncludeVersionToHeader: isIncludeVersion
    )

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

    suite "Signature generate test":
        # https://dev.twitter.com/oauth/overview/authorizing-requests
        test "Twitter example":
            let signature = getSignature(HttpPOST, url1, body1, table1, consumerSecret1, tokenSecret1)
            check(signature == "tnnArxj06cWHq44gCs1OSKk/jLY=")

        test "rfc5849 example":
            # https://tools.ietf.org/html/rfc5849
            let signature = getSignature(HttpGET, url2, "", table2, consumerSecret2, tokenSecret2)
            check(percentEncode(signature) == "MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D")

    suite "OAuth1 request header test":
        test "all parameters should be included to header":
            let header = getOAuth1RequestHeader(mockOAuth1Parameters())
            check(header["Content-Type"] == "application/x-www-form-urlencoded")
            check(header["Authorization"] == "OAuth realm=\"_realm\", oauth_consumer_key=\"_consumerKey\", oauth_signature_method=\"_signatureMethod\", oauth_timestamp=\"_timestamp\", oauth_nonce=\"_nonce\", oauth_signature=\"_signature\", oauth_token=\"_token\", oauth_callback=\"_callback\", oauth_verifier=\"_verifier\", oauth_version=\"1.0\"")

        test "realm should be erased from header when realm is empty":
            let header = getOAuth1RequestHeader(mockOAuth1Parameters(realm = ""))
            check(header["Authorization"] == "OAuth oauth_consumer_key=\"_consumerKey\", oauth_signature_method=\"_signatureMethod\", oauth_timestamp=\"_timestamp\", oauth_nonce=\"_nonce\", oauth_signature=\"_signature\", oauth_token=\"_token\", oauth_callback=\"_callback\", oauth_verifier=\"_verifier\", oauth_version=\"1.0\"")

        test "oauth_token should be erased from header when token is empty":
            let header = getOAuth1RequestHeader(mockOAuth1Parameters(token = ""))
            check(header["Authorization"] == "OAuth realm=\"_realm\", oauth_consumer_key=\"_consumerKey\", oauth_signature_method=\"_signatureMethod\", oauth_timestamp=\"_timestamp\", oauth_nonce=\"_nonce\", oauth_signature=\"_signature\", oauth_callback=\"_callback\", oauth_verifier=\"_verifier\", oauth_version=\"1.0\"")

        test "oauth_callback should be erased from header when callback is empty":
            let header = getOAuth1RequestHeader(mockOAuth1Parameters(callback = ""))
            check(header["Authorization"] == "OAuth realm=\"_realm\", oauth_consumer_key=\"_consumerKey\", oauth_signature_method=\"_signatureMethod\", oauth_timestamp=\"_timestamp\", oauth_nonce=\"_nonce\", oauth_signature=\"_signature\", oauth_token=\"_token\", oauth_verifier=\"_verifier\", oauth_version=\"1.0\"")

        test "oauth_token should be erased from header when token is empty":
            let header = getOAuth1RequestHeader(mockOAuth1Parameters(verifier = ""))
            check(header["Authorization"] == "OAuth realm=\"_realm\", oauth_consumer_key=\"_consumerKey\", oauth_signature_method=\"_signatureMethod\", oauth_timestamp=\"_timestamp\", oauth_nonce=\"_nonce\", oauth_signature=\"_signature\", oauth_token=\"_token\", oauth_callback=\"_callback\", oauth_version=\"1.0\"")

        test "oauth_version should be erased from header when isIncludeVersionToHeader is false":
            let header = getOAuth1RequestHeader(mockOAuth1Parameters(isIncludeVersion = false))
            check(header["Authorization"] == "OAuth realm=\"_realm\", oauth_consumer_key=\"_consumerKey\", oauth_signature_method=\"_signatureMethod\", oauth_timestamp=\"_timestamp\", oauth_nonce=\"_nonce\", oauth_signature=\"_signature\", oauth_token=\"_token\", oauth_callback=\"_callback\", oauth_verifier=\"_verifier\"")

        test "headers should be overwritten by extra headers":
            let header = getOAuth1RequestHeader(mockOAuth1Parameters(), newHttpHeaders({"Authorization": "auth", "Extra": "header"}))
            check(header["Authorization"] == "auth")
            check(header["Extra"] == "header")
