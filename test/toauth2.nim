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
# date  :2016-03-15

import unittest
import httpclient
import ../src/oauth2

suite "OAuth2 test":
    setup:
        const
            url = "http://server.example.com/authorize"
            clientId = "s6BhdRkqt3"
            redirectUri = "https://client.example.com/cb"
            state = "xyz"

    test "authorization code grant url":
        let correct = "http://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb"
        check(getAuthorizationCodeGrantUrl(url, clientId, redirectUri, state) == correct)

    test "implicit grant url":
        let correct = "http://server.example.com/authorize?response_type=token&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb"
        check(getImplicitGrantUrl(url, clientId, redirectUri, state) == correct)

    test "get basic authorization header":
        let header = getBasicAuthorizationHeader("Aladdin", "open sesame")
        assert header["Authorization"] == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="

    test "get bearer request header":
        let header = getBearerRequestHeader("Aladdin")
        assert header["Authorization"] == "Bearer Aladdin"

    test "generate state":
        assert len(generateState()) == 5

    test "parse redirect uri":
        let
            uri = "https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz"
            response = uri.parseAuthorizationCodeGrantRedirectUri()
        assert response.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert response.state == "xyz"

    test "parse redirect uri 2":
        let
            uri = "https://client.example.com/cb?error=access_denied&state=xyz"
        try:
            discard uri.parseAuthorizationCodeGrantRedirectUri()
        except AuthorizationError as error:
            assert error.error == "access_denied"
            assert error.state == "xyz"

    test "parse redirect uri 3":
        let
            uri = "https://client.example.com/cb?error=access_denied&error_description=error%20description&error_uri=http%3A%2F%2Fexample.com&state=xyz"
        try:
            discard uri.parseAuthorizationCodeGrantRedirectUri()
        except AuthorizationError as error:
            assert error.error == "access_denied"
            assert error.errorDescription == "error description"
            assert error.errorUri == "http://example.com"
            assert error.state == "xyz"
