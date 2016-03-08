# Copyright [2015] [Yoshihiro Tanaka]
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

import times, strutils
import math, httpclient
import base64
import tables

proc percentEncode*(str: string): string =
    result = ""
    for s in str:
        case s
        of 'a'..'z', 'A'..'Z', '0'..'9', '-', '.', '_', '~':
            result = result & s
        of ' ':
            result = result & '+'
        else:
            result = result & '%' & toHex(ord s, 2)

proc createNonce*(): string =
    let epoch = $epochTime()
    var
        rst = ""
        r = 0

    randomize()
    for i in 0..(23 - len(epoch)):
        r = random(26)
        rst = rst & chr(97 + r)

    result = encode(rst & epoch)

proc httpMethod2String*(httpMethod: HttpMethod): string = 
    case httpMethod
    of httpHEAD:
        result = "HEAD"
    of httpGET:
        result = "GET"
    of httpPOST:
        result = "POST"
    of httpPUT:
        result = "PUT"
    of httpDELETE:
        result = "DELETE"
    of httpTRACE:
        result = "TRACE"
    of httpOPTIONS:
        result = "OPTIONS"
    of httpCONNECT:
        result = "CONNECT"

proc parseResponseBody*(body: string): Table[string, string] =
    let responses = body.split("&")
    result = initTable[string, string]()
    for response in responses:
        let r = response.split("=")
        result[r[0]] = r[1]
