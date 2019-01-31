﻿//----------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

namespace Microsoft.Identity.Client.Platforms.iOS
{
    internal class BrokerConstants
    {
        public const string ChallengeResponseHeader = "Authorization";
        public const string ChallengeResponseType = "PKeyAuth";
        public const string ChallengeResponseToken = "AuthToken";
        public const string ChallengeResponseContext = "Context";
        public const string ChallengeResponseVersion = "Version";
        public const string BrowserExtPrefix = "browser://";
        public const string BrowserExtInstallPrefix = "msauth://";
        public const string DeviceAuthChallengeRedirect = "urn:http-auth:PKeyAuth";
        public const string ChallengeHeaderKey = "x-ms-PKeyAuth";
        public const string ChallengeHeaderValue = "1.0";

        public const string BrokerKey = "broker_key";
        // new parameter to specify the protocol version, should be "3"
        public const string MsgProtocolVer = "msg_protocol_ver";
        public const string Claims = "claims";
        public const string SkipCache = "skip_cache";
        public const string AppLink = "app_link";
        public const string InvokeBroker = "msauthv2://broker?";
        public const string Code = "code";
        public const string BrokerError = "broker_error";
        public const string Error = "error";
        public const string ErrorDescription = "error_description";
        public const string ExpectedHash = "hash";
        public const string EncryptedResponsed = "response";

          //broker related log messages
        public const string InvokeIosBrokerAppLink = "Invoking the iOS broker app link";
        public const string InvokeTheIosBroker = "Invoking the iOS broker";
    }
}