// ------------------------------------------------------------------------------
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
// ------------------------------------------------------------------------------

using Microsoft.Identity.Client.Core;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Utils;
using UIKit;
using Foundation;
using Microsoft.Identity.Client.Internal;
using System;
using CoreFoundation;
using Microsoft.Identity.Client.OAuth2;
using Microsoft.Identity.Client.Internal.Broker;
using Microsoft.Identity.Client.UI;
using Microsoft.Identity.Client.AppConfig;

namespace Microsoft.Identity.Client.Platforms.iOS
{
    /// <summary>
    /// Handles requests which invoke the broker. This is only for mobile (iOS and Android) scenarios.
    /// </summary>
    internal class iOSBroker : IBroker
    {
        private static SemaphoreSlim brokerResponseReady = null;

        private static NSUrl brokerResponse = null;
        private readonly ApplicationConfiguration brokerRequest;
        private IServiceBundle _serviceBundle;

        public bool CanInvokeBroker
        {
            get
            {
                CoreUIParent uiParent = new CoreUIParent();
                if (!brokerRequest.IsBrokerEnabled)
                {
                    return false;
                }

                var result = false;

                if (brokerRequest.IsBrokerEnabled)
                {
                    uiParent.CallerViewController.InvokeOnMainThread(() =>
                    {
                        result = UIApplication.SharedApplication.CanOpenUrl(new NSUrl("msauthv2://"));
                    });
                }

                return result;
            }
        }

        public async Task<MsalTokenResponse> AcquireTokenUsingBrokerAsync(Dictionary<string, string> brokerPayload, IServiceBundle serviceBundle)
        {
            _serviceBundle = serviceBundle;
            if (brokerPayload.ContainsKey(BrokerParameter.SilentBrokerFlow))
            {
                throw new MsalUiRequiredException("something", "something else");
            }

            brokerResponse = null;
            brokerResponseReady = new SemaphoreSlim(0);

            // call broker
            string base64EncodedString = Base64UrlHelpers.Encode(BrokerKeyHelper.GetRawBrokerKey());
            brokerPayload[BrokerConstants.BrokerKey] = base64EncodedString;
            brokerPayload[BrokerConstants.MsgProtocolVer] = "3";

            if (brokerPayload.ContainsKey(BrokerConstants.Claims))
            {
                brokerPayload.Add(BrokerConstants.SkipCache, "YES");
                string claims = Base64UrlHelpers.Encode(brokerPayload[BrokerParameter.Claims]); //TODO: check this
                brokerPayload[BrokerParameter.Claims] = claims;
            }

            if (brokerPayload.ContainsKey(BrokerParameter.BrokerInstallUrl))
            {
                string url = brokerPayload[BrokerParameter.BrokerInstallUrl];
                Uri uri = new Uri(url);
                string query = uri.Query;
                if (query.StartsWith("?", StringComparison.OrdinalIgnoreCase))
                {
                    query = query.Substring(1);
                }
                
                //log something interesting here ("Invoking the iOS broker app link");

                Dictionary<string, string> keyPair = CoreHelpers.ParseKeyValueList(query, '&', true, false, null);
                DispatchQueue.MainQueue.DispatchAsync(() => UIApplication.SharedApplication.OpenUrl(new NSUrl(keyPair[BrokerConstants.AppLink])));

                throw new MsalClientException(MsalErrorIOSEx.BrokerApplicationRequired, MsalErrorMessageIOSEx.BrokerApplicationRequired);
            }

            else
            {
                //log something interesting here ("Invoking the iOS broker");
                NSUrl url = new NSUrl(BrokerConstants.InvokeBroker + brokerPayload.ToQueryParameter());
                DispatchQueue.MainQueue.DispatchAsync(() => UIApplication.SharedApplication.OpenUrl(url));
            }

            await brokerResponseReady.WaitAsync().ConfigureAwait(false);
            return ProcessBrokerResponse();
        }

        private MsalTokenResponse ProcessBrokerResponse()
        {
            string[] keyValuePairs = brokerResponse.Query.Split('&');
            Dictionary<string, string> responseDictionary = new Dictionary<string, string>();

            foreach (string pair in keyValuePairs)
            {
                string[] keyValue = pair.Split('=');
                responseDictionary[keyValue[0]] = CoreHelpers.UrlDecode(keyValue[1]);
                if (responseDictionary[keyValue[0]].Equals("(null)", StringComparison.OrdinalIgnoreCase) && keyValue[0].Equals(BrokerConstants.Code, StringComparison.OrdinalIgnoreCase))
                {
                    responseDictionary[BrokerConstants.Error] = BrokerConstants.BrokerError;
                }
            }

            return ResultFromBrokerResponse(responseDictionary);
        }

        private MsalTokenResponse ResultFromBrokerResponse(Dictionary<string, string> responseDictionary)
        {
            MsalTokenResponse tokenResponse = new MsalTokenResponse();

            if (responseDictionary.ContainsKey(BrokerConstants.Error) || responseDictionary.ContainsKey(BrokerConstants.ErrorDescription))
            {
                tokenResponse.CreateFromBrokerResponse(responseDictionary);
            }
            else
            {
                string expectedHash = responseDictionary[BrokerConstants.ExpectedHash];
                string encryptedResponse = responseDictionary[BrokerConstants.EncryptedResponsed];
                string decryptedResponse = BrokerKeyHelper.DecryptBrokerResponse(encryptedResponse);
                string responseActualHash = _serviceBundle.PlatformProxy.CryptographyManager.CreateSha256Hash(decryptedResponse);
                byte[] rawHash = Convert.FromBase64String(responseActualHash);
                string hash = BitConverter.ToString(rawHash);

                if (expectedHash.Equals(hash.Replace("-", ""), StringComparison.OrdinalIgnoreCase))
                {
                    responseDictionary = CoreHelpers.ParseKeyValueList(decryptedResponse, '&', false, null);
                    tokenResponse.CreateFromBrokerResponse(responseDictionary);
                }
                else
                {
                    tokenResponse = new MsalTokenResponse
                    {
                        Error = MsalError.BrokerReponseHashMismatch,
                        ErrorDescription = MsalClientException.BrokerReponseHashMismatch

                    };
                }
            }

            var dateTimeOffset = new DateTimeOffset(new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc));
            dateTimeOffset = dateTimeOffset.AddSeconds(tokenResponse.ExpiresIn);
            return tokenResponse;
        }

         public static void SetBrokerResponse(NSUrl responseUrl)
        {
            brokerResponse = responseUrl;
            brokerResponseReady.Release();
        }
    }
}
