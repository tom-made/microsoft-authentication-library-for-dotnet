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

using Microsoft.Identity.Client.ApiConfig.Parameters;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Internal.Broker;
using Microsoft.Identity.Client.Utils;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.Identity.Client.Internal.Requests
{
    internal class BrokerInteractiveRequest : RequestBase
    {    
        BrokerFactory brokerFactory = new BrokerFactory();

        public Dictionary<string, string> _brokerPayload = new Dictionary<string, string>();
        protected IBroker BrokerHelper { get; }

        public BrokerInteractiveRequest(
           IServiceBundle serviceBundle,
           AuthenticationRequestParameters authenticationRequestParameters,
           AcquireTokenByBrokerParameters brokerParameters)
           : base(serviceBundle, authenticationRequestParameters, brokerParameters)
        {
            BrokerHelper = brokerFactory.CreateBrokerFacade(ServiceBundle.DefaultLogger);
            _brokerPayload = brokerParameters.BrokerPayload;

            _brokerPayload.Add(BrokerParameter.Authority, authenticationRequestParameters.Authority.AuthorityInfo.CanonicalAuthority);
            string scopes = ScopeHelper.ConvertSortedSetScopesToString(authenticationRequestParameters.Scope);

            _brokerPayload.Add(BrokerParameter.RequestScopes, scopes);
            _brokerPayload.Add(BrokerParameter.ClientId, authenticationRequestParameters.ClientId);
            _brokerPayload.Add(BrokerParameter.CorrelationId, ServiceBundle.DefaultLogger.CorrelationId.ToString());
            _brokerPayload.Add(BrokerParameter.ClientVersion, MsalIdHelper.GetMsalVersion());
            _brokerPayload.Add(BrokerParameter.Force, "NO");
            _brokerPayload.Add(BrokerParameter.RedirectUri, authenticationRequestParameters.RedirectUri.AbsoluteUri);

            //string extraQP = string.Join("&", authenticationRequestParameters.ExtraQueryParameters.Select(x => x.Key + "=" + x.Value.ToString()));
            //_brokerParameters.BrokerPayload.Add(BrokerParameter.ExtraQp, extraQP);
            _brokerPayload.Add(BrokerParameter.Username, authenticationRequestParameters.Account?.Username ?? string.Empty);
            _brokerPayload.Add(BrokerParameter.ExtraOidcScopes, BrokerParameter.OidcScopesValue);
        }


        internal override async Task<AuthenticationResult> ExecuteAsync(CancellationToken cancellationToken)
        {
            await ResolveAuthorityEndpointsAsync().ConfigureAwait(false);

            await BrokerHelper.AcquireTokenUsingBrokerAsync(_brokerPayload, ServiceBundle).ConfigureAwait(false);

            var msalTokenResponse = await SendTokenRequestAsync(null, cancellationToken)
                                        .ConfigureAwait(false);
            return CacheTokenResponseAndCreateAuthenticationResult(msalTokenResponse);
        }
    }
}
