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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Test.Common;
using Microsoft.Identity.Client.Utils;
using Microsoft.Identity.Test.Common.Core.Mocks;
using Microsoft.Identity.Client.ApiConfig.Parameters;
using Microsoft.Identity.Client.Internal.Requests;
using Microsoft.Identity.Client;
using System.Threading;
using Microsoft.Identity.Client.Internal;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.OAuth2;
using System.Net.Http;
using System.Net;
using Microsoft.Identity.Test.Unit.RequestsTests;

namespace Microsoft.Identity.Test.Unit
{
    [TestClass]
    public class BrokerParametersTests
    {
        [TestInitialize]
        public void TestInitialize()
        {
            TestCommon.ResetStateAndInitMsal();
        }

        private const string Authority = "https://login.microsoftonline.com/test";
        public static readonly string CanonicalizedAuthority = Client.AppConfig.AuthorityInfo.CanonicalizeAuthorityUri(CoreHelpers.UrlDecode(Authority));

        [TestMethod]
        [Description("Test setting of the broker parameters in the BrokerInteractiveRequest constructor.")]
        public void BrokerInteractiveRequest_CreateBrokerParametersTest()
        {
            using (var harness = new MockHttpAndServiceBundle())
            {
                var parameters = CreateAuthenticationParametersAndSetupMocks(
                    harness,
                    out HashSet<string> expectedScopes);

                var cache = parameters.TokenCache;

                // Check that cache is empty
                Assert.AreEqual(0, cache.Accessor.AccessTokenCount);
                Assert.AreEqual(0, cache.Accessor.AccountCount);
                Assert.AreEqual(0, cache.Accessor.IdTokenCount);
                Assert.AreEqual(0, cache.Accessor.RefreshTokenCount);

                var brokerParameters = new AcquireTokenByBrokerParameters();

                var request = new BrokerInteractiveRequest(harness.ServiceBundle, parameters, brokerParameters);

                Assert.AreEqual(9, brokerParameters.BrokerPayload.Count);

                Assert.AreEqual(CanonicalizedAuthority, brokerParameters.BrokerPayload[BrokerParameter.Authority]);
                Assert.AreEqual(MsalTestConstants.ScopeStr, brokerParameters.BrokerPayload[BrokerParameter.RequestScopes]);
                Assert.AreEqual(MsalTestConstants.ClientId, brokerParameters.BrokerPayload[BrokerParameter.ClientId]);

                Assert.AreEqual(harness.ServiceBundle.DefaultLogger.CorrelationId.ToString(), brokerParameters.BrokerPayload[BrokerParameter.CorrelationId]);
                Assert.AreEqual(MsalIdHelper.GetMsalVersion(), brokerParameters.BrokerPayload[BrokerParameter.ClientVersion]);
                Assert.AreEqual("NO", brokerParameters.BrokerPayload[BrokerParameter.Force]);
                Assert.AreEqual(string.Empty, brokerParameters.BrokerPayload[BrokerParameter.Username]);
                
                Assert.AreEqual(MsalTestConstants.RedirectUri, brokerParameters.BrokerPayload[BrokerParameter.RedirectUri]);

               // Assert.AreEqual(MsalTestConstants.BrokerExtraQueryParameters, brokerParameters.BrokerPayload[BrokerParameter.ExtraQp]);

               // Assert.AreEqual(MsalTestConstants.BrokerClaims, brokerParameters.BrokerPayload[BrokerParameter.Claims]);
               Assert.AreEqual(BrokerParameter.OidcScopesValue, brokerParameters.BrokerPayload[BrokerParameter.ExtraOidcScopes]);
            }
        }

        private AuthenticationRequestParameters CreateAuthenticationParametersAndSetupMocks(
           MockHttpAndServiceBundle harness,
           out HashSet<string> expectedScopes)
        {
            var cache = new TokenCache(harness.ServiceBundle);
            Dictionary<string, string> expectedQueryParameters = new Dictionary<string, string>();
            expectedQueryParameters.Add(BrokerParameter.ExtraQp, MsalTestConstants.BrokerExtraQueryParameters);

            var parameters = harness.CreateBrokerAuthenticationRequestParameters(Authority, null, null, expectedQueryParameters, cache);

            expectedScopes = new HashSet<string>();
            expectedScopes.UnionWith(MsalTestConstants.Scope);
            expectedScopes.Add(OAuth2Value.ScopeOfflineAccess);
            expectedScopes.Add(OAuth2Value.ScopeProfile);
            expectedScopes.Add(OAuth2Value.ScopeOpenId);

            return parameters;
        }
    }
}
