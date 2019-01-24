﻿// ------------------------------------------------------------------------------
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

using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Microsoft.Identity.Client.ApiConfig;
using Microsoft.Identity.Client.ApiConfig.Parameters;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NSubstitute;

namespace Microsoft.Identity.Test.Unit.ApiConfigTests.Harnesses
{
    internal class AcquireTokenByUsernamePasswordBuilderHarness : AbstractBuilderHarness
    {
        public AcquireTokenByUsernamePasswordParameters UsernamePasswordParametersReceived { get; private set; }
        public IPublicClientApplication ClientApplication { get; private set; }

        public async Task SetupAsync()
        {
            ClientApplication = Substitute.For<IPublicClientApplication, IPublicClientApplicationExecutor>();

            await ((IPublicClientApplicationExecutor)ClientApplication).ExecuteAsync(
                Arg.Do<AcquireTokenCommonParameters>(parameters => CommonParametersReceived = parameters),
                Arg.Do<AcquireTokenByUsernamePasswordParameters>(parameters => UsernamePasswordParametersReceived = parameters),
                CancellationToken.None).ConfigureAwait(false);
        }

        public void ValidateInteractiveParameters(string expectedUsername = null, SecureString expectedPassword = null)
        {
            Assert.IsNotNull(UsernamePasswordParametersReceived);
            Assert.AreEqual(expectedUsername, UsernamePasswordParametersReceived.Username);
            Assert.AreEqual(expectedPassword, UsernamePasswordParametersReceived.Password);
        }
    }
}