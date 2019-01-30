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

using System;
using System.ComponentModel;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client.Cache;
using Microsoft.Identity.Client.Core;
using Microsoft.Identity.Client.Exceptions;
using Microsoft.Identity.Client.PlatformsCommon.Interfaces;
using Microsoft.Identity.Client.PlatformsCommon.Shared;
using Microsoft.Identity.Client.UI;

namespace Microsoft.Identity.Client.Platforms.net45
{
    /// <summary>
    ///     Platform / OS specific logic.
    /// </summary>
    internal class NetDesktopPlatformProxy : AbstractPlatformProxy
    {
        /// <inheritdoc />
        public NetDesktopPlatformProxy(ICoreLogger logger)
            : base(logger)
        {
        }

        private bool IsWindows
        {
            get
            {
                switch (Environment.OSVersion.Platform)
                {
                case PlatformID.Win32S:
                case PlatformID.Win32Windows:
                case PlatformID.Win32NT:
                case PlatformID.WinCE:
                    return true;
                default:
                    return false;
                }
            }
        }

        /// <summary>
        ///     Get the user logged in to Windows or throws
        /// </summary>
        /// <returns>Upn or throws</returns>
        public override Task<string> GetUserPrincipalNameAsync()
        {
            // TODO: there is discrepancy between the implementation of this method on net45 - throws if upn not found - and uap and 
            // the rest of the platforms - returns "" 

            const int NameUserPrincipal = 8;
            uint userNameSize = 0;
            WindowsNativeMethods.GetUserNameEx(NameUserPrincipal, null, ref userNameSize);
            if (userNameSize == 0)
            {
                throw MsalExceptionFactory.GetClientException(
                    CoreErrorCodes.GetUserNameFailed,
                    CoreErrorMessages.GetUserNameFailed,
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }

            var sb = new StringBuilder((int)userNameSize);
            if (!WindowsNativeMethods.GetUserNameEx(NameUserPrincipal, sb, ref userNameSize))
            {
                throw MsalExceptionFactory.GetClientException(
                    CoreErrorCodes.GetUserNameFailed,
                    CoreErrorMessages.GetUserNameFailed,
                    new Win32Exception(Marshal.GetLastWin32Error()));
            }

            return Task.FromResult(sb.ToString());
        }

        public override Task<bool> IsUserLocalAsync(RequestContext requestContext)
        {
            var current = WindowsIdentity.GetCurrent();
            if (current != null)
            {
                string prefix = WindowsIdentity.GetCurrent().Name.Split('\\')[0].ToUpperInvariant();
                return Task.FromResult(
                    prefix.Equals(Environment.MachineName.ToUpperInvariant(), StringComparison.OrdinalIgnoreCase));
            }

            return Task.FromResult(false);
        }

        public override bool IsDomainJoined()
        {
            if (!IsWindows)
            {
                return false;
            }

            bool returnValue = false;
            try
            {
                int result = WindowsNativeMethods.NetGetJoinInformation(null, out var pDomain, out var status);
                if (pDomain != IntPtr.Zero)
                {
                    WindowsNativeMethods.NetApiBufferFree(pDomain);
                }

                returnValue = result == WindowsNativeMethods.ErrorSuccess &&
                              status == WindowsNativeMethods.NetJoinStatus.NetSetupDomainName;
            }
            catch (Exception ex)
            {
                Logger.WarningPii(ex);
                // ignore the exception as the result is already set to false;
            }

            return returnValue;
        }

        public override string GetEnvironmentVariable(string variable)
        {
            if (string.IsNullOrWhiteSpace(variable))
            {
                throw new ArgumentNullException(nameof(variable));
            }

            return Environment.GetEnvironmentVariable(variable);
        }

        /// <inheritdoc />
        public override string GetBrokerOrRedirectUri(Uri redirectUri)
        {
            return redirectUri.OriginalString;
        }

        /// <inheritdoc />
        public override string GetDefaultRedirectUri(string clientId)
        {
            return Constants.DefaultRedirectUri;
        }

        /// <inheritdoc />
        public override ILegacyCachePersistence CreateLegacyCachePersistence()
        {
            return new InMemoryLegacyCachePersistance();
        }

        /// <inheritdoc />
        public override ITokenCacheAccessor CreateTokenCacheAccessor()
        {
            return new InMemoryTokenCacheAccessor();
        }

        /// <inheritdoc />
        protected override IWebUIFactory CreateWebUiFactory()
        {
            return new NetDesktopWebUIFactory();
        }

        /// <inheritdoc />
        protected override string InternalGetDeviceModel()
        {
            // Since MSAL .NET may be used on servers, for security reasons, we do not emit device type.
            return null;
        }

        /// <inheritdoc />
        protected override string InternalGetOperatingSystem()
        {
            return Environment.OSVersion.ToString();
        }

        /// <inheritdoc />
        protected override string InternalGetProcessorArchitecture()
        {
            return IsWindows ? WindowsNativeMethods.GetProcessorArchitecture() : null;
        }

        /// <inheritdoc />
        protected override string InternalGetCallingApplicationName()
        {
            // Considered PII, ensure that it is hashed.
            return Assembly.GetEntryAssembly()?.GetName()?.Name;
        }

        /// <inheritdoc />
        protected override string InternalGetCallingApplicationVersion()
        {
            // Considered PII, ensure that it is hashed.
            return Assembly.GetEntryAssembly()?.GetName()?.Version?.ToString();
        }

        /// <inheritdoc />
        protected override string InternalGetDeviceId()
        {
            // Considered PII, ensure that it is hashed.
            return NetworkInterface.GetAllNetworkInterfaces().Where(nic => nic.OperationalStatus == OperationalStatus.Up)
                            .Select(nic => nic.GetPhysicalAddress()?.ToString()).FirstOrDefault();
        }

        /// <inheritdoc />
        protected override string InternalGetProductName()
        {
            return "MSAL.Desktop";
        }

        /// <inheritdoc />
        protected override ICryptographyManager InternalGetCryptographyManager()
        {
            return new NetDesktopCryptographyManager();
        }

        /// <inheritdoc />
        protected override IPlatformLogger InternalGetPlatformLogger()
        {
            return new EventSourcePlatformLogger();
        }
    }
}