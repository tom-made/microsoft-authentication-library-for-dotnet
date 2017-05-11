//----------------------------------------------------------------------
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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Identity.Client.Internal.Telemetry;

namespace Microsoft.Identity.Client
{
    /// <summary>
    /// 
    /// </summary>
    public class Telemetry
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="events"></param>
        public delegate void Receiver(List<Dictionary<string, string>> events);

        private Receiver _receiver = null;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="r"></param>
        public void RegisterReceiver(Receiver r)
        {
            _receiver = r;
        }

        private static readonly Telemetry Singleton = new Telemetry();

        internal Telemetry(){}  // This is an internal constructor to build isolated unit test instance

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public static Telemetry GetInstance()
        {
            return Singleton;
        }

        /// <summary>
        /// 
        /// </summary>
        public bool TelemetryOnFailureOnly { get; set; }

        internal TelemetryRequestContext GenerateNewRequestId() // Keeps the old name. Will probably rename to CreateRequestContext() later.
        // Despite of an (upcoming) different method name, the usage pattern remains the same.
        // In fact, all the pre-existing test cases remain the same, without needing to change a single line.
        {
            return new TelemetryRequestContext() { Receiver=_receiver, TelemetryOnFailureOnly=TelemetryOnFailureOnly, ClientId=ClientId };
            // Note: This implementation does not use a plain string as RequestId,
            // instead we return a class instance (which behaves mostly like an array, although caller doesn't need to know that).
            // From telemetry caller's perspective, the usage pattern remains similar,
            // because you will just need to keep the return value of this method,
            // and include it in subsequent StartEvent(...) call, etc.
        }

        internal void StartEvent(TelemetryRequestContext context, EventBase eventToStart)
        // Despite of a different input parameter type, the usage pattern remains the same.
        {
            context?.Add(eventToStart);
            /* There used to be a global dictionary EventsInProgress
               (which was historically designed to keep track of event start time),
               so the previous implementation here need to calculate a unique key name to be used in that dictionary.

               Now, because this implementation stores events in a per-request context, rather than a global dictionary,
               We simply add the event into the context (which behaves like an array here).
             */
        }

        internal void StopEvent(TelemetryRequestContext requestId, EventBase eventToStop) // TODO: Simply remove useless requestId parameter
        // Previous implementation contains the RequestId parameter,
        // because it need to locate the event in EventsInProgress dictionary, and then move it into CompletedEvents dictionary.

        // In this alternative implementation, we store the events in only 1 place, the per-request context.
        // And it is already there. So we don't need to move anything here. We simply calls the event's own Stop() method.

        // Also, simplified implementation prevents potential coding logic error.
        // Previously we had lots of discussion for subtle implementation detail during the previous implementation in PR 314, namely:
        // 1. How to organize the if...else... safety check for potentially calling StopEvent() without calling StartEvent() first.
        // 2. Whether do we write a line of log when we detect such a Stop-without-start scenario.
        // 3. It turns out the previous (widely-adopted) logic contains a hidden bug when trying to detect orphaned events
        // https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/pull/314#discussion_r111499906
        // Now all of those topics simply do not exist in the new implementation.
        {
            eventToStop.Stop();
            /* At this point, we may consider further simplify this implementation by removing this helper completely,
            because:
                Telemetry.GetInstance().StopEvent(telemetryRequestId, apiEvent);
            is not as neat as:
                apiEvent.Stop();

            Same applies to StartEvent() and Flush().
             */
        }

        internal void Flush(TelemetryRequestContext context)
        // Despite of different parameter type, the usage pattern of this method remains the same.
        {
            context.Flush();
            // While the actual logic has been moved into TelemetryRequestContext 's same name method,
            // it is worth noting that the new implementation there has been simplified from 60+ lines of code into only 4.
            // That is mainly because, since all events are in one list, there is no such thing as orphaned event.
            // So the implementation does not need to implement the logic to handle orphaned event.
            // By the way, the previous implementation contained a unobvious bug (https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/pull/314#discussion_r111499906).
            // The new approach avoids such problem, by design.
        }

        internal string ClientId { get; set; }
    }
}
