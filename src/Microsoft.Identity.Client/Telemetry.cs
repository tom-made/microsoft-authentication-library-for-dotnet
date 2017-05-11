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


        internal ConcurrentDictionary<Tuple<string, string>, EventBase> EventsInProgress = new ConcurrentDictionary<Tuple<string, string>, EventBase>();

        internal ConcurrentDictionary<string, List<EventBase>> CompletedEvents = new ConcurrentDictionary<string, List<EventBase>>();

        internal string GenerateNewRequestId()
        {
            return Guid.NewGuid().ToString();
        }

        internal TelemetryRequestContext CreateRequestContext()
        // Despite of a different method name, the usage pattern remains the same.
        {
            return new TelemetryRequestContext() { Receiver=_receiver, TelemetryOnFailureOnly=TelemetryOnFailureOnly, ClientId=ClientId };
            // Note: This implementation does not use a plain string as RequestId,
            // instead we return a class instance (which behaves mostly like an array, although caller doesn't need to know that).
            // From telemetry caller's perspective, the usage pattern remains similar,
            // because you will just need to keep the return value of this method,
            // and include it in subsequent StartEvent(...) call, etc.
        }

        internal void StartEvent(string requestId, EventBase eventToStart)
        {
            if (_receiver != null && requestId != null)
            {
                EventsInProgress[new Tuple<string, string>(requestId, eventToStart[EventBase.EventNameKey])] = eventToStart;
            }
        }

        internal void StartEvent(TelemetryRequestContext context, EventBase eventToStart)
        // Despite of a different input parameter type, the usage pattern remains the same.
        {
            context.Add(eventToStart);
            /* There used to be a global dictionary EventsInProgress
               (which was historically designed to keep track of event start time),
               so the previous implementation here need to calculate a unique key name to be used in that dictionary.

               Now, because this implementation stores events in a per-request context, rather than a global dictionary,
               We simply add the event into the context (which behaves like an array here).
             */
        }

        internal void StopEvent(string requestId, EventBase eventToStop)
        {
            if (_receiver == null || requestId == null)
            {
                return;
            }
            Tuple<string, string> eventKey = new Tuple<string, string>(requestId, eventToStop[EventBase.EventNameKey]);

            // Locate the same name event in the EventsInProgress map
            EventBase eventStarted = null;
            if (EventsInProgress.ContainsKey(eventKey))
            {
                eventStarted = EventsInProgress[eventKey];
            }

            // If we did not get anything back from the dictionary, most likely its a bug that StopEvent
            // was called without a corresponding StartEvent
            if (null == eventStarted)
            {
                // Stop Event called without a corresponding start_event.
                return;
            }

            // Set execution time properties on the event
            eventToStop.Stop();

            if (!CompletedEvents.ContainsKey(requestId))
            {
                // if this is the first event associated to this
                // RequestId we need to initialize a new List to hold
                // all of sibling events
                List<EventBase> events = new List<EventBase>();
                events.Add(eventToStop);
                CompletedEvents[requestId] = events;
            }
            else
            {
                // if this event shares a RequestId with other events
                // just add it to the List
                CompletedEvents[requestId].Add(eventToStop);
            }

            // Mark this event as no longer in progress
            EventBase dummy = null; // The TryRemove(...) next line requires an out parameter, even though we don't actually use it
            EventsInProgress.TryRemove(eventKey, out dummy);
            // We could use the following one-liner instead, but we believe it is less readable:
            // ((IDictionary<Tuple<string, string>, EventBase>)EventsInProgress).Remove(eventKey);
        }

        internal void StopEvent(EventBase eventToStop)
        // Previous implementation contains one more parameter, the RequestId,
        // because it need to locate the event in EventsInProgress dictionary, and then move it into CompletedEvents dictionary.

        // In this alternative implementation, we store the events in only 1 place, the per-request context.
        // So we don't need to move anything here. We simply calls the event's own Stop() method.

        // Also, simplified implementation prevents coding logic error.
        // Previously we had lots of discussion for this topic during the previous implementation in PR 314.
        // Now we can solve them, once and for all.
        {
            eventToStop.Stop();
            /* At this point, we may consider further simplify this implementation by removing this helper completely,
            because:
                Telemetry.GetInstance().StopEvent(telemetryRequestId, apiEvent);
            is not as concise as:
                apiEvent.Stop();

            Same applies to StartEvent() and Flush().
             */
        }

        internal void Flush(string requestId)
        {
            if (_receiver == null)
            {
                return;
            }

            // check for orphaned events...
            List<EventBase> orphanedEvents = CollateOrphanedEvents(requestId);
            // Add the OrphanedEvents to the completed EventList
            if (!CompletedEvents.ContainsKey(requestId))
            {
                // No completed Events returned for RequestId
                return;
            }

            CompletedEvents[requestId].AddRange(orphanedEvents);

            List<EventBase> eventsToFlush;
            CompletedEvents.TryRemove(requestId, out eventsToFlush);

            if (TelemetryOnFailureOnly)
            {
                // iterate over Events, if the ApiEvent was successful, don't dispatch
                bool shouldRemoveEvents = false;

                foreach (var anEvent in eventsToFlush)
                {
                    var apiEvent = anEvent as ApiEvent;
                    if (apiEvent != null)
                    {
                        shouldRemoveEvents = apiEvent.WasSuccessful;
                        break;
                    }
                }

                if (shouldRemoveEvents)
                {
                    eventsToFlush.Clear();
                }
            }

            if (eventsToFlush.Count > 0)
            {
                eventsToFlush.Insert(0, new DefaultEvent(ClientId));
                _receiver(eventsToFlush.Cast<Dictionary<string, string>>().ToList());
            }
        }

        private List<EventBase> CollateOrphanedEvents(String requestId)
        {
            var orphanedEvents = new List<EventBase>();
            foreach (var key in EventsInProgress.Keys)
            {
                if (key.Item1 == requestId)
                {
                    // The orphaned event already contains its own start time, we simply collect it
                    EventBase orphan;
                    EventsInProgress.TryRemove(key, out orphan);
                    orphanedEvents.Add(orphan);
                }
            }
            return orphanedEvents;
        }

        internal void Flush(TelemetryRequestContext context)
        // Despite of different parameter type, the usage pattern of this method remains the same.
        {
            context.Flush();
            // While the actual logic has been moved into TelemetryRequestContext 's same name method,
            // it is worth noting that its implementation has been simplified into 4 lines in total.
            // That is mainly because, since all events are in one list, there is no such thing as orphaned event.
            // So the implementation does not need to implement the logic to handle orphaned event,
            // which was error-prone, and contained a unobvious bug (https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/pull/314#discussion_r111499906).
            // The new approach avoids such problem, by design.
        }

        internal string ClientId { get; set; }
    }
}
