/*
 *  Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
 *  See LICENSE in the source repository root for complete license information.
 */

namespace GraphWebhooks.Helpers
{
    public class SubscriptionDetails
    {
        public string SubscriptionId { get; set; }
        public string ClientState { get; set; }
        public string UserId { get; set; }
        public string RedirectUrl { get; set; }

        internal SubscriptionDetails(string subscriptionId, string clientState, string userId, string redirectUrl)
        {
            SubscriptionId = subscriptionId;
            ClientState = clientState;
            UserId = userId;
            RedirectUrl = redirectUrl;
        }
    }
}