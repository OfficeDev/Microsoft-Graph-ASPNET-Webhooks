/*
 *  Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
 *  See LICENSE in the source repository root for complete license information.
 */

using GraphWebhooks.Helpers;
using GraphWebhooks.Models;
using GraphWebhooks.SignalR;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace GraphWebhooks.Controllers
{
    public class NotificationController : Controller
    {
        public ActionResult LoadView()
        {
            ViewBag.CurrentUserId = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
            return View("Notification");
        }

        // The `notificationUrl` endpoint that's registered with the webhook subscription.
        [HttpPost]
        public async Task<ActionResult> Listen()
        {

            // Validate the new subscription by sending the token back to Microsoft Graph.
            // This response is required for each subscription.
            if (Request.QueryString["validationToken"] != null)
            {
                var token = Request.QueryString["validationToken"];
                return Content(token, "plain/text");
            }

            // Parse the received notifications.
            else
            {
                try
                {
                    var notifications = new Dictionary<string, Notification>();
                    using (var inputStream = new System.IO.StreamReader(Request.InputStream))
                    {
                        JObject jsonObject = JObject.Parse(inputStream.ReadToEnd());
                        if (jsonObject != null)
                        {

                            // Notifications are sent in a 'value' array. The array might contain multiple notifications for events that are
                            // registered for the same notification endpoint, and that occur within a short timespan.
                            JArray value = JArray.Parse(jsonObject["value"].ToString());
                            foreach (var notification in value)
                            {
                                Notification current = JsonConvert.DeserializeObject<Notification>(notification.ToString());

                                // Check client state to verify the message is from Microsoft Graph.
                                var subscription = SubscriptionCache.GetSubscriptionCache().GetSubscriptionInfo(current.SubscriptionId);

                                // This sample only works with subscriptions that are still cached.
                                if (subscription != null)
                                {
                                    if (current.ClientState == subscription.ClientState)
                                    {
                                        // Just keep the latest notification for each resource.
                                        // No point pulling data more than once.
                                        notifications[current.Resource] = current;
                                    }
                                }
                            }

                            if (notifications.Count > 0)
                            {

                                // Query for the changed messages.
                                await GetChangedMessagesAsync(notifications.Values);
                            }
                        }
                    }
                }
                catch (Exception)
                {
                    // TODO: Handle the exception.
                    // Still return a 202 so the service doesn't resend the notification.
                }
                return new HttpStatusCodeResult(202);
            }
        }

        // Get information about the changed messages and send to the browser via SignalR.
        // A production application would typically queue a background job for reliability.
        public async Task GetChangedMessagesAsync(IEnumerable<Notification> notifications)
        {
            List<MessageViewModel> messages = new List<MessageViewModel>();

            foreach (var notification in notifications)
            {
                SubscriptionDetails subscription = SubscriptionCache.GetSubscriptionCache().GetSubscriptionInfo(notification.SubscriptionId);

                var graphClient = GraphHelper.GetAuthenticatedClient(subscription.UserId, subscription.RedirectUrl);

                // Get the message
                var message = await graphClient.Me.Messages[notification.ResourceData.Id].Request()
                    .Select("id,subject,bodyPreview,createdDateTime,isRead,conversationId,changeKey")
                    .GetAsync();

                // Clear the additional data from Graph (purely for display purposes)
                message.AdditionalData.Clear();

                MessageViewModel messageViewModel = new MessageViewModel(message, subscription.UserId);
                messages.Add(messageViewModel);
            }
            if (messages.Count > 0)
            {
                NotificationService notificationService = new NotificationService();
                notificationService.SendNotificationToClient(messages);
            }
        }
    }
}
