/*
 *  Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
 *  See LICENSE in the source repository root for complete license information.
 */

using System;
using System.Web.Mvc;
using GraphWebhooks.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using System.Configuration;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using GraphWebhooks.Helpers;
using System.Security.Claims;
using System.Collections.Generic;

namespace GraphWebhooks.Controllers
{
    public class SubscriptionController : Controller
    {

        public ActionResult Index()
        {
            return View();
        }

        // Create a webhook subscription.
        [Authorize]
        public async Task<ActionResult> CreateSubscription()
        {
            string subscriptionsEndpoint = "https://graph.microsoft.com/v1.0/subscriptions/";
            string accessToken;
            try
            {

                // Get an access token.
                accessToken = await AuthHelper.GetAccessTokenAsync();
            }
            catch (Exception e)
            {
                ViewBag.Message = BuildErrorMessage(e);
                return View("Error", e);
            }

            // This sample subscribes to get notifications when the user receives an email.
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, subscriptionsEndpoint);
            Subscription subscription = new Subscription
            {
                Resource = "me/mailFolders('Inbox')/messages",
                ChangeType = "created",
                NotificationUrl = ConfigurationManager.AppSettings["ida:NotificationUrl"],
                ClientState = Guid.NewGuid().ToString(),
                //ExpirationDateTime = DateTime.UtcNow + new TimeSpan(0, 0, 4230, 0) // current maximum timespan for messages
                ExpirationDateTime = DateTime.UtcNow + new TimeSpan(0, 0, 15, 0) // shorter duration useful for testing
            };

            string contentString = JsonConvert.SerializeObject(subscription, 
                new JsonSerializerSettings { NullValueHandling = NullValueHandling.Ignore });
            request.Content = new StringContent(contentString, System.Text.Encoding.UTF8, "application/json");

            // Send the `POST subscriptions` request and parse the response.
            GraphHttpClient graphHttpClient = new GraphHttpClient(accessToken);
            HttpResponseMessage response = await graphHttpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                string stringResult = await response.Content.ReadAsStringAsync();
                SubscriptionViewModel viewModel = new SubscriptionViewModel
                {
                    Subscription = JsonConvert.DeserializeObject<Subscription>(stringResult)
                };

                // This sample temporarily stores the current subscription ID, client state, user object ID, and tenant ID. 
                // This info is required so the NotificationController, which is not authenticated, can retrieve an access token from the cache and validate the subscription.
                // Production apps typically use some method of persistent storage.
                SubscriptionStore.SaveSubscriptionInfo(viewModel.Subscription.Id,
                    viewModel.Subscription.ClientState,
                    ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value,
                    ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value);

                // This sample just saves the current subscription ID to the session so we can delete it later.
                Session["SubscriptionId"] = viewModel.Subscription.Id;
                return View("Subscription", viewModel);
            }
            else
            {
                return RedirectToAction("Index", "Error", new { message = response.StatusCode, debug = await response.Content.ReadAsStringAsync() });
            }
        }

        // Delete the current webhooks subscription and sign out the user.
        [Authorize]
        public async Task<ActionResult> DeleteSubscription()
        {
            string subscriptionsEndpoint = "https://graph.microsoft.com/v1.0/subscriptions/";
            string subscriptionId = (string)Session["SubscriptionId"];
            string accessToken;
            try
            {

                // Get an access token.
                accessToken = await AuthHelper.GetAccessTokenAsync();
            }
            catch (Exception e)
            {
                ViewBag.Message = BuildErrorMessage(e);
                return View("Error", e);
            }

            if (!string.IsNullOrEmpty(subscriptionId))
            {
                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Delete, subscriptionsEndpoint + subscriptionId);

                // Send the `DELETE subscriptions/id` request.
                GraphHttpClient graphHttpClient = new GraphHttpClient(accessToken);
                HttpResponseMessage response = await graphHttpClient.SendAsync(request);

                if (!response.IsSuccessStatusCode)
                {
                    return RedirectToAction("Index", "Error", new { message = response.StatusCode, debug = response.Content.ReadAsStringAsync() });
                }
            }
            return RedirectToAction("SignOut", "Account");
        }

        public string BuildErrorMessage(Exception e)
        {
            string message = e.Message;
            if (e is AdalSilentTokenAcquisitionException) message = "Unable to get an access token. You may need to sign in again.";
            return message;
        }
    }
}