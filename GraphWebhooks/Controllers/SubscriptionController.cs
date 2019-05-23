/*
 *  Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
 *  See LICENSE in the source repository root for complete license information.
 */

using GraphWebhooks.Helpers;
using GraphWebhooks.Models;
using Microsoft.Identity.Client;
using System;
using System.Threading.Tasks;
using System.Web.Mvc;

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
            string baseUrl = $"{Request.Url.Scheme}://{Request.Url.Authority}";

            try
            {
                var subscription = await SubscriptionHelper.CreateSubscription(baseUrl);

                SubscriptionViewModel viewModel = new SubscriptionViewModel()
                {
                    Subscription = subscription
                };

                return View("Subscription", viewModel);
            }
            catch (Exception e)
            {
                ViewBag.Message = BuildErrorMessage(e);
                return View("Error", e);
            }
        }

        // Delete the current webhooks subscription and sign out the user.
        [Authorize]
        public async Task<ActionResult> DeleteSubscription()
        {
            string baseUrl = $"{Request.Url.Scheme}://{Request.Url.Authority}";
            var subscriptions = SubscriptionCache.GetSubscriptionCache().DeleteAllSubscriptions();

            try
            {
                foreach (var subscription in subscriptions)
                {
                    await SubscriptionHelper.DeleteSubscription(subscription.Key, baseUrl);
                }

                return RedirectToAction("SignOut", "Account");
            }
            catch (Exception ex)
            {
                ViewBag.Message = BuildErrorMessage(ex);
                return View("Error", ex);
            }
        }

        public string BuildErrorMessage(Exception e)
        {
            string message = e.Message;
            if (e is MsalUiRequiredException) message = "Unable to get an access token. You may need to sign in again.";
            return message;
        }
    }
}