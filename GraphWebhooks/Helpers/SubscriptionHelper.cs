using Microsoft.Graph;
using System;
using System.Configuration;
using System.Security.Claims;
using System.Threading.Tasks;

namespace GraphWebhooks.Helpers
{
    public class SubscriptionHelper
    {
        internal static string CurrentUserId
        {
            get
            {
                return ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
            }
        }

        internal static async Task<Subscription> CreateSubscription(string baseUrl, string userId = null)
        {
            var graphClient = GraphHelper.GetAuthenticatedClient(string.IsNullOrEmpty(userId) ? CurrentUserId : userId, baseUrl);

            var subscription = new Subscription
            {
                Resource = "me/mailFolders('Inbox')/messages",
                ChangeType = "created",
                NotificationUrl = ConfigurationManager.AppSettings["ida:NotificationUrl"],
                ClientState = Guid.NewGuid().ToString(),
                ExpirationDateTime = DateTime.UtcNow + new TimeSpan(0, 0, 15, 0) // shorter duration useful for testing
            };

            var newSubscription = await graphClient.Subscriptions.Request().AddAsync(subscription);

            // This sample temporarily stores the current subscription ID, client state, and user object ID.
            // This info is required so the NotificationController, which is not authenticated, can retrieve
            // an access token from the cache and validate the subscription.
            // Production apps typically use some method of persistent storage.
            var subscriptionDetails = new SubscriptionDetails(
                    newSubscription.Id,
                    newSubscription.ClientState,
                    CurrentUserId,
                    baseUrl);

            SubscriptionCache.GetSubscriptionCache().SaveSubscriptionInfo(subscriptionDetails);

            return newSubscription;
        }


        internal static async Task<Subscription> RenewSubscription(string subscriptionId, string userId, string baseUrl)
        {
            var graphClient = GraphHelper.GetAuthenticatedClient(userId, baseUrl);

            Subscription subscription = new Subscription
            {
                ExpirationDateTime = DateTime.UtcNow + new TimeSpan(0, 0, 15, 0) // shorter duration useful for testing
            };

            return await graphClient.Subscriptions[subscriptionId].Request().UpdateAsync(subscription);
        }
        
        internal static async Task<Subscription> CheckSubscription(string subscriptionId, string userId, string baseUrl)
        {
            var graphClient = GraphHelper.GetAuthenticatedClient(userId, baseUrl);
            return await graphClient.Subscriptions[subscriptionId].Request().GetAsync();
        }

        internal static async Task DeleteSubscription(string subscriptionId, string baseUrl)
        {
            var graphClient = GraphHelper.GetAuthenticatedClient(CurrentUserId, baseUrl);
            await graphClient.Subscriptions[subscriptionId].Request().DeleteAsync();
        }
    }
}