using System.Collections.Generic;
using System.Runtime.Caching;
using System.Timers;

namespace GraphWebhooks.Helpers
{
    public class SubscriptionCache
    {
        static SubscriptionCache cache = null;

        private static ObjectCache objCache = MemoryCache.Default;
        private static CacheItemPolicy defaultPolicy = new CacheItemPolicy();

        Timer timer;
        private SubscriptionCache()
        {
            // Renew subscriptions every 10 minute.
            Timer renewalTimer = new Timer(10 * 60 * 1000)
            {
                AutoReset = false
            };
            renewalTimer.Elapsed += OnRenewal;
            renewalTimer.Start();
            timer = renewalTimer;
        }

        public static SubscriptionCache GetSubscriptionCache()
        {
            if(cache != null)
            {
                return cache;
            }

            cache = new SubscriptionCache();
            return cache;
        }


        private async void OnRenewal(object sender, ElapsedEventArgs e)
        {
            var subscriptionstore = objCache.Get("subscription_store") as Dictionary<string, SubscriptionDetails>;

            foreach (var item in subscriptionstore)
            {
                var response = await SubscriptionHelper.CheckSubscription(item.Key, item.Value.UserId, item.Value.RedirectUrl);
                if (response != null)
                {
                    await SubscriptionHelper.RenewSubscription(item.Key, item.Value.UserId, item.Value.RedirectUrl);
                }
                else
                {
                    await SubscriptionHelper.CreateSubscription(item.Value.UserId, item.Value.RedirectUrl);
                }
            }

            timer.Start();
        }

        // This sample temporarily stores the current subscription ID, client state, user object ID, and tenant ID. 
        // This info is required so the NotificationController can retrieve an access token from the cache and validate the subscription.
        // Production apps typically use some method of persistent storage.
        public void SaveSubscriptionInfo(SubscriptionDetails subscriptionDetails)
        {
            if (objCache["subscription_store"] == null)
            {
                var subscriptionstore = new Dictionary<string, SubscriptionDetails>();
                subscriptionstore.Add(subscriptionDetails.SubscriptionId, subscriptionDetails);

                objCache.Set(new CacheItem("subscription_store", subscriptionstore), defaultPolicy);
            }
            else
            {
                var subscriptionstore = objCache.Get("subscription_store") as Dictionary<string, SubscriptionDetails>;
                subscriptionstore.Add(subscriptionDetails.SubscriptionId, subscriptionDetails);
            }
        }

        public SubscriptionDetails GetSubscriptionInfo(string subscriptionId)
        {
            var subscriptionstore = objCache.Get("subscription_store") as Dictionary<string, SubscriptionDetails>;
            return subscriptionstore[subscriptionId];
        }

        public Dictionary<string, SubscriptionDetails> DeleteAllSubscriptions()
        {
            return objCache.Remove("subscription_store") as Dictionary<string, SubscriptionDetails>;
        }
    }
}