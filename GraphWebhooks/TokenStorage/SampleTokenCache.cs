/*
 *  Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
 *  See LICENSE in the source repository root for complete license information.
 */

using Microsoft.Identity.Client;
using System.Runtime.Caching;
using System.Threading;

namespace GraphWebhooks.TokenStorage
{

    // This sample uses the runtime cache. Production apps will typically use some method of persistent storage.
    // Adapted from https://github.com/Azure-Samples/active-directory-dotnet-webapp-openidconnect-v2
    public class SampleTokenCache
    {
        private static ReaderWriterLockSlim sessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        private string userId = string.Empty;
        private string cacheId = string.Empty;
        private static ObjectCache cache = MemoryCache.Default;
        private static CacheItemPolicy defaultPolicy = new CacheItemPolicy();

        TokenCache tokenCache = new TokenCache();

        public SampleTokenCache(string userId)
        {
            this.userId = userId;
            cacheId = userId + "_TokenCache";
            Load();
        }

        public TokenCache GetMsalCacheInstance()
        {
            tokenCache.SetBeforeAccess(BeforeAccessNotification);
            tokenCache.SetAfterAccess(AfterAccessNotification);
            Load();
            return tokenCache;
        }

        public bool HasData()
        {
            return (cache[cacheId] != null && ((byte[])cache[cacheId]).Length > 0);
        }

        public void Clear()
        {
            cache.Remove(cacheId);
        }

        private void Load()
        {
            sessionLock.EnterReadLock();
            var item = cache.GetCacheItem(cacheId);
            if (item != null)
            {
                tokenCache.Deserialize((byte[])item.Value);
            }
            sessionLock.ExitReadLock();
        }

        private void Persist()
        {
            sessionLock.EnterWriteLock();

            // Optimistically set HasStateChanged to false. 
            // We need to do it early to avoid losing changes made by a concurrent thread.
            tokenCache.HasStateChanged = false;

            cache.Set(new CacheItem(cacheId, tokenCache.Serialize()), defaultPolicy);
            
            sessionLock.ExitWriteLock();
        }

        // Triggered right before MSAL needs to access the cache. 
        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            // Reload the cache from the persistent store in case it changed since the last access. 
            Load();
        }

        // Triggered right after MSAL accessed the cache.
        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            // if the access operation resulted in a cache update
            if (tokenCache.HasStateChanged)
            {
                Persist();
            }
        }
    }
}