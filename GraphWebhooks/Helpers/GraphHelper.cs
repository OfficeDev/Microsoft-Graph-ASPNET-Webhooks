/*
 *  Copyright (c) Microsoft. All rights reserved. Licensed under the MIT license.
 *  See LICENSE in the source repository root for complete license information.
 */

using GraphWebhooks.Models;
using GraphWebhooks.TokenStorage;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Policy;
using System.Web;

namespace GraphWebhooks.Helpers
{
    public static class GraphHelper
    {
        public static GraphServiceClient GetAuthenticatedClient(string userId, string redirect)
        {
            var graphClient = new GraphServiceClient(
                new DelegateAuthenticationProvider(
                    async (request) =>
                    {                     
                        var tokenCache = new SampleTokenCache(userId);

                        var cca = new ConfidentialClientApplication(Startup.ClientId, redirect,
                            new ClientCredential(Startup.ClientSecret), tokenCache.GetMsalCacheInstance(), null);

                        var accounts = await cca.GetAccountsAsync();

                        var authResult = await cca.AcquireTokenSilentAsync(Startup.Scopes, accounts.First());
                        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authResult.AccessToken);

                    }));

            return graphClient;
        }
    }
}