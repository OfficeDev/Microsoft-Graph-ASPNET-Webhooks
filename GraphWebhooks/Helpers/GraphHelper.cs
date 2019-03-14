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
                        //var tokenCache = new SampleTokenCache(userId);

                        //var cca = new ConfidentialClientApplication(Startup.ClientId, redirect,
                        //    new ClientCredential(Startup.ClientSecret), tokenCache.GetMsalCacheInstance(), null);

                        //AuthenticationResult authResult = null;
                        //var accounts = await cca.GetAccountAsync(userId); // await cca.AcquireTokenSilentAsync(Startup.Scopes, cca.Users.First());
                        //authResult = await cca.AcquireTokenSilentAsync(Startup.Scopes, cca.Users.First()); //await cca.AcquireTokenSilentAsync(Startup.Scopes, accounts.);
                        //request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", authResult.AccessToken);

                        HttpContextBase context = HttpContext.Current.GetOwinContext().Environment["System.Web.HttpContextBase"] as HttpContextBase;
                        
                        string signedInUserID = ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier).Value;
                        TokenCache userTokenCache = new MSALSessionCache(signedInUserID, context).GetMsalCacheInstance();
                        ConfidentialClientApplication cca = new ConfidentialClientApplication(Startup.ClientId, redirect, new ClientCredential(Startup.ClientSecret), userTokenCache, null);
                        var accounts = await cca.GetAccountsAsync();
                        AuthenticationResult result = await cca.AcquireTokenSilentAsync(Startup.Scopes, accounts.First());

                    }));

            return graphClient;
        }
    }
}