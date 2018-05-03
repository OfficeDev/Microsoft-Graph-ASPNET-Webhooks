
namespace GraphWebhooks.Helpers
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Threading.Tasks;

    public class GraphHttpClient
    {
        private static readonly int MaxRetryAttempts = 5;

        private string accessToken = null;

        public GraphHttpClient(string accessToken)
        {
            this.accessToken = accessToken;
        }

        // Send HTTP request implemenation with retries on transient failures.
        public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            HttpResponseMessage response = null;
            var attempt = 0;
            do
            {
                attempt++;

                HttpClient httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                response = await httpClient.SendAsync(request);

                if (((int)response.StatusCode == 429) || ((int)response.StatusCode == 503))
                {
                    TimeSpan pauseDuration = TimeSpan.FromSeconds(Math.Pow(2, attempt));
                    TimeSpan serverRecommendedPauseDuration = GetServerRecommendedPause(response);
                    if (serverRecommendedPauseDuration > pauseDuration)
                    {
                        pauseDuration = serverRecommendedPauseDuration;
                    }
                    await Task.Delay(pauseDuration);
                }
                else
                {
                    IEnumerable<string> requestId = response.Headers.GetValues("request-id");
                    Console.WriteLine("request-id value is : " + requestId);

                    IEnumerable<string> date = response.Headers.GetValues("Date");
                    Console.WriteLine("Date value is : " + date);

                    return response;
                }
            } while (attempt <= MaxRetryAttempts);

            return response;
        }

        private TimeSpan GetServerRecommendedPause(HttpResponseMessage response)
        {
            var retryAfter = response?.Headers?.RetryAfter;
            if (retryAfter == null)
                return TimeSpan.Zero;

            return retryAfter.Date.HasValue
                ? retryAfter.Date.Value - DateTime.UtcNow
                : retryAfter.Delta.GetValueOrDefault(TimeSpan.Zero);
        }
    }
}