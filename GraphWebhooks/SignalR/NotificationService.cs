using GraphWebhooks.Models;
using Microsoft.AspNet.SignalR;
using System.Collections.Generic;

namespace GraphWebhooks.SignalR
{
    public class NotificationService : PersistentConnection
    {
        public void SendNotificationToClient(List<MessageViewModel> messages)
        {
            var hubContext = GlobalHost.ConnectionManager.GetHubContext<NotificationHub>();
            if (hubContext != null)
            {
                hubContext.Clients.All.showNotification(messages);
            }
        }
    }
}