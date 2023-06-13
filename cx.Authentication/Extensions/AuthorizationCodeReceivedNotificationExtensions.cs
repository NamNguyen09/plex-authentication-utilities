using cx.Authentication.Utilities.Dtos;
using log4net;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace cx.Authentication.Extensions
{
    public static class AuthorizationCodeReceivedNotificationExtensions
    {
        private static readonly ILog _logger = LogManager.GetLogger(typeof(AuthorizationCodeReceivedNotificationExtensions));
        public static void LogContext(this AuthorizationCodeReceivedNotification context, LoginProvider loginProvider, string message)
        {
            var authenticationTicketProperties = context.AuthenticationTicket.Properties ?? new AuthenticationProperties();
            int? loginServiceId = loginProvider == null ? (int?)null : loginProvider.LoginServiceID;
            var protocolMessage = context.ProtocolMessage;
            _logger.Debug(new
            {
                Message = message,
                LoginServiceId = loginServiceId,
                AuthorizationCodeReceivedNotification = new
                {
                    context.Code,
                    AuthenticationTicket = new
                    {
                        Properties = new
                        {
                            authenticationTicketProperties.IssuedUtc,
                            authenticationTicketProperties.ExpiresUtc
                        }
                    },
                    ProtocolMessage = protocolMessage == null ? null : new
                    {
                        protocolMessage.ExpiresIn,
                        protocolMessage.Error,
                        protocolMessage.ErrorDescription
                    }
                }
            });
        }
    }
}
