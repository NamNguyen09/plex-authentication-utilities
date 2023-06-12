using System.Security.Claims;
using System.Text;
using log4net;

namespace cx.Authentication.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        private static readonly ILog _logger = LogManager.GetLogger(typeof(ClaimsPrincipalExtensions));

        public static string GetClaimValue(this ClaimsPrincipal claimsPrincipal, string type)
        {
            if (claimsPrincipal == null) return "";

            Claim claim = claimsPrincipal.FindFirst(type);
            if (claim != null) return claim.Value;

            StringBuilder claims = new StringBuilder();
            foreach (var item in claimsPrincipal.Claims)
            {
                if (claims.Length > 0) claims.Append("; ");
                claims.Append(item.Type).Append(": ").Append(item.Value);
            }
            _logger.Info(string.Format("{0} is null in claims: {1}", type, claims.ToString()));
            return "";
        }
    }
}
