using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using cx.Authentication.Utilities.Extentions;
using log4net;

namespace cx.Authentication.Extensions
{
    public static class JwtSecurityTokenExtensions
    {
        private static readonly ILog _logger = LogManager.GetLogger(typeof(JwtSecurityTokenExtensions));

        public static string GetClaimValue(this JwtSecurityToken jwtSecurityToken, string type)
        {
            if (jwtSecurityToken == null) return "";

            Claim claim = jwtSecurityToken.Claims.FirstOrDefault(t => t.Type.EqualsIgnoreCase(type));
            if (claim != null) return claim.Value;

            StringBuilder claims = new StringBuilder();
            foreach (var item in jwtSecurityToken.Claims)
            {
                if (claims.Length > 0) claims.Append("; ");
                claims.Append(item.Type).Append(": ").Append(item.Value);
            }
            _logger.Info(string.Format("{0} is null in claims: {1}", type, claims.ToString()));
            return "";
        }
    }
}
