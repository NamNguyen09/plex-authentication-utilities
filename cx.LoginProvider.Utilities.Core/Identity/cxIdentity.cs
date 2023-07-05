using System.Security.Claims;

namespace cx.LoginProvider.Utilities.Core.Identity
{
    public class cxIdentity : ClaimsIdentity
    {
        public const string RolesClaimType = "http://www.conexus.no/conexus.Security.Role";
        public const string GroupClaimType = "http://www.conexus.com/conexus.Security.Group";
        public const string IPClaimType = "http://www.conexus.com/conexus.Security.IP";
        public const string IdClaimType = "http://www.conexus.com/conexus.Security.Id";


        public cxIdentity(IEnumerable<Claim> claims, string authenticationType)
            : base(claims, authenticationType: authenticationType)
        {

            AddClaims(from @group in claims where @group.Type == GroupClaimType select @group);
            AddClaims(from role in claims where role.Type == RoleClaimType select role);
            AddClaims(from id in claims where id.Type == IdClaimType select id);
            AddClaims(from ip in claims where ip.Type == IPClaimType select ip);


        }

        public cxIdentity(IEnumerable<string> roles, IEnumerable<string> groups, string IP, int id)
        {
            AddClaims(from @group in groups select new Claim(GroupClaimType, @group));
            AddClaims(from role in roles select new Claim(RolesClaimType, role));
            AddClaim(new Claim(IdClaimType, id.ToString()));
            AddClaim(new Claim(IPClaimType, IP.ToString()));
        }

        public IEnumerable<string> Roles
        {
            get
            {
                return from claim in FindAll(RolesClaimType) select claim.Value;
            }
        }

        public IEnumerable<string> Groups { get { return from claim in FindAll(GroupClaimType) select claim.Value; } }

        public int Id { get { return Convert.ToInt32(FindFirst(IdClaimType).Value); } }
        public string IP { get { return FindFirst(IPClaimType).Value; } }
    }

    public class cxPrincipal : ClaimsPrincipal
    {


        public cxPrincipal(cxIdentity identity)
            : base(identity)
        {

        }

        public cxPrincipal(ClaimsPrincipal claimsPrincipal)
            : base(claimsPrincipal)
        {

        }
    }
}
