using System.Security.Claims;

namespace cx.LoginProvider.Utilities.Core.Dtos
{
    [Serializable]
    public partial class OidcModel
    {
        public List<Claim> Claims { get; set; }
        public string UserInfo { get; set; }
        public string ApiUserInfo { get; set; }
        public string GroupInfo { get; set; }
    }
}
