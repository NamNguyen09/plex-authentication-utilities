using cx.LoginProvider.Utilities.Core.Settings;

namespace cx.LoginProvider.Utilities.Core.Dtos
{
    [Serializable]
    public partial class LoginProvider
    {
        public int LoginServiceID { get; set; }

        public int SiteID { get; set; }

        public int LoginServiceType { get; set; }

        public string Authority { get; set; }

        public string MetadataAddress { get; set; }

        public string RedirectUri { get; set; }

        public string SecondaryClaimType { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string Scope { get; set; }

        public string ResponseType { get; set; }

        public string PrimaryClaimType { get; set; }

        public string PostLogoutUri { get; set; }

        public string BaseUrl { get; set; }

        public OidcSetting OidcSetting { get; set; }
    }
}
