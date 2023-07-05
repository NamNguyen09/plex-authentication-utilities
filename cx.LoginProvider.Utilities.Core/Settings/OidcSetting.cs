namespace cx.LoginProvider.Utilities.Core.Settings
{
    [Serializable]
    public class OidcSetting
    {
        public string TokenEndPoint { get; set; }
        public string UserInfoEndPoint { get; set; }
        public string FeideOidcEndpoint { get; set; }
        public string FeideApiEndpoint { get; set; }
        public string GroupApiEndpoint { get; set; }
        public string AcrValues { get; set; }
        public string SecurityLevelClaimType { get; set; } = cxAuthConstants.ClaimKeys.SecurityLevelClaimType;
        public string SupportedSecurityLevel { get; set; }
        public string PersonalIdentityClaimType { get; set; }
        public string TokenAuthenticationStyle { get; set; }
        public string RoreApiEndPoint { get; set; }
        public string ServiceCode { get; set; }
        public string ServiceName { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Scope { get; set; }
        public string DefaultLoginEndpoint { get; set; } = cxAuthConstants.DefaultValues.LoginEndpoint;
    }
}