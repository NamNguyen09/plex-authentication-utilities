namespace cx.Authentication.Utilities.Settings
{
    public static class cxClaimKeys
    {
        public const string AuthProvider = "http://schemas.microsoft.com/identity/claims/identityprovider";
        public const string UserObjectId = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
        public const string FirstName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
        public const string LastName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";
        public const string Email = "emails";
        public const string MobilePhone = "extension_MobilePhone";
        public const string DateOfBirth = "extension_DateOfBirth";
        public const string Gender = "extension_Gender";
        public const string CountryName = "country";
        public const string CountryCode = "extension_CountryCode";
        public const string Locale = "locale";
        public const string EduPersonPrincipalName = "eduPPN";
        public const string SSN = "ssn";
        public const string OrgNum = "orgNum";
        public const string PrincipalName = "http://feide.no/eduPersonPrincipalName";
        public const string NorEduOrgNIN = "http://feide.no/norEduOrgNIN";
        public const string NorEduPersonNIN = "http://feide.no/norEduPersonNIN";
        public const string GroupOwnerPrimaryAndLowerSecondaryType = "primary_and_lower_secondary_owner";
        public const string GroupOwnerUpperSecondaryType = "upper_secondary_owner";
        public const string UserId = "uid";
        public const string Sub = "sub";
        public const string GivenName = "given_name";
        public const string FamilyName = "family_name";
    }
}
