using System.Collections.Generic;
using System.Linq;
using cx.Authentication.Utilities.Dtos;
using cx.Authentication.Utilities.Settings;
using cx.Utiities;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace cx.Authentication.Extensions
{
    public static class LoginProviderExtensions
    {
        public static string GetPrimaryClaimType(this string claimTypeUri)
        {
            if (string.IsNullOrWhiteSpace(claimTypeUri)) return "";
            if (!claimTypeUri.Contains("/")) return claimTypeUri;
            var arrPrimaryClaims = claimTypeUri.Split('/');
            return arrPrimaryClaims.LastOrDefault();
        }
        public static string GetJTokenValue(this JObject jObj, string claimType)
        {
            if (string.IsNullOrWhiteSpace(claimType) || jObj == null) return "";
            var jToken = jObj.GetValue(claimType.GetPrimaryClaimType());
            if (jToken == null) return "";
            return jToken.Value<string>();
        }
        public static string GetClaimValue(this string feideGroupInfoJson, string claimType)
        {
            if (string.IsNullOrWhiteSpace(claimType) || string.IsNullOrWhiteSpace(feideGroupInfoJson)) return "";
            List<FeideGroup> feideGroups = JsonConvert.DeserializeObject<List<FeideGroup>>(feideGroupInfoJson);
            if (feideGroups == null || !feideGroups.Any()) return "";
            foreach (var item in feideGroups)
            {
                if (item.OrgType == null ||
                    !item.OrgType.Any(t => t.EqualsIgnoreCase(cxAuthConstants.ClaimKeys.GroupOwnerPrimaryAndLowerSecondaryType)
                                         || t.EqualsIgnoreCase(cxAuthConstants.ClaimKeys.GroupOwnerUpperSecondaryType))) continue;

                if (string.IsNullOrEmpty(item.NorEduOrgNIN)) return "";
                return item.NorEduOrgNIN;
            }

            return "";
        }
    }
}
