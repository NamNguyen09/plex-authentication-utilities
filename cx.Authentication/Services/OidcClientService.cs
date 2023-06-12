using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using cx.Authentication.Extensions;
using cx.Authentication.Utilities.Dtos;
using cx.Authentication.Utilities.Extentions;
using cx.Authentication.Utilities.Settings;
using IdentityModel;
using IdentityModel.Client;
using log4net;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace cx.Authentication.Services
{
    public partial class OidcClientService : IOidcClientService
    {
        private static readonly ILog _logger = LogManager.GetLogger(typeof(OidcClientService));

        public async Task<string> GetAccessTokenByCodeAsync(string code, string feideOidcTokenUrl, LoginProvider loginProvider)
        {
            try
            {
                if (loginProvider == null) return null;
                var formVariables = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>(OidcConstants.TokenRequest.GrantType, OidcConstants.GrantTypes.AuthorizationCode),
                    new KeyValuePair<string, string>(OidcConstants.TokenRequest.ClientId, loginProvider.ClientId),
                    new KeyValuePair<string, string>(OidcConstants.TokenRequest.Scope, loginProvider.Scope),
                    new KeyValuePair<string, string>(OidcConstants.TokenRequest.Code, code),
                    new KeyValuePair<string, string>(OidcConstants.TokenRequest.RedirectUri, loginProvider.RedirectUri)
                };

                var formContent = new FormUrlEncodedContent(formVariables);
                formContent.Headers.ContentType.CharSet = "UTF-8";

                string svcCredentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(loginProvider.ClientId + ":" + loginProvider.ClientSecret));
                HttpClient httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", svcCredentials);

                var response = httpClient.PostAsync(feideOidcTokenUrl, formContent).GetAwaiter().GetResult();
                var jsonString = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode && !string.IsNullOrEmpty(jsonString))
                {
                    var tokenData = JObject.Parse(jsonString);
                    var accessToken = tokenData.GetValue(OidcConstants.TokenTypes.AccessToken).Value<string>();
                    ////_jwttoken = (JwtSecurityToken)_jwthandler.ReadToken(_accessToken);
                    return accessToken;
                }
                _logger.Error($"Failed to get access token by authorization code from '{feideOidcTokenUrl}'. Response {(int)response.StatusCode} - {response.StatusCode}: {jsonString}");
            }
            catch (Exception ex)
            {
                _logger.Error(ex.Message, ex);
            }
            return null;
        }

        public async Task<string> GetUserInfo(string token, string userInfoUrl)
        {
            if (string.IsNullOrWhiteSpace(token)) return await Task.FromResult("");
            try
            {
                HttpClient httpClient = new HttpClient();
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, token);

                var response = httpClient.GetAsync(userInfoUrl).GetAwaiter().GetResult();
                var jsonString = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode && !string.IsNullOrEmpty(jsonString))
                {
                    return jsonString;
                }
                _logger.Error($"Failed to get user info by token from '{userInfoUrl + userInfoUrl}'. Response {(int)response.StatusCode} - {response.StatusCode}: {jsonString}");

            }
            catch (Exception ex)
            {
                _logger.Error(ex.Message, ex);
            }
            return string.Empty;

        }
        public async Task<string> GetPersonalUserInfo(string token, string feideOidcUrl)
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(feideOidcUrl)) return await Task.FromResult("");
            try
            {
                HttpClient httpClient = new HttpClient
                {
                    BaseAddress = new Uri(feideOidcUrl)
                };
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, token);

                var endPoint = "/userinfo";
                var response = httpClient.GetAsync(endPoint).GetAwaiter().GetResult();
                var jsonString = await response.Content.ReadAsStringAsync();

                if (response.IsSuccessStatusCode && !string.IsNullOrEmpty(jsonString))
                {
                    return jsonString;
                }
                _logger.Error($"Failed to get user info by token from '{feideOidcUrl + endPoint}'. Response {(int)response.StatusCode} - {response.StatusCode}: {jsonString}");
            }
            catch (Exception ex)
            {
                _logger.Error(ex.Message, ex);
            }

            return string.Empty;
        }

        public async Task<string> GetGroupInfo(string token, string groupApiUrl)
        {

            if (string.IsNullOrWhiteSpace(token)) return await Task.FromResult("");
            try
            {
                HttpClient httpClient = new HttpClient
                {
                    BaseAddress = new Uri(groupApiUrl)
                };
                httpClient.DefaultRequestHeaders.Accept.Clear();
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer, token);

                var endPoint = "/groups/me/groups";
                var response = httpClient.GetAsync(endPoint).GetAwaiter().GetResult();
                var jsonString = await response.Content.ReadAsStringAsync();
                if (response.IsSuccessStatusCode && !string.IsNullOrEmpty(jsonString))
                {
                    return jsonString;
                }
                _logger.Error($"Failed to get group info by token from '{groupApiUrl + endPoint}'. Response {(int)response.StatusCode} - {response.StatusCode}: {jsonString}");
            }
            catch (Exception ex)
            {
                _logger.Error(ex.Message, ex);
            }

            return string.Empty;
        }

        public virtual Task SetAuthentication(AuthorizationCodeReceivedNotification context, LoginProvider ils)
        {
            if (context == null || ils == null || ils.OidcSetting == null) return Task.CompletedTask;

            var oidcSetting = ils.OidcSetting;
            if (string.IsNullOrWhiteSpace(oidcSetting.TokenEndPoint))
            {
                _logger.ErrorFormat("Missing TokenEndPoint when user login with loginserviceid: '{0}', url: '{1}'",
                       ils.LoginServiceID, ils.RedirectUri);
                return Task.CompletedTask;
            }

            string codeVerifier = context.TokenEndpointRequest.Parameters.ContainsKey(OidcConstants.TokenRequest.CodeVerifier) ?
                                            context.TokenEndpointRequest.Parameters[OidcConstants.TokenRequest.CodeVerifier] : null;
            // use the code to get the access and refresh token
            TokenClient tokenClient = new TokenClient(new HttpClient(), new TokenClientOptions
            {
                Address = oidcSetting.TokenEndPoint,
                ClientId = ils.ClientId,
                ClientSecret = ils.ClientSecret,
                ClientCredentialStyle = ClientCredentialStyle.PostBody
            });
            TokenResponse tokenResponse = tokenClient.RequestAuthorizationCodeTokenAsync(context.Code, ils.RedirectUri, codeVerifier).Result;

            // Check security level
            JwtSecurityToken jwtIdToken = new JwtSecurityToken(tokenResponse.IdentityToken);
            if (jwtIdToken != null && !string.IsNullOrWhiteSpace(oidcSetting.SecurityLevelClaimType)
                && !string.IsNullOrWhiteSpace(oidcSetting.SupportedSecurityLevel))
            {
                Claim acrClaim = jwtIdToken.Claims.FirstOrDefault(t => t.Type.EqualsIgnoreCase(oidcSetting.SecurityLevelClaimType));
                var levels = oidcSetting.SupportedSecurityLevel.Split(',');
                if (acrClaim == null || !levels.Contains(acrClaim.Value))
                {
                    _logger.Warn(string.Format("Require SecurityLevel is '{0}' when user login with authority '{1}' while the returned value is '{2}'",
                      oidcSetting.AcrValues, ils.Authority, acrClaim == null ? "" : acrClaim.Value));
                    _logger.Debug(string.Format("IdToken info: '{0}'", JsonConvert.SerializeObject(jwtIdToken)));
                    return Task.CompletedTask;
                }
            }

            string accessToken = "";
            if (string.IsNullOrWhiteSpace(oidcSetting.ClientId))
            {
                accessToken = tokenResponse.AccessToken;
            }
            else
            {
                TokenClient accessTokenClient = new TokenClient(new HttpClient(), new TokenClientOptions
                {
                    Address = oidcSetting.TokenEndPoint,
                    ClientId = oidcSetting.ClientId,
                    ClientSecret = oidcSetting.ClientSecret,
                    ClientCredentialStyle = ClientCredentialStyle.PostBody
                });
                TokenResponse accessTokenResponse = accessTokenClient.RequestClientCredentialsTokenAsync(oidcSetting.Scope).Result;
                accessToken = accessTokenResponse.AccessToken;
            }

            if (string.IsNullOrWhiteSpace(accessToken))
            {
                _logger.ErrorFormat("Cannot get access token when user login with loginserviceid: '{0}', url: '{1}'",
                       ils.LoginServiceID, ils.RedirectUri);
                return Task.CompletedTask;
            }

            ////string refreshToken = tokenResponse.RefreshToken;

            // create new identity
            var identityClaims = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationType);
            identityClaims.AddClaim(new Claim(OidcConstants.TokenRequest.Code, context.Code));
            identityClaims.AddClaim(new Claim(OidcConstants.TokenResponse.AccessToken, accessToken));
            identityClaims.AddClaim(new Claim(OidcConstants.AuthorizeResponse.ExpiresIn, DateTime.Now.AddSeconds(tokenResponse.ExpiresIn).ToLocalTime().ToString()));
            ////identityClaims.AddClaim(new Claim(ClaimKeys.RefreshToken, refreshToken));
            identityClaims.AddClaim(new Claim(OidcConstants.TokenResponse.IdentityToken, tokenResponse.IdentityToken));

            string primaryClaimValue = "";
            string secondaryClaimValue = "";
            if (string.IsNullOrWhiteSpace(oidcSetting.UserInfoEndPoint))
            {
                primaryClaimValue = jwtIdToken.GetClaimValue(ils.PrimaryClaimType);
            }
            else
            {
                // use the access token to retrieve claims from userinfo
                var userInfoResponse = this.GetUserInfo(accessToken, oidcSetting.UserInfoEndPoint).Result;
                if (string.IsNullOrWhiteSpace(userInfoResponse))
                {
                    _logger.ErrorFormat("Missing userinfo when retrieving from endpoint {0}", oidcSetting.UserInfoEndPoint);
                    return Task.CompletedTask;
                }

                JObject tokenData = JObject.Parse(userInfoResponse);
                primaryClaimValue = tokenData.GetJTokenValue(ils.PrimaryClaimType);
                secondaryClaimValue = tokenData.GetJTokenValue(ils.SecondaryClaimType);
                string eduPersonPrincipalName = tokenData.GetJTokenValue(cxClaimKeys.EduPersonPrincipalName);
                if (!string.IsNullOrWhiteSpace(eduPersonPrincipalName))
                    identityClaims.AddClaim(new Claim(cxClaimKeys.EduPersonPrincipalName, eduPersonPrincipalName));
            }

            if (!string.IsNullOrWhiteSpace(primaryClaimValue)
                 && !identityClaims.Claims.Any(t => t.Type.EqualsIgnoreCase(ils.PrimaryClaimType)))
            {
                identityClaims.AddClaim(new Claim(ils.PrimaryClaimType, primaryClaimValue));
            }

            if (!string.IsNullOrWhiteSpace(secondaryClaimValue)
                && !identityClaims.Claims.Any(t => t.Type.EqualsIgnoreCase(ils.SecondaryClaimType)))
            {
                identityClaims.AddClaim(new Claim(ils.SecondaryClaimType, secondaryClaimValue));
            }

            string sub = jwtIdToken.GetClaimValue(cxClaimKeys.Sub);
            if (!string.IsNullOrWhiteSpace(sub)
                && !identityClaims.Claims.Any(t => t.Type.EqualsIgnoreCase(cxClaimKeys.Sub)))
            {
                identityClaims.AddClaim(new Claim(cxClaimKeys.Sub, sub));
            }

            if (!string.IsNullOrWhiteSpace(oidcSetting.GroupApiEndpoint))
            {
                var groupInfoJson = this.GetGroupInfo(accessToken, oidcSetting.GroupApiEndpoint).Result;
                if (string.IsNullOrWhiteSpace(groupInfoJson))
                {
                    _logger.ErrorFormat("Missing groupinfo when retrieving from endpoint {0}", oidcSetting.GroupApiEndpoint);
                    return Task.CompletedTask;
                }

                string orgNr = groupInfoJson.GetClaimValue(cxClaimKeys.NorEduOrgNIN);
                if (string.IsNullOrWhiteSpace(orgNr)) return Task.CompletedTask;
                identityClaims.AddClaim(new Claim(cxClaimKeys.NorEduOrgNIN, orgNr));
            }

            // Set authentication
            context.AuthenticationTicket = new AuthenticationTicket(identityClaims, new AuthenticationProperties() { IsPersistent = false });

            context.OwinContext.Set(OwinContextKeys.LoginserviceId, ils.LoginServiceID);
            context.OwinContext.Set(OwinContextKeys.Authority, ils.Authority);
            context.OwinContext.Set(OwinContextKeys.RedirectUri, ils.RedirectUri);
            context.OwinContext.Set(OwinContextKeys.ClientId, ils.ClientId);
            context.OwinContext.Set(OwinContextKeys.PrimaryClaimType, ils.PrimaryClaimType);
            context.OwinContext.Set(OwinContextKeys.SecondaryClaimType, ils.SecondaryClaimType);
            context.OwinContext.Set(OwinContextKeys.LoginServiceType, ils.LoginServiceType);
            context.OwinContext.Set(OwinContextKeys.OidcSetting, oidcSetting);
            context.OwinContext.Set(OidcConstants.TokenResponse.AccessToken, accessToken);
            if (!string.IsNullOrWhiteSpace(sub)) context.OwinContext.Set(cxClaimKeys.Sub, sub);
            if (!string.IsNullOrWhiteSpace(primaryClaimValue)) context.OwinContext.Set(ils.PrimaryClaimType, primaryClaimValue);

            return Task.CompletedTask;
        }
    }
}
