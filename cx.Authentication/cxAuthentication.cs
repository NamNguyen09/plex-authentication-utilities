using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using cx.Authentication.Services;
using cx.Authentication.Utilities.Dtos;
using cx.Authentication.Utilities.Enums;
using cx.Authentication.Utilities.Extentions;
using IdentityModel;
using log4net;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.WsFederation;
using Owin;

namespace cx.Authentication
{
    public static class cxAuthentication
    {
        private static readonly ILog _logger = LogManager.GetLogger(typeof(cxAuthentication));
        public static IAppBuilder RegisterLoginProvider(this IAppBuilder app, LoginProvider ils)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (string.IsNullOrWhiteSpace(ils.MetadataAddress)
              || string.IsNullOrWhiteSpace(ils.RedirectUri)
              || ils.OidcSetting == null) return app;

            if (ils.LoginServiceType == (int)cxLoginType.ADFS)
            {
                app.UseWsFederationAuthentication(new WsFederationAuthenticationOptions
                {
                    MetadataAddress = ils.MetadataAddress,// The path to xml file contains configuration for ADFS server
                    Wtrealm = ils.RedirectUri, // This usually be home page of the web appilcation,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = false,
                    }
                });

                return app;
            }
            else if (ils.LoginServiceType == (int)cxLoginType.AADB2C)
            {
                //For now:
                //Issuer: Represent for B2C policy
                //RealmUrl: Represent to B2C appication id (client id)
                //HomeRealm: Represent to B2C tenant
                ////app.UseOpenIdConnectAuthentication(CreateOptionsFromPolicy(ils.Issuer, ils.RealmUrl, ils.HomeRealm));
                return app;
            }

            _logger.Debug(string.Format("RedirectUri: {0}", ils.RedirectUri));
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = ils.ClientId,
                ClientSecret = ils.ClientSecret,
                Authority = ils.Authority,
                RedirectUri = ils.RedirectUri,
                ResponseType = ils.ResponseType,
                Scope = ils.Scope,
                UseTokenLifetime = false,
                AuthenticationType = ils.ClientId,
                SignInAsAuthenticationType = CookieAuthenticationDefaults.AuthenticationType,
                MetadataAddress = ils.MetadataAddress,
                PostLogoutRedirectUri = ils.PostLogoutUri,
                ProtocolValidator = new OpenIdConnectProtocolValidator
                {
                    RequireNonce = ils.ResponseType.ContainsIgnoreCase(OidcConstants.ResponseTypes.IdToken),
                    RequireState = false,
                    RequireStateValidation = false
                },
                UsePkce = true,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = (context) =>
                    {
                        if (context.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var idTokenHint = ClaimsPrincipal.Current.Claims.FirstOrDefault(t => t.Type == OidcConstants.TokenTypes.IdentityToken);
                            if (idTokenHint != null)
                            {
                                context.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                            }

                            context.ProtocolMessage.PostLogoutRedirectUri = ils.PostLogoutUri;
                        }

                        if (context.ProtocolMessage.RequestType != OpenIdConnectRequestType.Authentication) return Task.FromResult(0);

                        // hack to work around session cookie not being removed when expires. this is preventing owin from accepting an open id response
                        context.OwinContext.Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);

                        context.Response.OnSendingHeaders(x =>
                        {
                            var scv = context.Response.Headers.FirstOrDefault(h => h.Key == "Set-Cookie");
                            if (!scv.Equals(default(KeyValuePair<string, string[]>)))
                            {
                                foreach (var item in scv.Value.Where(t => t.ContainsIgnoreCase("nonce")))
                                {
                                    context.Response.Headers.Set("Set-Cookie", item + "; SameSite=None;Secure");
                                }
                            }

                        }, null);

                        if (!string.IsNullOrWhiteSpace(ils.OidcSetting.AcrValues)
                           && !context.ProtocolMessage.Parameters.ContainsKey(OidcConstants.AuthorizeRequest.AcrValues))
                        {
                            context.ProtocolMessage.Parameters.Add(OidcConstants.AuthorizeRequest.AcrValues, ils.OidcSetting.AcrValues);
                        }

                        return Task.FromResult(0);
                    },
                    AuthorizationCodeReceived = context =>
                    {
                        IOidcClientService oidcClientService = new OidcClientService();
                        return oidcClientService.GetClaimsAndAuthentication(context, ils);
                    },
                    AuthenticationFailed = (context) =>
                    {
                        if (context.Exception.Message.StartsWith("OICE_20004") || context.Exception.Message.Contains("IDX10311"))
                        {
                            _logger.Error("OIDC - Error IDX10311 have been handled by redirect to refresh nonce");
                            context.HandleResponse();
                            context.Response.Redirect(ils.BaseUrl + string.Format("{0}?LoginServiceId={1}", ils.OidcSetting.DefaultLoginEndpoint, ils.LoginServiceID));
                        }
                        else
                        {
                            _logger.Error(context.Exception);
                        }
                        return Task.FromResult(0);
                    }
                }
            });

            return app;
        }
    }
}
