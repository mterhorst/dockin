using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json.Serialization;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Dockin
{
    public class Program
    {
        private static readonly ConcurrentDictionary<string, DateTime> _states = new();

        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateSlimBuilder(new WebApplicationOptions
            {
                Args = args,
                WebRootPath = ""
            });

            if (builder.Environment.IsDevelopment())
            {
                builder.WebHost.UseKestrelHttpsConfiguration();
            }

            builder.WebHost.ConfigureKestrel(serverOptions =>
            {
                serverOptions.Limits.MaxRequestBodySize = long.MaxValue;
                serverOptions.AddServerHeader = false;
            });

            builder.Services.ConfigureHttpJsonOptions(options =>
            {
                options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
            });

            builder.Services.AddHttpContextAccessor();

            builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

            builder.Services.AddSingleton<IAuthorizationPolicyProvider, DynamicAuthPolicyProvider>();

            var entraId = builder.Configuration.GetEntraId();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                // The "s_" prefix marks proxy session cookies; they are stripped before requests are forwarded.
                options.Cookie.Name = "s_";
                options.Cookie.HttpOnly = true;
            })
            .AddJwtBearer(options =>
            {
                options.Authority = $"https://login.microsoftonline.com/{entraId.Tenantid}/v2.0";
                options.Audience = entraId.Clientid;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true
                };

                options.Events = new JwtBearerEvents
                {
                    OnAuthenticationFailed = context =>
                    {
                        Console.WriteLine("OnAuthenticationFailed");
                        Console.WriteLine(context.Exception.ToString());
                        return Task.CompletedTask;
                    }
                };
            })
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                options.Authority = $"https://login.microsoftonline.com/{entraId.Tenantid}/v2.0";
                options.ClientId = entraId.Clientid;
                options.ClientSecret = entraId.Clientsecret;
                options.ResponseType = "code";
                options.SaveTokens = true;
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("https://graph.microsoft.com/.default");

                if (builder.Environment.IsProduction())
                {
                    // Behind a TLS-terminating proxy the request scheme is http, so build the https redirect URI explicitly.
                    options.Events = new OpenIdConnectEvents
                    {
                        OnRedirectToIdentityProvider = context =>
                        {
                            var request = context.Request;
                            var host = request.Host.Value;
                            var pathBase = request.PathBase.Value;
                            var callbackPath = context.Options.CallbackPath.Value;
                            var redirectUri = $"https://{host}{pathBase}{callbackPath}";

                            context.ProtocolMessage.RedirectUri = redirectUri;

                            return Task.CompletedTask;
                        }
                    };
                }

                // Drop the client secret from the retained config once it has been handed to the OIDC options.
                entraId = entraId with { Clientsecret = string.Empty };
            });

            builder.Services.AddSingleton<ITransformProvider, DynamicDestinationTransformProvider>();

            var app = builder.Build();

            // Starts the admin consent flow by redirecting to Entra ID with a one-time state value.
            app.MapGet("/admin-consent", () =>
            {
                var clientId = entraId.Clientid;
                var scopes = Uri.EscapeDataString("openid profile https://graph.microsoft.com/.default");

                var state = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
                _states[state] = DateTime.UtcNow;

                var url = $"https://login.microsoftonline.com/{entraId.Tenantid}/v2.0/adminconsent" +
                          $"?client_id={clientId}" +
                          $"&scope={scopes}" +
                          $"&redirect_uri={entraId.Redirecturi}" +
                          $"&state={state}";

                return Results.Redirect(url);
            });

            // Receives the admin consent result and validates the state issued by /admin-consent.
            app.MapGet("/admin-consent/callback", (
                [FromQuery] string? state,
                [FromQuery] string? admin_consent,
                [FromQuery] string? tenant,
                [FromQuery] string? scope,
                [FromQuery] string? error,
                [FromQuery] string? error_description) =>
            {
                if (!_states.TryRemove(state ?? "", out _))
                {
                    return Results.Text("Invalid or missing state parameter.");
                }

                if (admin_consent == "True")
                {
                    return Results.Text($"Consent granted for tenant {tenant} scope={scope}");
                }

                return Results.Text($"Consent failed: {error} - {error_description}");
            });

            app.MapGet("/logout", async (HttpContext context) =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                var callbackUrl = Uri.EscapeDataString("https://localhost:5000/");
                var tenantId = entraId.Tenantid;
                var logoutUrl = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/logout?post_logout_redirect_uri={callbackUrl}";

                await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
                {
                    RedirectUri = logoutUrl
                });
            });

            app.MapReverseProxy(proxyPipeline =>
            {
            });

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.Run();
        }
    }

    public record EntraId(string Tenantid, string Clientid, string Clientsecret, string Redirecturi);
    public record App(string Name, int Port);

    [JsonSerializable(typeof(EntraId))]
    [JsonSerializable(typeof(App))]
    internal partial class AppJsonSerializerContext : JsonSerializerContext { }

    public class DynamicDestinationTransformProvider : ITransformProvider
    {
        /// <inheritdoc/>

        public void ValidateRoute(TransformRouteValidationContext context)
        {

        }

        /// <inheritdoc/>
        public void ValidateCluster(TransformClusterValidationContext context)
        {

        }

        /// <inheritdoc/>
        public void Apply(TransformBuilderContext context)
        {
            context.RequestTransforms.Add(new DynamicDestinationTransform(context.Services));
        }

        private sealed class DynamicDestinationTransform : RequestTransform
        {
            private readonly App _app;
            private readonly ILogger<DynamicDestinationTransform> _logger;

            public DynamicDestinationTransform(IServiceProvider services)
            {
                var config = services.GetRequiredService<IConfiguration>();
                _app = config.GetApp();
                _logger = services.GetRequiredService<ILogger<DynamicDestinationTransform>>();
            }

            /// <summary>
            /// Builds the destination URI from the configured app name and port, preserving the
            /// request path and query string, and rewrites the proxy request to use it.
            /// </summary>
            public override async ValueTask ApplyAsync(RequestTransformContext context)
            {
                Log.LogFoundSelectedApp(_logger, _app);

                var newUri = new UriBuilder("http",
                                            _app.Name,
                                            _app.Port,
                                            context.HttpContext.Request.Path,
                                            context.HttpContext.Request.QueryString.Value).Uri;

                Log.LogProxyUri(_logger, newUri);

                Rewrite(context, newUri);

                await ValueTask.CompletedTask;
            }
        }

        /// <summary>
        /// Points the proxy request at the new URI and sets the Host header to match.
        /// Cookies prefixed with "s_" belong to the proxy session and are removed before forwarding.
        /// </summary>
        private static void Rewrite(RequestTransformContext context, Uri uri)
        {
            if (context.ProxyRequest.Headers.TryGetValues("Cookie", out var cookieHeaders))
            {
                var filteredCookies = cookieHeaders
                    .SelectMany(header => header.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    .Select(cookie => cookie.Trim())
                    .Where(cookie =>
                    {
                        var cookieName = cookie.Split('=', 2)[0].Trim();
                        return !cookieName.StartsWith("s_", StringComparison.OrdinalIgnoreCase);
                    });

                var newCookieHeader = string.Join("; ", filteredCookies);
                context.ProxyRequest.Headers.Remove("Cookie");
                if (!string.IsNullOrEmpty(newCookieHeader))
                {
                    context.ProxyRequest.Headers.Add("Cookie", newCookieHeader);
                }
            }

            context.ProxyRequest.RequestUri = uri;
            context.ProxyRequest.Headers.Host = uri.Authority;
        }
    }

    public sealed class DynamicAuthPolicyProvider : DefaultAuthorizationPolicyProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public DynamicAuthPolicyProvider(IOptions<AuthorizationOptions> options, IHttpContextAccessor httpContextAccessor) : base(options)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        /// <summary>
        /// Ignores the policy name and always requires an authenticated user.
        /// The JWT scheme is added when the request carries a matching Authorization header.
        /// </summary>
        public override Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
        {
            var policyBuilder = new AuthorizationPolicyBuilder();

            if (_httpContextAccessor.HttpContext?.Request.Headers.TryGetValue("Authorization", out var authHeader) == true && 
                AuthenticationHeaderValue.TryParse(authHeader, out var authHeaderValue) &&
                string.Equals(authHeaderValue.Scheme, "Bearer", StringComparison.OrdinalIgnoreCase))
            {
                policyBuilder.AddAuthenticationSchemes("Bearer");
            }

            policyBuilder.RequireAuthenticatedUser();

            return Task.FromResult(policyBuilder.Build())!;
        }
    }
}