using System.Collections.Immutable;
using System.Security.Claims;
using System.Web;
using AuthService.Enums;
using AuthService.Identity;
using AuthService.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthService.Authorization;

public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthorizationHelper _authService;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        AuthorizationHelper authHelper
    )
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _signInManager = signInManager;
        _userManager = userManager;
        _authService = authHelper;
    }

    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request =
            HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException(
                "The OpenID Connect request cannot be retrieved."
            );
        var application =
            await _applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException(
                "Details concerning the calling client application cannot be found."
            );
        if (await _applicationManager.GetConsentTypeAsync(application) != ConsentTypes.Explicit)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(
                    new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                            Errors.InvalidClient,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Only clients with explicit consent type are allowed.",
                    }
                )
            );
        }

        var result = await HttpContext.AuthenticateAsync(
            CookieAuthenticationDefaults.AuthenticationScheme
        );
        var parameters = _authService.ParseOAuthParameters(HttpContext, [Parameters.Prompt]);
        if (!_authService.IsAuthenticated(result, request))
        {
            return Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters),
                },
                [CookieAuthenticationDefaults.AuthenticationScheme]
            );
        }

        if (request.HasPromptValue(PromptValues.Login))
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters),
                },
                [CookieAuthenticationDefaults.AuthenticationScheme]
            );
        }

        if (request.HasPromptValue(PromptValues.Login))
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters),
                },
                [CookieAuthenticationDefaults.AuthenticationScheme]
            );
        }

        var consentClaim = result.Principal!.GetClaim(AppClaimTypes.Consent);
        if (
            consentClaim != ConsentDecision.Grant.ToString()
            || request.HasPromptValue(PromptValues.Consent)
        )
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            var returnUrl = HttpUtility.UrlEncode(
                _authService.BuildRedirectUrl(HttpContext.Request, parameters)
            );
            var consentRedirectUrl = $"/Consent?returnUrl={returnUrl}";

            return Redirect(consentRedirectUrl);
        }
        var userId = result.Principal!.FindFirst(ClaimTypes.Email)!.Value;

        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role
        );

        identity
            .SetClaim(Claims.Subject, userId)
            .SetClaim(Claims.Email, userId)
            .SetClaim(Claims.Name, userId)
            .SetClaims(Claims.Role, new List<string> { "user", "admin" }.ToImmutableArray());

        identity.SetScopes(request.GetScopes());
        identity.SetResources(
            await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync()
        );
        identity.SetDestinations(c => AuthorizationHelper.GetDestinations(identity, c));

        return SignIn(
            new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
    }
}
