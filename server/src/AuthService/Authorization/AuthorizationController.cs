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

[ApiController]
public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthorizationHelper _authService;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        AuthorizationHelper authHelper
    )
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _authService = authHelper;
        _userManager = userManager;
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

        var user = await _userManager.GetUserAsync(result.Principal!);
        if (user == null)
        {
            return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role
        );

        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user));

        identity.SetClaim(Claims.Email, await _userManager.GetEmailAsync(user));

        identity.SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user));

        var userRoles = await _userManager.GetRolesAsync(user);
        identity.SetClaims(Claims.Role, userRoles.ToImmutableArray());

        if (!string.IsNullOrEmpty(user.Nickname))
        {
            identity.SetClaim("nickname", user.Nickname);
        }

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
