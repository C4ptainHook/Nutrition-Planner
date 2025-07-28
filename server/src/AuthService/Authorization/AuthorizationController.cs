using System.Collections.Immutable;
using System.Security.Claims;
using AuthService.Enums;
using AuthService.Identity;
using AuthService.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace AuthService.Authorization;

[ApiController]
public class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly AuthorizationHelper _authService;
    private readonly SignInManager<ApplicationUser> _signInManager;

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
        _signInManager = signInManager;
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

        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        var parameters = _authService.ParseOAuthParameters(HttpContext, [Parameters.Prompt]);
        if (!_authService.IsAuthenticated(result, request))
        {
            return Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters),
                },
                [IdentityConstants.ApplicationScheme]
            );
        }

        if (request.HasPromptValue(PromptValues.Login))
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

            return Challenge(
                properties: new AuthenticationProperties
                {
                    RedirectUri = _authService.BuildRedirectUrl(HttpContext.Request, parameters),
                },
                [IdentityConstants.ApplicationScheme]
            );
        }

        var consentClaim = result.Principal!.GetClaim(AppClaimTypes.Consent);
        if (
            consentClaim != ConsentDecision.Grant.ToString()
            || request.HasPromptValue(PromptValues.Consent)
        )
        {
            var returnUrl = _authService.BuildRedirectUrl(
                HttpContext.Request,
                _authService.ParseOAuthParameters(HttpContext)
            );
            var clientConsentUrl = "http://localhost:5173/consent";
            var redirectUrl = $"{clientConsentUrl}?returnUrl={Uri.EscapeDataString(returnUrl)}";
            return Redirect(redirectUrl);
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

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request =
            HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException(
                "The OpenID Connect request cannot be retrieved."
            );

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
        {
            throw new InvalidOperationException("The specified grant type is not supported.");
        }

        var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );

        var userId = result.Principal!.GetClaim(Claims.Subject);
        if (string.IsNullOrEmpty(userId))
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(
                    new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                            Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The authorization code is invalid or has expired.",
                    }
                )
            );
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user is null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(
                    new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                            Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The user associated with the authorization code no longer exists.",
                    }
                )
            );
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

        identity.SetClaim(
            "AspNet.Identity.SecurityStamp",
            await _userManager.GetSecurityStampAsync(user)
        );

        identity.SetScopes(result.Principal!.GetScopes());
        identity.SetResources(
            await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync()
        );
        identity.SetDestinations(claim => AuthorizationHelper.GetDestinations(identity, claim));

        return SignIn(
            new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        );
    }

    [Authorize(AuthenticationSchemes = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)]
    [HttpGet("~/connect/userinfo"), HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(
                    new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] =
                            Errors.InvalidToken,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The token is invalid or the user associated with it no longer exists.",
                    }
                )
            );
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [Claims.Subject] = await _userManager.GetUserIdAsync(user),
        };

        if (User.HasScope(Scopes.Email))
        {
            claims[Claims.Email] = await _userManager.GetEmailAsync(user) ?? string.Empty;
            claims[Claims.EmailVerified] = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (User.HasScope(Scopes.Profile))
        {
            claims[Claims.Name] = await _userManager.GetUserNameAsync(user) ?? string.Empty;
            claims["nickname"] = user.Nickname ?? string.Empty;
        }

        if (User.HasScope(Scopes.Roles))
        {
            claims[Claims.Role] = await _userManager.GetRolesAsync(user);
        }

        return Ok(claims);
    }

    [HttpPost("~/connect/consent")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Consent(
        [FromForm] string decision,
        [FromForm] string returnUrl
    )
    {
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        if (!result.Succeeded || result.Principal?.Identity is not ClaimsIdentity identity)
        {
            return BadRequest(
                "Your session has expired. Please close this window and try logging in again."
            );
        }
        if (decision != "grant")
        {
            return Redirect("http://localhost:5173/access-denied"); // TODO: add access denied page
        }
        var consentClaim = identity.FindFirst(AppClaimTypes.Consent);
        if (consentClaim is not null)
        {
            identity.RemoveClaim(consentClaim);
        }

        identity.AddClaim(new Claim(AppClaimTypes.Consent, ConsentDecision.Grant.ToString()));
        var newPrincipal = new ClaimsPrincipal(identity);
        await HttpContext.SignInAsync(
            IdentityConstants.ApplicationScheme,
            newPrincipal,
            result.Properties
        );

        return LocalRedirect(returnUrl);
    }

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        await _signInManager.SignOutAsync();

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties { RedirectUri = "/" }
        );
    }
}
