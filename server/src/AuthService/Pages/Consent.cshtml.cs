using System.Security.Claims;
using AuthService.Enums;
using AuthService.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace AuthService.Pages;

[Authorize]
public class ConsentModel : PageModel
{
    public string? ReturnUrl { get; set; }

    public void OnGet(string? returnUrl = null)
    {
        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync(string decision, string? returnUrl = null)
    {
        ReturnUrl = returnUrl ?? Url.Content("~/");
        if (decision == ConsentDecision.Grant.ToString())
        {
            if (User.Identity is not ClaimsIdentity identity)
            {
                return Forbid();
            }

            identity.AddClaim(new Claim(AppClaimTypes.Consent, ConsentDecision.Grant.ToString()));
            var updatedPrincipal = new ClaimsPrincipal(identity);
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                updatedPrincipal
            );
        }

        return LocalRedirect(ReturnUrl);
    }
}
