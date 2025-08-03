using AuthService.Authentification.Email.Abstractions;
using AuthService.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthService.Authentification.Email;

public class EmailLinkFactory(
    IHttpContextAccessor context,
    UserManager<ApplicationUser> userManager,
    LinkGenerator linkGenerator
) : IEmailLinkFactory
{
    public async Task<string> CreateConfirmationLink(string email)
    {
        var user =
            await userManager.FindByEmailAsync(email)
            ?? throw new ArgumentException("Invalid email address.");
        var token = await userManager.GenerateEmailConfirmationTokenAsync(user);
        var callbackUrl = linkGenerator.GetUriByAction(
            context.HttpContext!,
            action: "ConfirmEmail",
            controller: "Authentication",
            values: new { email, token }
        );
        return callbackUrl
            ?? throw new InvalidOperationException("Failed to generate confirmation link.");
    }
}
