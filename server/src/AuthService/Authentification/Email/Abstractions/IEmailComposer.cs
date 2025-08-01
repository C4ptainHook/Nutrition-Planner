using MimeKit;

namespace AuthService.Authentification.Email.Abstractions;

public interface IEmailComposer
{
    MimeMessage CreateConfirmationEmail(string email, string confirmationLink);
}
