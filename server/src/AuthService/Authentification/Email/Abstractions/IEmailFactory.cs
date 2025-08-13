using MimeKit;

namespace AuthService.Authentification.Email.Abstractions;

public interface IEmailFactory
{
    MimeMessage CreateConfirmationEmail(string email, string confirmationLink);
    MimeMessage CreatePasswordResetEmail(string email, string otp);
}
