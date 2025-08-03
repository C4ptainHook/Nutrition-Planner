using MimeKit;

namespace AuthService.Authentification.Email.Abstractions;

public interface IEmailSender
{
    Task SendEmailAsync(MimeMessage message);
}
