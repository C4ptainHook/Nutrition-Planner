using AuthService.Authentification.Email.Abstractions;
using MimeKit;

namespace AuthService.Authentification.Email;

public sealed class EmailComposer(IConfiguration configuration) : IEmailComposer
{
    public MimeMessage CreateConfirmationEmail(string email, string confirmationLink)
    {
        var appName = configuration["ClientSettings:AppName"]!;
        var subject = $"{appName} - Confirm your email";
        var body = $"""
            <p>Hi,</p>
            <p>Thank you for registering with {appName}.</p>
            <p>Please confirm your email address by clicking the link below:</p>
            <a href="{confirmationLink}">Confirm Email</a>
            <p>If you did not register, please ignore this email.</p>
            <p>Best regards,</p>
            <p>{appName} Team</p>
            """;

        return new MimeMessage
        {
            Subject = subject,
            Body = new TextPart("html") { Text = body },
            From = { new MailboxAddress(appName, configuration["EmailSettings:FromEmail"]!) },
            To = { new MailboxAddress(email, email) },
        };
    }
}
