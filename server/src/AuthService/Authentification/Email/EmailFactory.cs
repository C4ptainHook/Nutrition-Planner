using AuthService.Authentification.Email.Abstractions;
using MimeKit;

namespace AuthService.Authentification.Email;

public sealed class EmailFactory(IConfiguration configuration) : IEmailFactory
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

    public MimeMessage CreatePasswordResetEmail(string email, string otp)
    {
        var appName = configuration["ClientSettings:AppName"]!;
        var subject = $"{appName} - Your Password Reset Code";
        var body = $"""
            <p>Hi,</p>
            <p>A request was received to reset the password for your account.</p>
            <p>Use the following code to complete the process. This code is valid for 10 minutes.</p>
            <h2 style="font-family: 'Courier New', Courier, monospace; letter-spacing: 5px; text-align: center;">{otp}</h2>
            <p>If you did not request a password reset, please ignore this email.</p>
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
