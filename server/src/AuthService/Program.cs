using AuthService.Authentification.Email;
using AuthService.Authentification.Email.Abstractions;
using AuthService.Authorization;
using AuthService.Data;
using AuthService.Data.Extensions;
using AuthService.Identity;
using AuthService.Models;
using AuthService.Seeders;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy
            .WithOrigins(builder.Configuration["ClientSettings:RootUrl"]!)
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.AddControllers();
builder.Services.AddOpenApi();
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("IdentityStorage")!);
    options.UseOpenIddict();
});
builder
    .Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        var clientLoginUrl = $"{builder.Configuration["ClientSettings:RootUrl"]}/login";
        var serverUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        context.Response.Redirect(
            $"{clientLoginUrl}?returnUrl={serverUrl}{Uri.EscapeDataString(context.Properties.RedirectUri ?? "/")}"
        );
        return Task.CompletedTask;
    };

    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.None;
});

builder
    .Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore().UseDbContext<AuthDbContext>();
    })
    .AddServer(options =>
    {
        options
            .SetAuthorizationEndpointUris("connect/authorize")
            .SetEndSessionEndpointUris("connect/logout")
            .SetTokenEndpointUris("connect/token")
            .SetUserInfoEndpointUris("connect/userinfo");

        options.RegisterScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Roles);

        options.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow();
        options.AddDevelopmentEncryptionCertificate().AddDevelopmentSigningCertificate();
        options
            .UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableEndSessionEndpointPassthrough()
            .EnableStatusCodePagesIntegration()
            .EnableTokenEndpointPassthrough();
    });

builder.Services.AddHostedService<ClientSeeder>();
builder.Services.AddHostedService<RoleSeeder>();
builder.Services.AddScoped<AuthorizationHelper>();
builder.Services.AddScoped<
    IUserClaimsPrincipalFactory<ApplicationUser>,
    ApplicationClaimsPrincipalFactory
>();
builder.Services.AddScoped<IEmailComposer, EmailComposer>();
builder.Services.AddScoped<IEmailSender, EmailSender>();
builder.Services.AddScoped<IEmailVerificationFactory, EmailVerificationFactory>();

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}
app.UseHttpsRedirection();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.UseMigration();
app.MapControllers();
app.Run();
