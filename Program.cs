using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OnePatch.Client;
using OnePatch.Client.Providers;
using OnePatch.Client.Security;
using OnePatch.Client.Services;

var builder = Host.CreateApplicationBuilder(args);
await ClientConsoleSetup.EnsureConfiguredAsync(builder.Configuration);
builder.Services.Configure<ClientOptions>(builder.Configuration.GetSection("OnePatch"));
builder.Services.AddHttpClient();
builder.Services.AddSingleton<DeviceIdentityService>();
builder.Services.AddSingleton<SigningVerificationService>();
builder.Services.AddSingleton<NodeDiscoveryService>();
builder.Services.AddSingleton<BackendNodeClient>();
builder.Services.AddSingleton<TaskSecurityVerifier>();
builder.Services.AddSingleton<IPackageProvider, PlatformPackageProvider>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();

var opts = host.Services.GetRequiredService<IOptions<ClientOptions>>().Value;
var errors = new List<string>();

if (string.IsNullOrWhiteSpace(opts.ManagementUrl))
    errors.Add("OnePatch:ManagementUrl is required");

if (string.IsNullOrWhiteSpace(opts.EnrollmentToken))
    errors.Add("OnePatch:EnrollmentToken is required");

if (opts.TrustedSigningPublicKeys.Count == 0)
    errors.Add("OnePatch:TrustedSigningPublicKeys is required (keyId -> PEM public key)");

if (errors.Count > 0)
{
    foreach (var error in errors)
        Console.Error.WriteLine($"[FATAL] Configuration error: {error}");
    Environment.Exit(1);
}

await host.RunAsync();
