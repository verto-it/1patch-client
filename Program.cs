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
builder.Services.AddSingleton<IPlatformInfo, SystemPlatformInfo>();
builder.Services.AddSingleton<IProcessRunner, SystemProcessRunner>();
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

if (opts.TrustedSigningKeys.Count == 0 && !IsDevelopment())
    errors.Add("OnePatch:TrustedSigningKeys is required (keyId -> scoped signing key metadata)");

if (opts.TrustedSigningKeys.Values.Any(k => string.Equals(k.Scope, "*", StringComparison.Ordinal)) && !IsDevelopment())
    errors.Add("OnePatch:TrustedSigningKeys must not contain wildcard signing keys");

if (opts.TrustedSigningKeys.Values.Any(k => k.IsDev && !IsDevelopment()))
    errors.Add("OnePatch:TrustedSigningKeys must not contain dev keys outside development");

if (errors.Count > 0)
{
    foreach (var error in errors)
        Console.Error.WriteLine($"[FATAL] Configuration error: {error}");
    Environment.Exit(1);
}

await host.RunAsync();

static bool IsDevelopment()
    => string.Equals(Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase) ||
       string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"), "Development", StringComparison.OrdinalIgnoreCase);
