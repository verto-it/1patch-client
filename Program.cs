using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OnePatch.Client;
using OnePatch.Client.Providers;
using OnePatch.Client.Services;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.Configure<ClientOptions>(builder.Configuration.GetSection("OnePatch"));
builder.Services.AddHttpClient();
builder.Services.AddSingleton<DeviceIdentityService>();
builder.Services.AddSingleton<NodeDiscoveryService>();
builder.Services.AddSingleton<BackendNodeClient>();
builder.Services.AddSingleton<IPackageProvider, PlatformPackageProvider>();
builder.Services.AddHostedService<Worker>();

await builder.Build().RunAsync();
