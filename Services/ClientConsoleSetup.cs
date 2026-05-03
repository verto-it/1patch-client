using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;

namespace OnePatch.Client.Services;

public static class ClientConsoleSetup
{
    private const string AppSettingsPath = "appsettings.json";

    public static async Task EnsureConfiguredAsync(IConfiguration configuration)
    {
        if (HasRequiredConfig(configuration))
            return;

        if (!Environment.UserInteractive)
        {
            Console.Error.WriteLine("[FATAL] 1Patch client is not configured. Run it once in an interactive console and paste the dashboard client JSON.");
            Environment.Exit(1);
            return;
        }

        Console.WriteLine();
        Console.WriteLine("1Patch Client Console Setup");
        Console.WriteLine("---------------------------");
        Console.WriteLine("Create a client config in the management dashboard, then choose how to enter it.");
        Console.WriteLine();

        var onePatch = await PromptForConfigAsync();
        Apply(configuration, onePatch);
        WriteAppSettings(onePatch);

        Console.WriteLine();
        Console.WriteLine("Client configuration saved.");
        Console.WriteLine($"Tenant:         {onePatch["TenantId"]}");
        Console.WriteLine($"Management URL: {onePatch["ManagementUrl"]}");
        Console.WriteLine($"Heartbeat:      {onePatch["HeartbeatSeconds"]}s");
        Console.WriteLine($"Inventory:      {onePatch["InventoryMinutes"]}m");
        Console.WriteLine();
    }

    private static bool HasRequiredConfig(IConfiguration configuration)
        => !string.IsNullOrWhiteSpace(configuration["OnePatch:ManagementUrl"])
           && !string.IsNullOrWhiteSpace(configuration["OnePatch:EnrollmentToken"])
           && !string.IsNullOrWhiteSpace(configuration["OnePatch:ManifestSigningSecret"]);

    private static async Task<JsonObject> PromptForConfigAsync()
    {
        while (true)
        {
            Console.Write("Enter client config as JSON or individual fields? [json/individual]: ");
            var mode = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
            if (mode is "" or "json" or "j")
                return await PromptForJsonConfigAsync();
            if (mode is "individual" or "i")
                return PromptForIndividualConfig();
            Console.WriteLine("Enter 'json' or 'individual'.");
        }
    }

    private static async Task<JsonObject> PromptForJsonConfigAsync()
    {
        while (true)
        {
            Console.WriteLine("Paste client JSON, then press Enter on a blank line.");
            Console.Write("Client JSON: ");
            var pasted = await ReadJsonBlockAsync();
            var config = ParseConfig(pasted);
            if (config is not null)
            {
                Console.WriteLine("Client JSON accepted.");
                return config;
            }
            Console.WriteLine("Could not parse client JSON. Paste the full JSON object again, then press Enter on a blank line.");
        }
    }

    private static async Task<string> ReadJsonBlockAsync()
    {
        var lines = new List<string>();
        while (true)
        {
            var line = await Task.Run(Console.ReadLine);
            if (line is null || (line.Length == 0 && lines.Count > 0)) break;
            if (line.Length == 0) continue;
            lines.Add(line);
            if (LooksCompleteJson(string.Join(Environment.NewLine, lines))) break;
        }
        return string.Join(Environment.NewLine, lines);
    }

    private static bool LooksCompleteJson(string value)
    {
        var start = value.IndexOf('{');
        var end = value.LastIndexOf('}');
        if (start < 0 || end <= start) return false;
        try
        {
            JsonNode.Parse(value[start..(end + 1)]);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static JsonObject? ParseConfig(string raw)
    {
        var start = raw.IndexOf('{');
        var end = raw.LastIndexOf('}');
        if (start < 0 || end <= start) return null;

        try
        {
            var root = JsonNode.Parse(raw[start..(end + 1)])?.AsObject();
            if (root is null) return null;

            if (root["OnePatch"] is JsonObject onePatch && IsValid(onePatch))
                return onePatch;

            if (root["clients"] is JsonArray clients)
            {
                var choices = clients
                    .OfType<JsonObject>()
                    .Select(client => new
                    {
                        Label = client["label"]?.GetValue<string>() ?? "client",
                        Config = client["config"]?["OnePatch"] as JsonObject,
                    })
                    .Where(client => client.Config is not null && IsValid(client.Config))
                    .ToList();

                if (choices.Count == 0) return null;
                if (choices.Count == 1) return choices[0].Config!;

                Console.WriteLine("Batch config contains:");
                foreach (var choice in choices)
                    Console.WriteLine($"- {choice.Label}");
                Console.Write($"Client label to use [{choices[0].Label}]: ");
                var selected = (Console.ReadLine() ?? "").Trim();
                return choices.FirstOrDefault(choice => string.Equals(choice.Label, selected, StringComparison.OrdinalIgnoreCase))?.Config
                       ?? choices[0].Config!;
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static bool IsValid(JsonObject config)
        => HasValue(config, "TenantId")
           && HasValue(config, "ManagementUrl")
           && HasValue(config, "EnrollmentToken")
           && HasValue(config, "ManifestSigningSecret");

    private static bool HasValue(JsonObject config, string key)
        => !string.IsNullOrWhiteSpace(config[key]?.GetValue<string>());

    private static JsonObject PromptForIndividualConfig()
    {
        var managementUrl = Ask("Management URL", "http://localhost:4100");
        var trusted = Ask("Trusted download hosts", managementUrl);
        return new JsonObject
        {
            ["TenantId"] = Ask("Tenant", "default"),
            ["ManagementUrl"] = managementUrl,
            ["EnrollmentToken"] = Ask("Enrollment token", ""),
            ["ClientName"] = Ask("Client name override", ""),
            ["ManifestSigningSecret"] = Ask("Manifest signing secret", ""),
            ["TrustedDownloadHosts"] = new JsonArray(trusted.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(v => JsonValue.Create(v)).ToArray<JsonNode?>()),
            ["HeartbeatSeconds"] = ReadInt("Heartbeat seconds", 60),
            ["InventoryMinutes"] = ReadInt("Inventory minutes", 30),
            ["NodeProbeTimeoutMilliseconds"] = ReadInt("Node probe timeout milliseconds", 2000),
        };
    }

    private static string Ask(string label, string fallback)
    {
        Console.Write($"{label}{(string.IsNullOrWhiteSpace(fallback) ? "" : $" [{fallback}]")}: ");
        var value = Console.ReadLine();
        return string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
    }

    private static int ReadInt(string label, int fallback)
        => int.TryParse(Ask(label, fallback.ToString()), out var value) && value > 0 ? value : fallback;

    private static void Apply(IConfiguration configuration, JsonObject onePatch)
    {
        foreach (var item in onePatch)
        {
            if (item.Value is JsonArray array)
            {
                for (var i = 0; i < array.Count; i++)
                    configuration[$"OnePatch:{item.Key}:{i}"] = array[i]?.GetValue<string>();
                continue;
            }
            configuration[$"OnePatch:{item.Key}"] = item.Value?.ToString();
        }
    }

    private static void WriteAppSettings(JsonObject onePatch)
    {
        JsonObject root;
        if (File.Exists(AppSettingsPath))
        {
            root = JsonNode.Parse(File.ReadAllText(AppSettingsPath))?.AsObject() ?? new JsonObject();
        }
        else
        {
            root = new JsonObject();
        }

        root["OnePatch"] = onePatch.DeepClone();
        File.WriteAllText(AppSettingsPath, root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }
}
