using Pondhawk.Waf;
using Pondhawk.Waf.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddPondhawkWaf(options =>
{
    // Start in DetectionOnly, review the "Pondhawk.Waf.Rules" log, then switch to On.
    options.RuleEngine = builder.Configuration.GetValue("Waf:Enforce", false) ? RuleEngineMode.On : RuleEngineMode.DetectionOnly;
    options.ParanoiaLevel = 1;
    options.Bypass = ctx => ctx.Request.Path == "/healthz";

    // Example exclusion: the "password" argument of /login never triggers SQLi rules.
    options.Directives = """
        SecRule REQUEST_FILENAME "@streq /login" \
            "id:10001,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-sqli;ARGS:password"
        """;
});

var app = builder.Build();

app.UsePondhawkWaf();

app.MapGet("/healthz", () => "ok");
app.MapGet("/search", (string? q) => $"results for {q}");
app.MapPost("/login", (HttpRequest request) => Results.Ok(new { user = request.Form["user"].ToString() }));
app.MapPost("/api/items", (Item item) => Results.Created($"/api/items/{item.Name}", item));

// Simulates an application that leaks a database error. The WAF replaces the response (CRS 951xxx).
app.MapGet("/leaky", () => Results.Problem(
    "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"));

app.Run();

internal sealed record Item(string Name, int Quantity);
