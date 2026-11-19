using Pondhawk.Waf.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Settings from the "Pondhawk:Waf" section of appsettings.json; edits apply without a restart.
builder.Services.AddPondhawkWaf(builder.Configuration.GetSection("Pondhawk:Waf"), options =>
{
    options.Bypass = ctx => ctx.Request.Path == "/healthz";

    // Example exclusion: rule 942100 (SQL injection, libinjection) does not inspect the password field of /login.
    options.Exclude(942100, "ARGS:password", path: "/login");
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
