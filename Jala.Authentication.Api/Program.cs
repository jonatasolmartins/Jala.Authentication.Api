using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();

var app = builder.Build();

app.Use((ctx, next) =>
{
    if (ctx.Request.Path.Value.StartsWith("/login"))
    {
        return next();
    }
    
    var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
    var protector = idp.CreateProtector("cookie");
    
    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));

    if (authCookie is null)
    {
        ctx.Response.StatusCode = 401;
        ctx.Response.WriteAsync("no authenticated");
        return Task.CompletedTask;
    }
       
    var payload = authCookie.Split("=").Last();
    var unprotected = protector.Unprotect(payload);
    var value = unprotected.Split(":");
    
    var claim = new List<Claim>();
    claim.Add(new Claim(value[0], value[1]));
    var identity = new ClaimsIdentity(claim);
    ctx.User = new ClaimsPrincipal(identity);
    
    return next();
});

app.MapGet("/user", (HttpContext ctx) =>
{
    return ctx.User.FindFirst("usr").Value;
});

app.MapGet("/login", (AuthService authService) =>
{
    authService.SignIn();
    return "ok";
});

app.Run();

public class AuthService
{
    private readonly IDataProtectionProvider _idp;
    private readonly IHttpContextAccessor _httpContextAccessor;

    public AuthService(IDataProtectionProvider idp, IHttpContextAccessor httpContextAccessor)
    {
        _idp = idp;
        _httpContextAccessor = httpContextAccessor;
    }

    public void SignIn()
    {
        var protector = _idp.CreateProtector("cookie");
        var cookieValue = $"auth={protector.Protect("usr:jonatas")}";
        _httpContextAccessor.HttpContext.Response.Headers["set-cookie"] = cookieValue;
    }
}