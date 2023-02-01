using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

#region Services we used for the manual Authentication proccess
// builder.Services.AddDataProtection();
// builder.Services.AddHttpContextAccessor();
// builder.Services.AddScoped<AuthService>();
#endregion

const string authScheme = "cookie";
//We specifies that we want to use authentication with the cookie scheme
builder.Services.AddAuthentication(authScheme)
    .AddCookie(authScheme);

// Create a authorization rules that will be apply for any request that tries to access an endpoint marked with this policy
builder.Services.AddAuthorization(builderOptions =>
{
    //The name of the policy 
    builderOptions.AddPolicy("premium user", pb =>
    {
        //This rule set that the user must be authenticated first them can access the endpoint
        pb.RequireAuthenticatedUser()
            //The user must have the user claim with the value of premium
            .RequireClaim("user", "premium");
    });
});

var app = builder.Build();

app.UseAuthentication();
#region Authentication
// app.Use((ctx, next) =>
// {
//     if (ctx.Request.Path.Value.StartsWith("/login"))
//     {
//         return next();
//     }
//     
//     var idp = ctx.RequestServices.GetRequiredService<IDataProtectionProvider>();
//     var protector = idp.CreateProtector("cookie");
//
//     var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
//
//     if (authCookie is null)
//     {
//         ctx.Response.StatusCode = 401;
//         ctx.Response.WriteAsync("no authenticated");
//         return Task.CompletedTask;
//     }
//        
//     var payload = authCookie.Split("=").Last();
//     var unprotected = protector.Unprotect(payload);
//     var value = unprotected.Split(":");
//     
//     var claim = new List<Claim>();
//     claim.Add(new Claim(value[0], value[1]));
//     claim.Add(new Claim(value[0], "premium"));
//     var identity = new ClaimsIdentity(claim, AuthScheme);
//     ctx.User = new ClaimsPrincipal(identity);
//     
//     return next();
// });
#endregion

app.UseAuthorization();
#region Authorization
// app.Use((ctx, next) =>
// {
//     if (ctx.Request.Path.Value.StartsWith("/login"))
//     {
//         return next();
//     }
//     if (!ctx.User.Identities.Any(x => x.AuthenticationType == AuthScheme))
//     {
//         ctx.Response.StatusCode = 401;
//         return Task.CompletedTask;
//     }
//
//     if (!ctx.User.HasClaim("usr", "premium"))
//     {
//         ctx.Response.StatusCode = 403;
//         return Task.CompletedTask;
//     }
//
//     return next();
// });
#endregion

#region Endpoints

app.MapGet("/premium", (HttpContext ctx) =>
{
    var claim = ctx.User.FindAll("user");
    return $"This user has {claim.LastOrDefault().Value} access to the system!";

}).RequireAuthorization("premium user");

//To access this endpoint the user only need to be authenticated
app.MapGet("/user", (HttpContext ctx) =>
{
    var claim = ctx.User.FindFirst("user");
    return $"This user has {claim!.Value} access to the system!";
}).RequireAuthorization(); //No special policy needed

//To access this endpoint the user need be authenticated with cookie scheme and has the user claim along with the premium respective value
app.MapGet("/login", (HttpContext ctx /*AuthService authService*/) =>
{
    //authService.SignIn();
    var claim = new List<Claim>
    {
        new Claim("user", "normal")
    };
    var identity = new ClaimsIdentity(claim, authScheme);
    var principal = new ClaimsPrincipal(identity);
    
    ctx.SignInAsync("cookie", principal);
    return "User logged in!";
}).AllowAnonymous();

//Call this endpoint to add the premium claim to the user
//User must be authenticated to access this endpoint
app.MapGet("/addnewclaim", (HttpContext ctx) =>
{
    var principal = ctx.User.Clone();
    var claim = new List<Claim> {new Claim("user", "premium")};
    principal.AddIdentity(new ClaimsIdentity(claim, authScheme));
    ctx.SignInAsync("cookie", principal);
    return "User promoted to premium!";
}).RequireAuthorization();

#endregion


app.Run();

#region Custom Authentication Service
//IAuthenticationService
// public class AuthService
// {
//     private readonly IDataProtectionProvider _idp;
//     private readonly IHttpContextAccessor _httpContextAccessor;
//
//     public AuthService(IDataProtectionProvider idp, IHttpContextAccessor httpContextAccessor)
//     {
//         _idp = idp;
//         _httpContextAccessor = httpContextAccessor;
//     }
//
//     public void SignIn()
//     {
//         var protector = _idp.CreateProtector("cookie");
//         var cookieValue = $"auth={protector.Protect("usr:premiumm")}";
//         _httpContextAccessor.HttpContext.Response.Headers["set-cookie"] = cookieValue;
//     }
// }

#endregion
