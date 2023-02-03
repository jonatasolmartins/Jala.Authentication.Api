using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

#region Services we used for the manual Authentication proccess
// builder.Services.AddDataProtection();
// builder.Services.AddHttpContextAccessor();
// builder.Services.AddScoped<AuthService>();
#endregion

//OAuth is mean to be used to authorization and delegation
const string cookieAuthScheme = "cookie";
const string githubScheme = "github";

//We specifies that we want to use authentication with the cookie scheme
builder.Services.AddAuthentication(cookieAuthScheme)
    .AddCookie(cookieAuthScheme)
    .AddOAuth(githubScheme, o =>
    {
        /*
         We specifies that we want to use the cookie scheme to sign in the user.
         After the claims principal is created with the claims from the github user, we create a cookie with that claims principal information.
        */
        o.SignInScheme = cookieAuthScheme;
        //The client id and secret are the ones we get from the github oauth configuration.
        o.ClientId = "";
        o.ClientSecret = "";
        //The endpoint that will be used to get the authorization code
        o.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
        //The endpoint that will be used to get the access token
        o.TokenEndpoint = "https://github.com/login/oauth/access_token";
        //The path that will be used from the github oauth to call back to our application
        o.CallbackPath = "/oauth/github/callback";
        //We specifies that we want to save the tokens returned from the github alongside with the claims principal
        o.SaveTokens = true;
        //The endpoint that will be used to get the user information
        o.UserInformationEndpoint = "https://api.github.com/user";
        
        //Map the claims from the github user to the claims principal
        o.ClaimActions.MapJsonKey("sub", "id");
        o.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");
        //We subscribe to the OnCreatingTicket event to get the user information from the github api
        o.Events.OnCreatingTicket = async ctx =>
        {
            /*
             * Here is the place where we store the token in the database so we can re-fresh the token when it is about to expire
             * till the duration of our authentication policy, otherwise the user can end up with a valid cookie/jwt holding an invalid
             * access token which may cause problems when they try to use it.
             * Example: myDatabase = ctx.HttpContext.RequestServices.GetRequiredService<MyDatabase>();
             */
            
            using var request = new HttpRequestMessage(HttpMethod.Get, ctx.Options.UserInformationEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            //This header is required to get the user information from the github api
            //AccessTon is just a random string generated from github ans send to our application
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ctx.AccessToken);
            //BackChannel is used to call identity provider in a secure way far from the client 
            using var response = await ctx.Backchannel.SendAsync(request);
            var user = await response.Content.ReadFromJsonAsync<JsonElement>();
            //RunClaimActions will map the json data(properties) that we received fom github to the ClaimActions we specify above
            ctx.RunClaimActions(user);
        };
    });
// Create a authorization rules that will be apply for any request that tries to access an endpoint marked with this policy
builder.Services.AddAuthorization(builderOptions =>
{
    //The name of the policy 
    builderOptions.AddPolicy("premium user", pb =>
    {
        pb.AuthenticationSchemes.Add(cookieAuthScheme);
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
// app.MapGet("/login", (HttpContext ctx /*AuthService authService*/) =>
// {
//     //authService.SignIn();
//     var claim = new List<Claim>
//     {
//         new Claim("user", "normal"),
//         new Claim("user_id", Guid.NewGuid().ToString())
//     };
//     var identity = new ClaimsIdentity(claim, cookieAuthScheme);
//     var principal = new ClaimsPrincipal(identity);
//     
//     ctx.SignInAsync("cookie", principal);
//     return "User logged in!";
// }).AllowAnonymous();

//Call this endpoint to add the premium claim to the user
//User must be authenticated to access this endpoint
app.MapGet("/addnewclaim", (HttpContext ctx) =>
{
    var principal = ctx.User.Clone();
    var claim = new List<Claim> {new Claim("user", "premium")};
    principal.AddIdentity(new ClaimsIdentity(claim, cookieAuthScheme));
    ctx.SignInAsync(cookieAuthScheme, principal);
    return "Claim added!";
}).RequireAuthorization();
#endregion

// app.MapGet("/login", () => Results.SignIn(
//     new ClaimsPrincipal(
//         new ClaimsIdentity(
//             new List<Claim>
//             {
//                 new Claim("user", "normal"),
//                 new Claim("user_id", Guid.NewGuid().ToString())
//             }
//             , cookieAuthScheme))
// )).AllowAnonymous();

app.MapGet("/login", () =>
{
    return Results.Challenge(new AuthenticationProperties()
    {
        RedirectUri = "https://localhost:7090/"
    } ,authenticationSchemes: new List<string>() { githubScheme });
}).AllowAnonymous();

app.MapGet("/", (HttpContext ctx) =>
{
    return ctx.User.Claims.Select(x => new { x.Type, x.Value}).ToList();
});

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
