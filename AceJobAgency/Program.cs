using System.Text;
using AceJobAgency.Data;
using AceJobAgency.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllersWithViews();
builder.Services.AddRazorPages();

// Configure DbContext with SQL Server
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure Authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(1); // Session timeout
        options.SlidingExpiration = false; // ✅ FIXED: Changed from true to false - now session will expire after 1 minute
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Strict;
    });

// Add Session support for additional security tracking
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

// Add hosted service for background cleanup
builder.Services.AddHostedService<SessionCleanupService>();

// Register custom services
builder.Services.AddScoped<IEncryptionService, EncryptionService>();
builder.Services.AddScoped<IPasswordService, PasswordService>();
builder.Services.AddScoped<IAuditService, AuditService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddHttpContextAccessor();

// Register reCAPTCHA service (typed HttpClient)
builder.Services.AddHttpClient<IRecaptchaService, RecaptchaService>();

// Configure security headers
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

// Custom error pages
app.UseStatusCodePagesWithReExecute("/Error/{0}");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// CSP + NONCE MIDDLEWARE 
// CSP + NONCE MIDDLEWARE 
app.Use(async (context, next) =>
{
    var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
    context.Items["CspNonce"] = nonce;

    // Base allowed hosts for scripts/styles/connect
    var scriptSrc = new List<string>
    {
        "'self'",
        $"'nonce-{nonce}'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com",
        "https://www.google.com",      // ✅ reCAPTCHA
        "https://www.gstatic.com"      // ✅ reCAPTCHA
    };

    var styleSrc = new List<string>
    {
        "'self'",
        "'unsafe-inline'",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com"
    };

    var connectSrc = new List<string>
    {
        "'self'",
        "wss://localhost:*",
        "https://cdn.jsdelivr.net",
        "https://cdnjs.cloudflare.com"
    };

    // worker-src required for reCAPTCHA web worker
    var workerSrc = new List<string>
    {
        "'self'",
        "https://www.google.com",
        "https://www.gstatic.com"
    };

    var imgSrc = new List<string> { "'self'", "data:", "https://www.google.com" };
    var frameSrc = new List<string> { "'self'", "https://www.google.com" };

    var fontSrc = new List<string>
{
    "'self'",
    "data:",
    "https://cdn.jsdelivr.net"
};
    // Development relaxations (ONLY for dev)
    if (app.Environment.IsDevelopment())
    {
        connectSrc.Add("ws://localhost:*");
        connectSrc.Add("http://localhost:*");
        scriptSrc.Add("http://localhost:*");
        styleSrc.Add("http://localhost:*");
        scriptSrc.Add("'unsafe-eval'");
    }

    // Build CSP directives
    var csp = new StringBuilder();
    csp.Append("default-src 'self'; ");
    csp.Append($"script-src {string.Join(" ", scriptSrc)}; ");
    csp.Append($"script-src-elem {string.Join(" ", scriptSrc)}; ");
    csp.Append($"worker-src {string.Join(" ", workerSrc)}; ");
    csp.Append($"frame-src {string.Join(" ", frameSrc)}; ");
    csp.Append($"font-src {string.Join(" ", fontSrc)}; ");
    csp.Append($"style-src {string.Join(" ", styleSrc)}; ");
    csp.Append($"img-src {string.Join(" ", imgSrc)}; ");
    csp.Append($"connect-src {string.Join(" ", connectSrc)};");

    context.Response.Headers["Content-Security-Policy"] = csp.ToString();
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

    await next();
});

app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapRazorPages();

app.Run();