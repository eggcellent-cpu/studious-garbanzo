using FreshFarmMarket.Middleware;
using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.WebUtilities;
using IEmailSender = FreshFarmMarket.Services.IEmailSender;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddScoped<ReCaptchaService>();
builder.Services.AddScoped<AuditLogService>();
builder.Services.AddSingleton<EncryptionService>();
builder.Services.AddHttpClient();


// Configure Database and Identity
builder.Services.AddDbContext<MyAuthDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("MyAuthConnectionString")));

builder.Services.AddIdentity<CustomIdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<MyAuthDbContext>()
    .AddDefaultTokenProviders();

// Configure Authentication and Cookie settings
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Login";
        options.AccessDeniedPath = "/AccessDenied";
        options.Cookie.HttpOnly = true;
        options.Cookie.Name = "MyCookieAuth";
        options.ExpireTimeSpan = TimeSpan.FromSeconds(30); 
        options.SlidingExpiration = true; // Reset the expiration time on each request
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Ensure cookies are only sent over HTTPS
        options.Cookie.SameSite = SameSiteMode.Strict; // Prevent CSRF attacks
    });

// Configure Authorization and Identity options
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("MustBelongToHRDepartment", policy => policy.RequireClaim("Department", "HR"));
});

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
});

// Configure Session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(30); // Session expires after 30 minutes
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Configure Email Service
//var emailPassword = Environment.GetEnvironmentVariable("SMTP_PASSWORD"); --> for manually

var emailConfig = new EmailConfiguration
{
    From = "testing.testy.test1234@gmail.com",
    SmtpServer = "smtp.gmail.com",
    Port = 587,
    Username = "testing.testy.test1234@gmail.com",
    Password = "ovwv gfwg fbue alyj" // Load from environment variable
};

builder.Services.AddSingleton(emailConfig);
builder.Services.AddScoped<IEmailSender, EmailSender>();

builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(1);
});


var app = builder.Build();

// Apply database migrations during startup
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<MyAuthDbContext>();
    dbContext.Database.Migrate();  // Apply migrations here
}

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseStatusCodePagesWithReExecute("/Error/{0}");
    app.UseHsts();
}

// Middleware to clear cookies on app restart
app.Use(async (context, next) =>
{
    if (context.Request.Path == "/" && !context.User.Identity.IsAuthenticated)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    await next();
});

app.UseMiddleware<CustomErrorHandlingMiddleware>();

app.UseSession();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication(); // Authentication middleware
app.UseAuthorization();  // Authorization middleware

app.MapRazorPages();

app.Run();