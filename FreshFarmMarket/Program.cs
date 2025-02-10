using FreshFarmMarket.Middleware;
using FreshFarmMarket.Model;
using FreshFarmMarket.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.WebUtilities;
using IEmailSender = FreshFarmMarket.Services.IEmailSender;


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

builder.Services.AddSession();

// Configure Authentication and Cookie settings
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Login";
        options.AccessDeniedPath = "/AccessDenied";
        options.Cookie.Name = "MyCookieAuth";
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;
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

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

var emailPassword = Environment.GetEnvironmentVariable("SMTP_PASSWORD");

var emailConfig = new EmailConfiguration
{
    From = "bozow341@gmail.com",
    SmtpServer = "smtp.gmail.com",
    Port = 587,
    Username = "bozow341@gmail.com",
    Password = emailPassword // Load from environment variable
};

builder.Services.AddSingleton(emailConfig);
builder.Services.AddScoped<IEmailSender, EmailSender>();

builder.Services.Configure<DataProtectionTokenProviderOptions>(opt =>
    opt.TokenLifespan = TimeSpan.FromHours(1)
);


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

app.UseMiddleware<CustomErrorHandlingMiddleware>();

app.UseSession();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication(); // Authentication middleware
app.UseAuthorization();  // Authorization middleware

app.MapRazorPages();

app.Run();
