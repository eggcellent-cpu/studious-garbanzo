using System.Net;
using System.Text.Json;

namespace FreshFarmMarket.Middleware
{
    public class CustomErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<CustomErrorHandlingMiddleware> _logger;

        public CustomErrorHandlingMiddleware(RequestDelegate next, ILogger<CustomErrorHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);

                if (!context.Response.HasStarted)
                {
                    var statusCode = context.Response.StatusCode;
                    if (!context.Request.Path.StartsWithSegments("/Error"))
                    {
                        switch (statusCode)
                        {
                            case 400:
                                context.Response.Redirect("/Error/400");
                                break;
                            case 401:
                                context.Response.Redirect("/Error/401");
                                break;
                            case 403:
                                context.Response.Redirect("/Error/403");
                                break;
                            case 404:
                                context.Response.Redirect("/Error/404");
                                break;
                            default:
                                // Optionally, you can handle default cases, like 405, 502, etc.
                                break;
                        }
                    }
                }

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred.");
                await HandleExceptionAsync(context, ex);
            }
        }

        private static async Task HandleExceptionAsync(HttpContext context, Exception ex)
        {
            if (!context.Response.HasStarted)
            {
                context.Response.ContentType = "application/json";
                var response = new
                {
                    error = ex.Message,
                    stackTrace = ex.StackTrace
                };
                await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            }
        }
    }
}
