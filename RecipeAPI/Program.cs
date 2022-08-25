using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using RecipeAPI;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllersWithViews();
builder.Services.AddAntiforgery();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
	options.AddPolicy("Cors Policy",
		policy =>
		{
			policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
		});
});
builder.Services.AddSingleton<IDataHandler, DataHandler>();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseSwagger();
app.UseSwaggerUI(options =>
{
	options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
	options.RoutePrefix = string.Empty;
});

app.UseHttpsRedirection();
app.UseCors("Cors Policy");

app.UseAuthorization();

app.MapControllers();

app.MapGet("antiforgery/token", (IAntiforgery forgeryService, HttpContext context) =>
{
	var tokens = forgeryService.GetAndStoreTokens(context);
	context.Response.Cookies.Append("RequestVerificationToken", tokens.RequestToken!,
			new CookieOptions { HttpOnly = false });

	return Results.Ok();
});

app.Run();
