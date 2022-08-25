using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;
using RecipeAPI.Models;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(options =>
{
	options.AddPolicy("Cors Policy",
		policy =>
		{
			policy
				.WithOrigins(builder.Configuration["FrontendOrigin"])
				.AllowAnyHeader()
				.AllowAnyMethod()
				.AllowCredentials();
		});
});
builder.Services.AddAntiforgery(options => options.HeaderName = "X-XSRF-TOKEN");

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(options =>
{
	options.SwaggerEndpoint("/swagger/v1/swagger.json", "v1");
	options.RoutePrefix = string.Empty;
});

app.UseHttpsRedirection();
app.UseCors("Cors Policy");

// load previous categories if exists
string categoriesFile = "Categories.json";
string jsonCategoriesString;
var categoriesList = new List<string>();

if (File.Exists(categoriesFile))
{
	if (new FileInfo(categoriesFile).Length > 0)
	{
		jsonCategoriesString = await File.ReadAllTextAsync(categoriesFile);
		categoriesList = JsonSerializer.Deserialize<List<string>>(jsonCategoriesString)!;
	}
}
else
{
	File.Create(categoriesFile).Dispose();
}

// load previous recipes if exists
string recipesFile = "Recipes.json";
string jsonRecipesString;
var recipesList = new List<Recipe>();

if (File.Exists(recipesFile))
{
	if (new FileInfo(recipesFile).Length > 0)
	{
		jsonRecipesString = await File.ReadAllTextAsync(recipesFile);
		recipesList = JsonSerializer.Deserialize<List<Recipe>>(jsonRecipesString)!;
	}
}
else
{
	File.Create(recipesFile).Dispose();
}

app.MapGet("antiforgery/token", (IAntiforgery forgeryService, HttpContext context) =>
{
	var tokens = forgeryService.GetAndStoreTokens(context);
	context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!,
			new CookieOptions { HttpOnly = false });
});

// endpoints
app.MapGet("/recipes", async (HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	return Results.Ok(recipesList);
});

app.MapGet("/recipes/{id}", async (Guid id, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
	{
		return Results.Ok(recipe);
	}
	return Results.NotFound();
});

app.MapPost("/recipes", async (Recipe recipe, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (recipe.Title == String.Empty)
	{
		return Results.BadRequest();
	}
	recipe.Id = Guid.NewGuid();
	recipesList.Add(recipe);
	recipesList = recipesList.OrderBy(o => o.Title).ToList();
	await SaveAsync();
	return Results.Created($"/recipes/{recipe.Id}", recipe);
});

app.MapDelete("/recipes/{id}", async (Guid id, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
	{
		recipesList.Remove(recipe);
		await SaveAsync();
		return Results.Ok(recipe);
	}
	return Results.NotFound();
});

app.MapPut("/recipes/{id}", async (Recipe editedRecipe, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (recipesList.Find(recipe => recipe.Id == editedRecipe.Id) is Recipe recipe)
	{
		recipesList.Remove(recipe);
		recipesList.Add(editedRecipe);
		recipesList = recipesList.OrderBy(o => o.Title).ToList();
		await SaveAsync();
		return Results.NoContent();
	}
	return Results.NotFound();
});

app.MapGet("/categories", async (HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	return Results.Ok(categoriesList);
});

app.MapPost("/categories", async (string category, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (category == String.Empty || categoriesList.Contains(category))
	{
		return Results.BadRequest();
	}

	categoriesList.Add(category);
	categoriesList = categoriesList.OrderBy(o => o).ToList();

	await SaveAsync();
	return Results.Created($"/categories/{category}", category);
});

app.MapDelete("/categories/{category}", async (string category, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (category == String.Empty)
	{
		return Results.BadRequest();
	}

	if (!categoriesList.Contains(category))
	{
		return Results.NotFound();
	}

	foreach (Recipe recipe in recipesList)
	{
		recipe.Categories.Remove(category);
	}
	categoriesList.Remove(category);
	await SaveAsync();
	return Results.Ok(category);
});

app.MapPut("/categories/{category}", async (string category, string editedCategory, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (editedCategory == String.Empty)
	{
		return Results.BadRequest();
	}

	if (!categoriesList.Contains(category))
	{
		return Results.NotFound();
	}

	categoriesList.Remove(category);
	categoriesList.Add(editedCategory);
	categoriesList = categoriesList.OrderBy(o => o).ToList();

	foreach (var recipe in recipesList)
	{
		if (recipe.Categories.Contains(category))
		{
			recipe.Categories.Remove(category);
			recipe.Categories.Add(editedCategory);
		}
	}

	await SaveAsync();
	return Results.NoContent();
});

async Task SaveAsync()
{
	await Task.WhenAll(
		File.WriteAllTextAsync(recipesFile, JsonSerializer.Serialize(recipesList, new JsonSerializerOptions { WriteIndented = true })),
		File.WriteAllTextAsync(categoriesFile, JsonSerializer.Serialize(categoriesList, new JsonSerializerOptions { WriteIndented = true }))
		);
}

app.Run();