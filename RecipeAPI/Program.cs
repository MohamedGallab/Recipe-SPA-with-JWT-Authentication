using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using RecipeAPI;
using RecipeAPI.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// services
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

builder.Services.AddAuthentication(x =>
{
	x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
	x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
	var Key = Encoding.UTF8.GetBytes(builder.Configuration["JWT:Key"]);
	o.SaveToken = true;
	o.TokenValidationParameters = new TokenValidationParameters
	{
		ValidateIssuer = false,
		ValidateAudience = false,
		ValidateLifetime = true,
		ValidateIssuerSigningKey = true,
		ValidIssuer = builder.Configuration["JWT:Issuer"],
		ValidAudience = builder.Configuration["JWT:Audience"],
		IssuerSigningKey = new SymmetricSecurityKey(Key)
	};
});

builder.Services.AddAuthorization();

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
app.UseAuthentication();
app.UseAuthorization();

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

// load previous Users if exists
string usersFile = "Users.json";
string jsonUsersString;
var usersList = new List<User>();

if (File.Exists(usersFile))
{
	if (new FileInfo(usersFile).Length > 0)
	{
		jsonUsersString = await File.ReadAllTextAsync(usersFile);
		usersList = JsonSerializer.Deserialize<List<User>>(jsonUsersString)!;
	}
}
else
{
	File.Create(usersFile).Dispose();
}

JWToken? Authenticate(User user)
{
	if (!usersList.Any(x => x.Name == user.Name && x.Password == user.Password))
	{
		return null;
	}

	// Else we generate JSON Web Token
	var tokenHandler = new JwtSecurityTokenHandler();
	var tokenKey = Encoding.UTF8.GetBytes(app.Configuration["JWT:Key"]);
	var tokenDescriptor = new SecurityTokenDescriptor
	{
		Subject = new ClaimsIdentity(new Claim[]
		{
				new Claim(ClaimTypes.Name, user.Name)
		}),
		Expires = DateTime.UtcNow.AddMinutes(10),
		SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
	};
	var token = tokenHandler.CreateToken(tokenDescriptor);
	return new JWToken { Token = tokenHandler.WriteToken(token) };
}

// user enpoint
app.MapPost("/register", async (HttpContext context, IAntiforgery forgeryService, User user) =>
{
	if (user.Name == String.Empty || user.Password == String.Empty || usersList.Exists(oldUser => oldUser.Name == user.Name))
	{
		return Results.BadRequest();
	}
	usersList.Add(user);
	await SaveAsync();

	var token = Authenticate(user);

	if (token == null)
	{
		return Results.Unauthorized();
	}

	return Results.Created($"/users/{user.Name}", token);
});

app.MapPost("/login", (HttpContext context, IAntiforgery forgeryService, User user) =>
{
	var token = Authenticate(user);

	if (token == null)
	{
		return Results.Unauthorized();
	}

	return Results.Ok(token);
});

app.MapGet("antiforgery/token", [Authorize] (IAntiforgery forgeryService, HttpContext context) =>
{
	var tokens = forgeryService.GetAndStoreTokens(context);
	context.Response.Cookies.Append("XSRF-TOKEN", tokens.RequestToken!,
			new CookieOptions { HttpOnly = false });
});

// recipe endpoints
app.MapGet("/recipes", [Authorize] async (HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	return Results.Ok(recipesList);
});

app.MapGet("/recipes/{id}", [Authorize] async (Guid id, HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
	{
		return Results.Ok(recipe);
	}
	return Results.NotFound();
});

app.MapPost("/recipes", [Authorize] async (Recipe recipe, HttpContext context, IAntiforgery forgeryService) =>
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

app.MapDelete("/recipes/{id}", [Authorize] async (Guid id, HttpContext context, IAntiforgery forgeryService) =>
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

app.MapPut("/recipes/{id}", [Authorize] async (Recipe editedRecipe, HttpContext context, IAntiforgery forgeryService) =>
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

// category endpoints
app.MapGet("/categories", [Authorize] async (HttpContext context, IAntiforgery forgeryService) =>
{
	await forgeryService.ValidateRequestAsync(context);
	return Results.Ok(categoriesList);
});

app.MapPost("/categories", [Authorize] async (string category, HttpContext context, IAntiforgery forgeryService) =>
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

app.MapDelete("/categories/{category}", [Authorize] async (string category, HttpContext context, IAntiforgery forgeryService) =>
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

app.MapPut("/categories/{category}", [Authorize] async (string category, string editedCategory, HttpContext context, IAntiforgery forgeryService) =>
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
		File.WriteAllTextAsync(categoriesFile, JsonSerializer.Serialize(categoriesList, new JsonSerializerOptions { WriteIndented = true })),
		File.WriteAllTextAsync(usersFile, JsonSerializer.Serialize(usersList, new JsonSerializerOptions { WriteIndented = true }))
		);
}

app.Run();