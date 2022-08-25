using RecipeAPI;
using System.Text.Json;

namespace RecipeAPI;

public class DataHandler : IDataHandler
{
	private List<Recipe> _recipesList = new();
	private List<string> _categoriesList = new();
	private readonly string _recipesFile = "Recipes.json";
	private readonly string _categoriesFile = "Categories.json";
	private readonly bool _isLoaded = false;

	public async Task<List<Recipe>> LoadRecipesAsync()
	{
		if (_isLoaded)
			return _recipesList;

		// load previous recipes if exists
		if (File.Exists(_recipesFile))
		{
			if (new FileInfo(_recipesFile).Length > 0)
			{
				string jsonRecipesString = await File.ReadAllTextAsync(_recipesFile);
				_recipesList = JsonSerializer.Deserialize<List<Recipe>>(jsonRecipesString)!;
			}
		}
		else
		{
			File.Create(_recipesFile).Dispose();
		}

		return _recipesList;
	}

	public async Task<List<string>> LoadCategoriesAsync()
	{
		if (_isLoaded)
			return _categoriesList;



		if (File.Exists(_categoriesFile))
		{
			if (new FileInfo(_categoriesFile).Length > 0)
			{
				string jsonCategoriesString = await File.ReadAllTextAsync(_categoriesFile);
				_categoriesList = JsonSerializer.Deserialize<List<string>>(jsonCategoriesString)!;
			}
		}
		else
		{
			File.Create(_categoriesFile).Dispose();
		}

		return _categoriesList;
	}

	public async Task SaveDataAsync(List<Recipe> recipesList, List<string> categoriesList)
	{
		_recipesList = recipesList;
		_categoriesList = categoriesList;
		await Task.WhenAll(
			File.WriteAllTextAsync(_recipesFile, JsonSerializer.Serialize(_recipesList, new JsonSerializerOptions { WriteIndented = true })),
			File.WriteAllTextAsync(_categoriesFile, JsonSerializer.Serialize(_categoriesList, new JsonSerializerOptions { WriteIndented = true }))
			);
	}

	public async Task SaveDataAsync(List<Recipe> recipesList)
	{
		_recipesList = recipesList;
		await File.WriteAllTextAsync(_recipesFile, JsonSerializer.Serialize(_recipesList, new JsonSerializerOptions { WriteIndented = true }));
	}

	public async Task SaveDataAsync(List<string> categoriesList)
	{
		_categoriesList = categoriesList;
		await File.WriteAllTextAsync(_categoriesFile, JsonSerializer.Serialize(_categoriesList, new JsonSerializerOptions { WriteIndented = true }));
	}
}
