using RecipeAPI;

namespace RecipeAPI;

public interface IDataHandler
{
	Task<List<Recipe>> LoadRecipesAsync();
	Task<List<string>> LoadCategoriesAsync();
	Task SaveDataAsync(List<Recipe> recipesList, List<string> categoriesList);
	Task SaveDataAsync(List<Recipe> recipesList);
	Task SaveDataAsync(List<string> categoriesList);
}
