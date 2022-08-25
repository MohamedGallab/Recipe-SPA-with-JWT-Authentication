using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace RecipeAPI.Controllers;

[Route("categories")]
[ApiController]
public class CategoriesController : ControllerBase
{
	private readonly IDataHandler _dataHandler;

	public CategoriesController(IDataHandler dataHandler)
	{
		_dataHandler = dataHandler;
	}

	// GET: api/<CategoriesController>
	[HttpGet]
	[ValidateAntiForgeryToken]
	public async Task<IEnumerable<string>> GetAsync()
	{
		return await _dataHandler.LoadCategoriesAsync();
	}

	// POST api/<CategoriesController>
	[HttpPost]
	public async Task<ActionResult<string>> PostAsync(string category)
	{
		var categoriesList = await _dataHandler.LoadCategoriesAsync();
		if (category == String.Empty || categoriesList.Contains(category))
		{
			return BadRequest();
		}

		categoriesList.Add(category);
		categoriesList = categoriesList.OrderBy(o => o).ToList();

		await _dataHandler.SaveDataAsync(categoriesList);
		return Created($"/categories/{category}", category);
	}

	// PUT api/<CategoriesController>/5
	[HttpPut("{category}")]
	public async Task<IActionResult> PutAsync(string category, string editedCategory)
	{
		var categoriesList = await _dataHandler.LoadCategoriesAsync();
		var recipesList = await _dataHandler.LoadRecipesAsync();

		if (editedCategory == String.Empty)
		{
			return BadRequest();
		}

		if (!categoriesList.Contains(category))
		{
			return NotFound();
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

		await _dataHandler.SaveDataAsync(recipesList, categoriesList);
		return NoContent();
	}

	// DELETE api/<CategoriesController>/5
	[HttpDelete("{category}")]
	public async Task<ActionResult<string>> DeleteAsync(string category)
	{
		var categoriesList = await _dataHandler.LoadCategoriesAsync();
		var recipesList = await _dataHandler.LoadRecipesAsync();
		if (category == String.Empty)
		{
			return BadRequest();
		}

		if (!categoriesList.Contains(category))
		{
			return NotFound();
		}

		foreach (Recipe recipe in recipesList)
		{
			recipe.Categories.Remove(category);
		}
		categoriesList.Remove(category);
		await _dataHandler.SaveDataAsync(recipesList, categoriesList);
		return Ok(category);
	}
}
