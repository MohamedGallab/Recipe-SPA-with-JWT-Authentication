using Microsoft.AspNetCore.Mvc;

namespace RecipeAPI.Controllers;

[Route("recipes")]
[ApiController]
public class RecipesController : ControllerBase
{
	private readonly IDataHandler _dataHandler;

	public RecipesController(IDataHandler dataHandler)
	{
		_dataHandler = dataHandler;
	}

	// GET: api/<RecipesController>
	[HttpGet]
	[ValidateAntiForgeryToken]
	public async Task<IEnumerable<Recipe>> Get()
	{
		return await _dataHandler.LoadRecipesAsync();
	}

	// GET api/<RecipesController>/5
	[HttpGet("{id}")]
	public async Task<ActionResult<Recipe>> GetAsync(Guid id)
	{
		var recipesList = await _dataHandler.LoadRecipesAsync();
		if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
		{
			return Ok(recipe);
		}
		return NotFound();
	}

	// POST api/<RecipesController>
	[HttpPost]
	public async Task<ActionResult<Recipe>> PostAsync(Recipe recipe)
	{
		var recipesList = await _dataHandler.LoadRecipesAsync();
		if (recipe.Title == String.Empty)
		{
			return BadRequest();
		}
		recipe.Id = Guid.NewGuid();
		recipesList.Add(recipe);
		recipesList = recipesList.OrderBy(o => o.Title).ToList();
		await _dataHandler.SaveDataAsync(recipesList);
		return Created($"/recipes/{recipe.Id}", recipe);
	}

	// PUT api/<RecipesController>/5
	[HttpPut("{id}")]
	public async Task<IActionResult> PutAsync(Guid id, Recipe editedRecipe)
	{
		var recipesList = await _dataHandler.LoadRecipesAsync();
		if (recipesList.Find(recipe => recipe.Id == editedRecipe.Id) is Recipe recipe)
		{
			recipesList.Remove(recipe);
			recipesList.Add(editedRecipe);
			recipesList = recipesList.OrderBy(o => o.Title).ToList();
			await _dataHandler.SaveDataAsync(recipesList);
			return NoContent();
		}
		return NotFound();
	}

	// DELETE api/<RecipesController>/5
	[HttpDelete("{id}")]
	public async Task<IActionResult> DeleteAsync(Guid id)
	{
		var recipesList = await _dataHandler.LoadRecipesAsync();
		if (recipesList.Find(recipe => recipe.Id == id) is Recipe recipe)
		{
			recipesList.Remove(recipe);
			await _dataHandler.SaveDataAsync(recipesList);
			return Ok(recipe);
		}
		return NotFound();
	}
}
