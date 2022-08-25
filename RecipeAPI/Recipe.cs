namespace RecipeAPI;

public class Recipe
{
	public Guid Id { get; set; } = Guid.NewGuid();
	public string Title { get; set; } = string.Empty;
	public List<string> Ingredients { get; set; } = new();
	public List<string> Instructions { get; set; } = new();
	public List<string> Categories { get; set; } = new();
}
