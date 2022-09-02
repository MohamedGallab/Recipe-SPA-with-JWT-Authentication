namespace RecipeAPI.Models;

public class User
{
	public string Name { get; set; } = String.Empty;
	public string Password { get; set; } = String.Empty;
	public string RefreshToken { get; set; } = String.Empty;
}
