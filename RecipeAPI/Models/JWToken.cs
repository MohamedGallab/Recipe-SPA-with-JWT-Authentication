namespace RecipeAPI.Models;

public class JWToken
{
	public string Token { get; set; } = String.Empty;
	public string RefreshToken { get; set; } = String.Empty;
}
