using Microsoft.AspNetCore.Mvc;

namespace AceJobAgency.Controllers
{
    public class ErrorController : Controller
    {
        [Route("Error/{statusCode}")]
        public IActionResult Index(int statusCode)
        {
            ViewBag.StatusCode = statusCode;

            ViewBag.ErrorMessage = statusCode switch
            {
                404 => "Page Not Found",
                403 => "Access Denied",
                500 => "Internal Server Error",
                _ => "An Error Occurred"
            };

            ViewBag.ErrorDescription = statusCode switch
            {
                404 => "The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.",
                403 => "You don't have permission to access this resource.",
                500 => "Something went wrong on our end. We're working to fix it.",
                _ => "An unexpected error has occurred. Please try again later."
            };

            return View();
        }
    }
}