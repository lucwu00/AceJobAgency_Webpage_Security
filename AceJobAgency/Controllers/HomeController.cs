using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using AceJobAgency.Data;
using AceJobAgency.Services;

namespace AceJobAgency.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;

        public HomeController(ApplicationDbContext context, IEncryptionService encryptionService)
        {
            _context = context;
            _encryptionService = encryptionService;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Dashboard()
        {
            var memberId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
            var member = await _context.Members.FindAsync(memberId);

            if (member == null)
            {
                return NotFound();
            }

            // Decrypt NRIC for display
            ViewBag.DecryptedNRIC = _encryptionService.Decrypt(member.NRIC);
            ViewBag.Member = member;

            return View(member);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View();
        }
    }
}