using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.Json;
using AceJobAgency.Data;
using AceJobAgency.Models;
using AceJobAgency.Models.ViewModels;
using AceJobAgency.Services;

namespace AceJobAgency.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IEncryptionService _encryptionService;
        private readonly IPasswordService _passwordService;
        private readonly IAuditService _auditService;
        private readonly ISessionService _sessionService;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _environment;
        private readonly IRecaptchaService _recaptchaService;

        // Singapore timezone
        private static readonly TimeZoneInfo SingaporeTimeZone =
            TimeZoneInfo.FindSystemTimeZoneById("Singapore Standard Time");

        public AccountController(
            ApplicationDbContext context,
            IEncryptionService encryptionService,
            IPasswordService passwordService,
            IAuditService auditService,
            ISessionService sessionService,
            IConfiguration configuration,
            IWebHostEnvironment environment,
            IRecaptchaService recaptchaService)
        {
            _context = context;
            _encryptionService = encryptionService;
            _passwordService = passwordService;
            _auditService = auditService;
            _sessionService = sessionService;
            _configuration = configuration;
            _environment = environment;
            _recaptchaService = recaptchaService;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Check for duplicate email
            if (await _context.Members.AnyAsync(m => m.Email == model.Email))
            {
                ModelState.AddModelError("Email", "This email is already registered.");
                await _auditService.LogActivity(null, "Registration Failed - Duplicate Email", model.Email);
                return View(model);
            }

            // Validate password strength (server-side)
            var (isValid, message) = _passwordService.ValidatePasswordStrength(model.Password);
            if (!isValid)
            {
                ModelState.AddModelError("Password", message);
                return View(model);
            }

            // Handle resume upload
            string? resumePath = null;
            if (model.Resume != null)
            {
                var allowedExtensions = new[] { ".pdf", ".docx" };
                var extension = Path.GetExtension(model.Resume.FileName).ToLowerInvariant();

                if (!allowedExtensions.Contains(extension))
                {
                    ModelState.AddModelError("Resume", "Only PDF and DOCX files are allowed.");
                    return View(model);
                }

                if (model.Resume.Length > 5 * 1024 * 1024) // 5MB limit
                {
                    ModelState.AddModelError("Resume", "File size must not exceed 5MB.");
                    return View(model);
                }

                var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads", "resumes");
                Directory.CreateDirectory(uploadsFolder);

                var uniqueFileName = $"{Guid.NewGuid()}_{Path.GetFileName(model.Resume.FileName)}";
                var filePath = Path.Combine(uploadsFolder, uniqueFileName);

                using (var fileStream = new FileStream(filePath, FileMode.Create))
                {
                    await model.Resume.CopyToAsync(fileStream);
                }

                resumePath = $"/uploads/resumes/{uniqueFileName}";
            }

            var now = GetSingaporeTime();

            // Create member
            var member = new Member
            {
                FirstName = SanitizeInput(model.FirstName),
                LastName = SanitizeInput(model.LastName),
                Gender = model.Gender,
                NRIC = _encryptionService.Encrypt(model.NRIC), // Encrypt NRIC
                Email = model.Email.ToLower(),
                PasswordHash = _passwordService.HashPassword(model.Password),
                DateOfBirth = model.DateOfBirth,
                ResumePath = resumePath,
                WhoAmI = SanitizeInput(model.WhoAmI),
                CreatedAt = now,
                PasswordChangedAt = now  // Set initial password change time
            };

            _context.Members.Add(member);
            await _context.SaveChangesAsync();

            // Add password to history
            await _passwordService.AddPasswordToHistory(member.Id, member.PasswordHash);

            // Log activity
            await _auditService.LogActivity(member.Id, "Registration Successful", $"New member: {member.Email}");

            TempData["SuccessMessage"] = "Registration successful! Please login.";
            return RedirectToAction("Login");
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var member = await _context.Members
                .FirstOrDefaultAsync(m => m.Email == model.Email.ToLower());

            if (member == null)
            {
                await _auditService.LogActivity(null, "Login Failed - Invalid Email", model.Email);
                ModelState.AddModelError("", "Invalid email or password.");
                return View(model);
            }

            var now = GetSingaporeTime();

            // Check if account is locked
            if (member.IsLocked && member.LockoutEnd.HasValue && member.LockoutEnd.Value > now)
            {
                var remainingSeconds = (member.LockoutEnd.Value - now).TotalSeconds;
                await _auditService.LogActivity(member.Id, "Login Attempt - Account Locked", model.Email);
                ModelState.AddModelError("", $"Account is locked. Please try again in {Math.Ceiling(remainingSeconds)} seconds.");
                return View(model);
            }

            // Reset lockout if expired
            if (member.IsLocked && member.LockoutEnd.HasValue && member.LockoutEnd.Value <= now)
            {
                member.IsLocked = false;
                member.FailedLoginAttempts = 0;
                member.LockoutEnd = null;
                await _context.SaveChangesAsync();
            }

            // Verify password
            if (!_passwordService.VerifyPassword(model.Password, member.PasswordHash))
            {
                member.FailedLoginAttempts++;

                var maxAttempts = _configuration.GetValue<int>("SecuritySettings:MaxLoginAttempts", 3);
                if (member.FailedLoginAttempts >= maxAttempts)
                {
                    member.IsLocked = true;
                    var lockoutMinutes = _configuration.GetValue<int>("SecuritySettings:LockoutDurationMinutes", 1);
                    member.LockoutEnd = now.AddMinutes(lockoutMinutes);
                    await _auditService.LogActivity(member.Id, "Account Locked - Too Many Failed Attempts", model.Email);
                    ModelState.AddModelError("", $"Too many failed login attempts. Account locked for {lockoutMinutes} minute(s).");
                }
                else
                {
                    await _auditService.LogActivity(member.Id, "Login Failed - Invalid Password", model.Email);
                    ModelState.AddModelError("", $"Invalid email or password. {maxAttempts - member.FailedLoginAttempts} attempts remaining.");
                }

                await _context.SaveChangesAsync();
                return View(model);
            }

            // Check maximum password age
            var maxPasswordAgeMinutes =
                _configuration.GetValue<int>("SecuritySettings:MaxPasswordAgeMinutes", 0);

            if (maxPasswordAgeMinutes > 0 && member.PasswordChangedAt.HasValue)
            {
                var passwordAge = now - member.PasswordChangedAt.Value;
                var maxPasswordAge = TimeSpan.FromMinutes(maxPasswordAgeMinutes);

                if (passwordAge > maxPasswordAge)
                {
                    TempData["ExpiredPasswordMemberId"] = member.Id;
                    TempData["ErrorMessage"] = "Your password has expired. You must change it now.";

                    await _auditService.LogActivity(
                        member.Id,
                        "Password Expired - Forced Change Required",
                        model.Email
                    );

                    return RedirectToAction("ChangePassword");
                }
            }


            // Check for multiple sessions from different devices
            var activeSessionCount = await _sessionService.GetActiveSessionCount(member.Id);
            if (activeSessionCount > 0)
            {
                TempData["WarningMessage"] = "You have an active session on another device. Previous sessions have been logged out.";
                await _sessionService.InvalidateAllUserSessions(member.Id);
            }

            // Successful login
            member.FailedLoginAttempts = 0;
            member.LastLoginAt = now;
            member.IsLocked = false;
            member.LockoutEnd = null;
            await _context.SaveChangesAsync();

            // Create authentication cookie
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, member.Id.ToString()),
                new Claim(ClaimTypes.Email, member.Email),
                new Claim(ClaimTypes.Name, $"{member.FirstName} {member.LastName}")
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            var sessionTimeoutMinutes = _configuration.GetValue<int>("SecuritySettings:SessionTimeoutMinutes", 1);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = false,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(sessionTimeoutMinutes)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            // Create session
            var sessionId = HttpContext.Session.Id;
            await _sessionService.CreateSession(member.Id, sessionId);

            // Log activity
            await _auditService.LogActivity(member.Id, "Login Successful", model.Email);

            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            var memberId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");

            // Invalidate session
            await _sessionService.InvalidateSession(HttpContext.Session.Id);

            // Log activity
            await _auditService.LogActivity(memberId, "Logout", "User logged out");

            // Clear session
            HttpContext.Session.Clear();

            // Sign out
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return RedirectToAction("Login");
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> ChangePassword()
        {
            return View();
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var memberId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "0");
            var member = await _context.Members.FindAsync(memberId);

            if (member == null)
            {
                return NotFound();
            }

            var now = GetSingaporeTime();

            // Verify current password
            if (!_passwordService.VerifyPassword(model.CurrentPassword, member.PasswordHash))
            {
                ModelState.AddModelError("CurrentPassword", "Current password is incorrect.");
                return View(model);
            }

            // ✅ Check minimum password age (1 minute for testing)
            var minPasswordAgeMinutes = _configuration.GetValue<int>("SecuritySettings:MinPasswordAgeMinutes", 0);
            if (minPasswordAgeMinutes > 0 && member.PasswordChangedAt.HasValue)
            {
                var passwordAge = now - member.PasswordChangedAt.Value;
                var minPasswordAge = TimeSpan.FromMinutes(minPasswordAgeMinutes);

                if (passwordAge < minPasswordAge)
                {
                    var remainingSeconds = (minPasswordAge - passwordAge).TotalSeconds;
                    ModelState.AddModelError("", $"You must wait {Math.Ceiling(remainingSeconds)} seconds before changing password again.");
                    return View(model);
                }
            }

            // Validate new password strength
            var (isValid, message) = _passwordService.ValidatePasswordStrength(model.NewPassword);
            if (!isValid)
            {
                ModelState.AddModelError("NewPassword", message);
                return View(model);
            }

            // Check password history
            if (!await _passwordService.CheckPasswordHistory(memberId, model.NewPassword))
            {
                var historyCount = _configuration.GetValue<int>("SecuritySettings:PasswordHistoryCount", 2);
                ModelState.AddModelError("NewPassword", $"You cannot reuse your last {historyCount} passwords.");
                return View(model);
            }

            // Update password
            var newPasswordHash = _passwordService.HashPassword(model.NewPassword);
            member.PasswordHash = newPasswordHash;
            member.PasswordChangedAt = now;
            await _context.SaveChangesAsync();

            // Add to password history
            await _passwordService.AddPasswordToHistory(memberId, newPasswordHash);

            // Invalidate all sessions
            await _sessionService.InvalidateAllUserSessions(memberId);

            // Log activity
            await _auditService.LogActivity(memberId, "Password Changed", "User changed password");

            // ✅ FORCE LOGOUT (remove the earlier return statement)
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Clear();

            TempData["SuccessMessage"] = "Password changed successfully! Please login with your new password.";
            return RedirectToAction("Login");
        }

        // Helper method to get Singapore time
        private DateTime GetSingaporeTime()
        {
            return TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, SingaporeTimeZone);
        }

        private string? SanitizeInput(string? input)
        {
            if (string.IsNullOrEmpty(input))
                return input;

            // Basic XSS prevention
            return System.Net.WebUtility.HtmlEncode(input);
        }
    }
}