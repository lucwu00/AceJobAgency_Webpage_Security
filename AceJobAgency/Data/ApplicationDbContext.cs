using Microsoft.EntityFrameworkCore;
using AceJobAgency.Models;

namespace AceJobAgency.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Member> Members { get; set; }
        public DbSet<PasswordHistory> PasswordHistories { get; set; }
        public DbSet<AuditLog> AuditLogs { get; set; }
        public DbSet<UserSession> UserSessions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Member>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.HasIndex(e => e.Email).IsUnique();

                entity.HasMany(e => e.PasswordHistories)
                    .WithOne(e => e.Member)
                    .HasForeignKey(e => e.MemberId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasMany(e => e.AuditLogs)
                    .WithOne(e => e.Member)
                    .HasForeignKey(e => e.MemberId)
                    .OnDelete(DeleteBehavior.SetNull);

                entity.HasMany(e => e.UserSessions)
                    .WithOne(e => e.Member)
                    .HasForeignKey(e => e.MemberId)
                    .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}