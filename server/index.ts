import "dotenv/config"; // Load environment variables from .env file
import express, { type Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";
import { storage } from "./storage";
import crypto from "crypto";

// Verify DATABASE_URL configuration and provide helpful diagnostics
function verifyDatabaseConfiguration(): { valid: boolean; error?: string; suggestions?: string[] } {
  const databaseUrl = process.env.DATABASE_URL;
  
  if (!databaseUrl) {
    return {
      valid: false,
      error: "DATABASE_URL environment variable is not set",
      suggestions: [
        "Check that your .env file contains DATABASE_URL",
        "Verify the environment variable is properly loaded",
        "Ensure the database has been provisioned in your deployment settings"
      ]
    };
  }
  
  // Basic URL validation
  try {
    const url = new URL(databaseUrl);
    
    if (!url.protocol.startsWith('postgres')) {
      return {
        valid: false,
        error: "DATABASE_URL does not appear to be a PostgreSQL connection string",
        suggestions: [
          "Ensure the URL starts with 'postgresql://' or 'postgres://'",
          "Check that you're using the correct database provider"
        ]
      };
    }
    
    if (!url.hostname) {
      return {
        valid: false,
        error: "DATABASE_URL is missing hostname",
        suggestions: [
          "Verify the database connection string format",
          "Check that the database endpoint is properly configured"
        ]
      };
    }
    
    // Check for Neon-specific indicators
    if (url.hostname.includes('neon.tech') || url.hostname.includes('neon.')) {
      log("Detected Neon database configuration");
      if (databaseUrl.includes('pooling=true') || databaseUrl.includes('pgbouncer=true')) {
        log("Connection pooling is enabled");
      } else {
        log("Note: Connection pooling will be automatically added");
      }
    }
    
    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: `Invalid DATABASE_URL format: ${error instanceof Error ? error.message : String(error)}`,
      suggestions: [
        "Check the DATABASE_URL format: postgresql://user:password@host:port/database",
        "Ensure there are no extra spaces or special characters",
        "Verify the connection string from your database provider"
      ]
    };
  }
}

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);
    }
  });

  next();
});

/**
 * Generate a cryptographically secure random password
 * @param length Password length (minimum 16 characters)
 * @returns Secure random password with mixed case, numbers, and symbols
 */
function generateSecurePassword(length: number = 24): string {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
  let password = '';
  
  // Ensure at least one character from each category
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  password += uppercase[crypto.randomInt(uppercase.length)];
  password += lowercase[crypto.randomInt(lowercase.length)];
  password += numbers[crypto.randomInt(numbers.length)];
  password += symbols[crypto.randomInt(symbols.length)];
  
  // Fill the rest randomly
  for (let i = password.length; i < length; i++) {
    password += charset[crypto.randomInt(charset.length)];
  }
  
  // Shuffle the password to randomize character positions
  return password.split('').sort(() => crypto.randomInt(3) - 1).join('');
}

// Check database connection and wait for it to be ready
async function waitForDatabaseConnection(maxAttempts: number = 10, delayMs: number = 2000): Promise<void> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const connectionStatus = await storage.checkConnection();
      if (connectionStatus.connected) {
        log("Database connection established successfully.");
        return;
      } else {
        log(`Database connection attempt ${attempt}/${maxAttempts} failed: ${connectionStatus.error}`);
      }
    } catch (error) {
      log(`Database connection attempt ${attempt}/${maxAttempts} failed:`, String(error));
    }
    
    if (attempt < maxAttempts) {
      log(`Waiting ${delayMs}ms before next database connection attempt...`);
      await new Promise(resolve => setTimeout(resolve, delayMs));
    }
  }
  
  throw new Error(
    `Failed to establish database connection after ${maxAttempts} attempts. ` +
    "Please check your DATABASE_URL and ensure the Neon endpoint is enabled. " +
    "You may need to re-enable the endpoint through the Neon dashboard or API."
  );
}

// Seed initial admin user if none exists with robust error handling
async function seedAdminUser() {
  try {
    log("Checking admin user setup...");
    
    const users = await storage.listUsers();
    const adminExists = users.some(user => user.isAdmin);
    
    if (!adminExists) {
      log("No admin user found. Creating default admin...");
      
      // First, try to use password from environment variable
      let adminPassword = process.env.ADMIN_INITIAL_PASSWORD;
      let passwordSource = 'environment variable';
      
      if (!adminPassword) {
        // If no environment variable, generate a secure random password
        adminPassword = generateSecurePassword(24);
        passwordSource = 'generated';
        
        // Only log the generated password in development environment
        if (process.env.NODE_ENV === 'development') {
          log("=".repeat(80));
          log("IMPORTANT: Generated admin password (save this immediately):");
          log(`Username: admin`);
          log(`Password: ${adminPassword}`);
          log("Change this password after first login!");
          log("Set ADMIN_INITIAL_PASSWORD environment variable to avoid auto-generation.");
          log("=".repeat(80));
        } else {
          log("Admin user created with generated password.");
          log("SECURITY: Generated password not logged in production. Set ADMIN_INITIAL_PASSWORD to use a known password.");
        }
      } else {
        // Validate environment password meets minimum security requirements
        if (adminPassword.length < 16) {
          throw new Error("ADMIN_INITIAL_PASSWORD must be at least 16 characters long");
        }
        log("Using admin password from ADMIN_INITIAL_PASSWORD environment variable");
      }
      
      const adminUser = await storage.createUser({
        username: "admin",
        password: adminPassword
      });
      await storage.setUserAdmin(adminUser.id, true);
      log(`Default admin user created successfully using ${passwordSource} password.`);
      
      if (passwordSource === 'environment variable') {
        log("Admin user created with secure password from environment variable.");
      }
    } else {
      log("Admin user already exists.");
    }
  } catch (error: any) {
    const errorMessage = error.message || String(error);
    log("Error during admin user seeding:", errorMessage);
    
    // Provide more specific error messages based on error type
    if (errorMessage.includes('endpoint has been disabled')) {
      log("🔄 Database endpoint is disabled. The app will start but database operations will fail.");
      log("📋 To fix this: Enable the Neon endpoint through your Neon dashboard or API.");
      log("🚀 The app will continue to start and retry database operations automatically.");
      // Don't throw the error - allow the app to start and retry later
      return;
    } else if (errorMessage.includes('CONNECTION') || errorMessage.includes('timeout')) {
      log("🔄 Database connection issue detected. The app will start but database operations may be unstable.");
      log("📋 Please check your DATABASE_URL and network connectivity.");
      return;
    }
    
    // For other errors, still prevent startup to maintain security
    throw error;
  }
}

(async () => {
  // Verify database configuration first
  const dbConfig = verifyDatabaseConfiguration();
  if (!dbConfig.valid) {
    log("⚠️  Database Configuration Issue:");
    log(`   Error: ${dbConfig.error}`);
    if (dbConfig.suggestions) {
      log("   Suggestions:");
      dbConfig.suggestions.forEach(suggestion => log(`   • ${suggestion}`));
    }
    log("⚠️  Server will start but database operations will fail until this is resolved.");
  }
  
  const server = await registerRoutes(app);
  
  // Wait for database connection and seed admin user
  try {
    await waitForDatabaseConnection();
    await seedAdminUser();
  } catch (error) {
    log("Database startup failed:", String(error));
    log("⚠️  Server will start without database connectivity.");
    log("🔄 Database operations will automatically retry when the connection is restored.");
    
    if (String(error).includes('endpoint has been disabled')) {
      log("⚠️  IMPORTANT: Your Neon database endpoint has been disabled.");
      log("📋 ACTION REQUIRED: Please enable the endpoint through your Neon dashboard:");
      log("   1. Go to your Neon project dashboard");
      log("   2. Navigate to the Database section");
      log("   3. Enable the endpoint for your database");
      log("   4. The application will automatically reconnect once enabled");
    }
  }

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    // Log the error for debugging
    console.error('Express error handler:', err);
    
    // Send error response but don't re-throw to prevent crash loops
    if (!res.headersSent) {
      res.status(status).json({ message });
    }
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
   const port = parseInt(process.env.PORT || '5000', 10);
  
  // Use localhost for Windows/development, 0.0.0.0 for production
  const host = process.env.NODE_ENV === 'development' ? '127.0.0.1' : '0.0.0.0';
  
  server.listen({
    port,
    host,
    reusePort: false, // Disable for Windows compatibility
  }, () => {
    log(`serving on port ${port} (host: ${host})`);
  });
})();
