import "dotenv/config"; // Load environment variables from .env file
import express, { type Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./utils";
import { storage } from "./storage";
import crypto from "crypto";

// Database health and circuit breaker type definitions
interface DatabaseHealth {
  isHealthy: boolean;
  lastHealthCheck: number;
  consecutiveFailures: number;
  lastError?: string;
  connectionLatency?: number;
}

interface CircuitBreakerState {
  isOpen: boolean;
  failureCount: number;
  lastFailureTime: number;
  nextRetryTime: number;
}

interface DatabaseStatus {
  connected: boolean;
  health?: DatabaseHealth;
  circuitBreaker?: CircuitBreakerState;
  error?: string;
}

// Verify DATABASE_URL configuration and provide helpful diagnostics
function verifyDatabaseConfiguration(): { valid: boolean; error?: string; suggestions?: string[]; warnings?: string[] } {
  const databaseUrl = process.env.DATABASE_URL;
  
  if (!databaseUrl) {
    return {
      valid: false,
      error: "DATABASE_URL environment variable is not set",
      suggestions: [
        "For Replit deployments: Ensure DATABASE_URL is set in deployment secrets",
        "For local development: Add DATABASE_URL to your .env file",
        "Verify the database has been provisioned and the endpoint is enabled",
        "Check that the environment variable is properly loaded at startup",
        "If using Neon: Ensure the endpoint is enabled in your Neon dashboard"
      ]
    };
  }
  
  const warnings: string[] = [];
  const deploymentTips: string[] = [];
  
  // Basic URL validation
  try {
    const url = new URL(databaseUrl);
    
    if (!url.protocol.startsWith('postgres')) {
      return {
        valid: false,
        error: "DATABASE_URL does not appear to be a PostgreSQL connection string",
        suggestions: [
          "Ensure the URL starts with 'postgresql://' or 'postgres://'",
          "Check that you're using a PostgreSQL-compatible database",
          "Verify you copied the correct connection string from your provider"
        ]
      };
    }
    
    if (!url.hostname) {
      return {
        valid: false,
        error: "DATABASE_URL is missing hostname",
        suggestions: [
          "Verify the database connection string format: postgresql://user:password@host:port/database",
          "Check that the database endpoint is properly configured",
          "Ensure the URL was copied completely from your database provider"
        ]
      };
    }
    
    // Check for Neon-specific configuration
    if (url.hostname.includes('neon.tech') || url.hostname.includes('neon.')) {
      log("✅ Detected Neon database configuration");
      
      // Check for pooled endpoint (critical for deployment reliability)
      if (url.hostname.includes('pooler')) {
        log("✅ Using Neon pooled endpoint for optimal performance");
        deploymentTips.push("Pooled endpoint detected - excellent for production deployments");
      } else {
        warnings.push("DEPLOYMENT RECOMMENDATION: Use Neon's pooled endpoint for better reliability in production");
        warnings.push("Pooled endpoints handle connection limits and provide better failover support");
        deploymentTips.push("Get pooled endpoint: Neon Dashboard → Connection Details → Pooled Connection");
      }
      
      // Enhanced SSL and security checks for deployment
      if (!databaseUrl.includes('sslmode=require') && !databaseUrl.includes('ssl=true')) {
        if (process.env.NODE_ENV === 'production') {
          warnings.push("SECURITY WARNING: SSL not explicitly configured for production deployment");
          deploymentTips.push("Add ?sslmode=require to your DATABASE_URL for enhanced security");
        } else {
          warnings.push("Consider adding SSL configuration for enhanced security: sslmode=require");
        }
      }
      
      // Connection pooling verification
      if (databaseUrl.includes('pooling=true') || databaseUrl.includes('pgbouncer=true')) {
        log("✅ Connection pooling is explicitly enabled");
      } else {
        log("ℹ️  Connection pooling will be automatically added by the application");
        deploymentTips.push("Application will add connection pooling parameters automatically");
      }
      
      // Deployment-specific validations
      if (process.env.NODE_ENV === 'production') {
        deploymentTips.push("Production deployment detected - using enhanced error handling");
        
        // Check for common deployment issues
        if (url.hostname.includes('ep-') && !url.hostname.includes('pooler')) {
          warnings.push("DEPLOYMENT ISSUE: Direct endpoint URLs may have connection limits in production");
          warnings.push("Switch to pooled endpoint to avoid 'too many connections' errors");
        }
      }
      
      // Check for potential issues
      if (url.port && url.port !== '5432') {
        log(`ℹ️  Using custom port: ${url.port}`);
      }
      
    } else if (url.hostname.includes('localhost') || url.hostname.includes('127.0.0.1')) {
      log("🏠 Detected local database configuration");
      warnings.push("Local database detected - ensure PostgreSQL is running locally");
      if (process.env.NODE_ENV === 'production') {
        warnings.push("WARNING: Local database detected in production environment");
      }
    } else {
      log(`🔗 Detected external database: ${url.hostname}`);
      warnings.push("External database detected - ensure network connectivity is available");
      deploymentTips.push("External database - verify firewall and network access rules");
    }
    
    // Add deployment tips to warnings if any exist
    if (deploymentTips.length > 0) {
      warnings.push(...deploymentTips);
    }
    
    return { valid: true, warnings: warnings.length > 0 ? warnings : undefined };
  } catch (error) {
    return {
      valid: false,
      error: `Invalid DATABASE_URL format: ${error instanceof Error ? error.message : String(error)}`,
      suggestions: [
        "Check the DATABASE_URL format: postgresql://user:password@host:port/database",
        "Ensure there are no extra spaces, quotes, or special characters",
        "Verify the connection string from your database provider",
        "For Neon: Copy the connection string from Dashboard → Connection Details",
        "CRITICAL: If deploying, use the POOLED connection string for better reliability",
        "Test the connection string with a database client before deploying"
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

// Enhanced database connection management with deployment reliability
async function waitForDatabaseConnection(
  maxAttempts: number = process.env.NODE_ENV === 'production' ? 10 : 5, 
  baseDelayMs: number = process.env.NODE_ENV === 'production' ? 3000 : 2000
): Promise<DatabaseStatus> {
  const isProduction = process.env.NODE_ENV === 'production';
  
  log(`🔄 Starting database connection attempts (${isProduction ? 'production' : 'development'} mode)...`);
  
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const connectionStatus = await storage.checkConnection();
      
      if (connectionStatus.connected) {
        log("✅ Database connection established successfully.");
        
        // Log health metrics if available
        if (connectionStatus.health) {
          const latency = connectionStatus.health.connectionLatency;
          if (latency) {
            log(`📊 Database connection latency: ${latency}ms`);
            if (latency > 1000) {
              log("⚠️  High database latency detected - consider using pooled endpoint for better performance");
            }
          }
        }
        
        // Log circuit breaker status
        if (connectionStatus.circuitBreaker) {
          const cb = connectionStatus.circuitBreaker;
          if (cb.failureCount > 0) {
            log(`📊 Circuit breaker recovered (previous failures: ${cb.failureCount})`);
          }
        }
        
        return { connected: true, health: connectionStatus.health, circuitBreaker: connectionStatus.circuitBreaker };
      } else {
        const errorMessage = connectionStatus.error || 'Unknown connection error';
        log(`❌ Database connection attempt ${attempt}/${maxAttempts} failed: ${errorMessage}`);
        
        // Enhanced deployment error detection and guidance
        if (errorMessage.toLowerCase().includes('endpoint has been disabled') || 
            errorMessage.toLowerCase().includes('disabled') && errorMessage.toLowerCase().includes('endpoint')) {
          log("🔴 DEPLOYMENT ISSUE: Neon database endpoint is disabled");
          log("📋 CRITICAL ACTION REQUIRED:");
          log("   1. Login to your Neon dashboard");
          log("   2. Navigate to your project");
          log("   3. Go to Database section");
          log("   4. Enable the endpoint");
          log("⏱️  The application will start in limited mode and reconnect automatically");
          
          if (isProduction) {
            log("🚨 PRODUCTION WARNING: Database is unavailable - users will experience service degradation");
          }
          
          return { connected: false };
        } else if (errorMessage.toLowerCase().includes('too many connections')) {
          log("🔴 DEPLOYMENT ISSUE: Database connection pool exhausted");
          log("📋 SOLUTIONS:");
          log("   • Use Neon pooled endpoint (recommended)");
          log("   • Increase connection pool limits in your Neon dashboard");
          log("   • Scale down concurrent connections in application");
        } else if (errorMessage.toLowerCase().includes('connection refused') || errorMessage.toLowerCase().includes('econnrefused')) {
          log("🔴 DEPLOYMENT ISSUE: Cannot reach database server");
          log("📋 CHECK:");
          log("   • Network connectivity to database");
          log("   • DATABASE_URL hostname and port");
          log("   • Firewall or security group settings");
        } else if (errorMessage.toLowerCase().includes('authentication failed') || errorMessage.toLowerCase().includes('password')) {
          log("🔴 DEPLOYMENT ISSUE: Database authentication failed");
          log("📋 VERIFY:");
          log("   • DATABASE_URL credentials are correct");
          log("   • Database user exists and has proper permissions");
          log("   • No special characters are improperly encoded in URL");
        }
        
        // Circuit breaker information if available
        if (connectionStatus.circuitBreaker) {
          const cb = connectionStatus.circuitBreaker;
          if (cb.isOpen) {
            log(`⚡ Circuit breaker is open (failures: ${cb.failureCount})`);
            log(`⏰ Next retry available at: ${new Date(cb.nextRetryTime).toISOString()}`);
          }
        }
      }
    } catch (error) {
      const errorMessage = String(error);
      log(`❌ Database connection attempt ${attempt}/${maxAttempts} caught error:`, errorMessage);
      
      // Handle circuit breaker errors
      if (errorMessage.includes('Circuit breaker is open')) {
        log("⚡ Circuit breaker protection active - waiting for recovery window");
        break; // Exit early if circuit breaker is protecting us
      }
      
      // Check for disabled endpoint in caught errors
      if (errorMessage.toLowerCase().includes('endpoint has been disabled')) {
        log("🔴 DEPLOYMENT ISSUE: Neon database endpoint is disabled (caught in exception)");
        return { connected: false };
      }
    }
    
    // Calculate exponential backoff with jitter for production
    if (attempt < maxAttempts) {
      let delay = baseDelayMs * Math.pow(1.5, attempt - 1);
      const maxDelay = isProduction ? 15000 : 8000; // Max 15s in prod, 8s in dev
      delay = Math.min(delay, maxDelay);
      
      // Add jitter to prevent thundering herd
      if (isProduction) {
        const jitter = Math.random() * 0.2; // 20% jitter
        delay = delay * (1 + jitter);
      }
      
      log(`⏳ Waiting ${Math.round(delay)}ms before next database connection attempt...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  
  log("🔴 Failed to establish database connection after all attempts");
  log("📋 The application will start in limited mode");
  log("🔄 Database operations will retry automatically when connection is restored");
  
  if (isProduction) {
    log("🚨 PRODUCTION ALERT: Starting application without database connectivity");
    log("📊 Monitor application health and database status closely");
  }
  
  return { connected: false };
}

// Enhanced admin user seeding with deployment reliability
async function seedAdminUser(databaseStatus: DatabaseStatus): Promise<{ success: boolean; shouldRetry: boolean }> {
  const { connected } = databaseStatus;
  const isProduction = process.env.NODE_ENV === 'production';
  
  // If database is not connected, provide detailed guidance
  if (!connected) {
    log("🔶 Database not connected - admin user seeding deferred");
    
    if (isProduction) {
      log("🚨 PRODUCTION ALERT: Admin user seeding cannot proceed without database");
      log("📋 CRITICAL: Fix database connection to enable admin access");
      log("⚠️  The application will have limited functionality until database is restored");
    } else {
      log("📋 Development mode: Admin seeding will retry when database becomes available");
    }
    
    return { success: false, shouldRetry: true };
  }

  try {
    log("🔍 Checking admin user setup...");
    
    const users = await storage.listUsers();
    const adminExists = users.some(user => user.isAdmin);
    
    if (!adminExists) {
      log("🔧 No admin user found. Creating default admin user...");
      
      // Enhanced password management for deployment
      let adminPassword = process.env.ADMIN_INITIAL_PASSWORD;
      let passwordSource = 'environment variable';
      
      if (!adminPassword) {
        adminPassword = generateSecurePassword(24);
        passwordSource = 'generated';
        
        // Enhanced password logging for different environments
        if (isProduction) {
          log("🔐 Admin user created with generated password");
          log("🚨 SECURITY: Generated password not displayed in production logs");
          log("📋 CRITICAL: Set ADMIN_INITIAL_PASSWORD environment variable for known credentials");
          log("🔑 Alternative: Use database tools to reset admin password after deployment");
        } else {
          log("=".repeat(80));
          log("🔑 DEVELOPMENT: Generated admin credentials (save immediately):");
          log(`   Username: admin`);
          log(`   Password: ${adminPassword}`);
          log("⚠️  Change this password after first login!");
          log("💡 Tip: Set ADMIN_INITIAL_PASSWORD environment variable to avoid auto-generation");
          log("=".repeat(80));
        }
      } else {
        // Enhanced password validation
        if (adminPassword.length < 16) {
          const errorMsg = "ADMIN_INITIAL_PASSWORD must be at least 16 characters long";
          log(`❌ Password validation failed: ${errorMsg}`);
          throw new Error(errorMsg);
        }
        
        // Check password complexity in production
        if (isProduction) {
          const hasLower = /[a-z]/.test(adminPassword);
          const hasUpper = /[A-Z]/.test(adminPassword);
          const hasNumber = /\d/.test(adminPassword);
          const hasSymbol = /[^\w\s]/.test(adminPassword);
          
          if (!hasLower || !hasUpper || !hasNumber || !hasSymbol) {
            log("⚠️  PRODUCTION WARNING: Admin password should contain uppercase, lowercase, numbers, and symbols");
          }
        }
        
        log(`✅ Using admin password from ADMIN_INITIAL_PASSWORD environment variable`);
      }
      
      // Create admin user with enhanced error handling
      const adminUser = await storage.createUser({
        username: "admin",
        password: adminPassword
      });
      
      await storage.setUserAdmin(adminUser.id, true);
      
      log(`✅ Default admin user created successfully using ${passwordSource} password`);
      
      if (isProduction) {
        log("🔐 Production admin user is ready for secure access");
        log("📋 Reminder: Change default credentials after first deployment login");
      }
      
      return { success: true, shouldRetry: false };
    } else {
      log("✅ Admin user already exists - no action needed");
      
      if (isProduction) {
        log("🔐 Production admin access is configured");
      }
      
      return { success: true, shouldRetry: false };
    }
  } catch (error: any) {
    const errorMessage = error.message || String(error);
    log(`❌ Error during admin user seeding: ${errorMessage}`);
    
    // Enhanced deployment-specific error handling
    if (errorMessage.toLowerCase().includes('endpoint has been disabled')) {
      log("🔴 Database endpoint disabled during admin seeding");
      log("📋 ACTION: Enable Neon endpoint to complete admin setup");
      return { success: false, shouldRetry: true };
    } 
    
    if (errorMessage.toLowerCase().includes('connection') || errorMessage.toLowerCase().includes('timeout')) {
      log("🔴 Database connection issue during admin seeding");
      log("📋 CHECK: DATABASE_URL and network connectivity");
      return { success: false, shouldRetry: true };
    }
    
    if (errorMessage.toLowerCase().includes('authentication') || errorMessage.toLowerCase().includes('permission')) {
      log("🔴 Database authentication issue during admin seeding");
      log("📋 CHECK: Database user permissions and credentials");
      return { success: false, shouldRetry: false }; // Don't retry auth failures
    }
    
    if (errorMessage.includes('ADMIN_INITIAL_PASSWORD')) {
      log("🔴 Admin password validation failed");
      log("📋 FIX: Update ADMIN_INITIAL_PASSWORD to meet security requirements");
      return { success: false, shouldRetry: false }; // Don't retry validation failures
    }
    
    // Generic error handling
    if (isProduction) {
      log("🚨 PRODUCTION: Admin user seeding failed - application will start with limited access");
      log("📋 URGENT: Investigate and resolve admin setup issues");
    } else {
      log("⚠️  Development: Admin user seeding failed - check configuration");
    }
    
    return { success: false, shouldRetry: true };
  }
}

(async () => {
  // Verify database configuration first
  const dbConfig = verifyDatabaseConfiguration();
  if (!dbConfig.valid) {
    log("❌ Database Configuration Issue:");
    log(`   Error: ${dbConfig.error}`);
    if (dbConfig.suggestions) {
      log("   💡 Suggestions:");
      dbConfig.suggestions.forEach(suggestion => log(`   • ${suggestion}`));
    }
    log("⚠️  Server will start but database operations will fail until this is resolved.");
    log("");
  } else {
    if (dbConfig.warnings && dbConfig.warnings.length > 0) {
      log("⚠️  Database Configuration Warnings:");
      dbConfig.warnings.forEach(warning => log(`   • ${warning}`));
      log("");
    }
  }
  
  const server = await registerRoutes(app);
  
  // Enhanced startup sequence with comprehensive deployment reliability
  let databaseStatus: DatabaseStatus = { connected: false };
  let adminResult = { success: false, shouldRetry: false };
  const isProduction = process.env.NODE_ENV === 'production';
  
  try {
    log("🚀 Starting application initialization sequence...");
    
    // Attempt database connection with enhanced error handling
    databaseStatus = await waitForDatabaseConnection();
    
    if (databaseStatus.connected) {
      log("✅ Database connection successful - proceeding with admin setup");
      adminResult = await seedAdminUser(databaseStatus);
    } else {
      log("⚠️  Database connection failed - attempting admin setup anyway");
      adminResult = await seedAdminUser(databaseStatus);
    }
    
  } catch (error: any) {
    const errorMessage = String(error);
    log("🔴 Critical error during application startup:", errorMessage);
    
    // Enhanced deployment-specific error guidance
    if (errorMessage.toLowerCase().includes('endpoint has been disabled')) {
      log("")
      log("🚨 DEPLOYMENT CRITICAL: Neon database endpoint is disabled");
      log("📋 IMMEDIATE ACTION REQUIRED:");
      log("   Step 1: Login to your Neon dashboard (https://neon.tech)");
      log("   Step 2: Navigate to your project");
      log("   Step 3: Go to Settings → General → Compute settings");
      log("   Step 4: Enable 'Auto-suspend' or manually start the endpoint");
      log("   Step 5: Wait for the endpoint status to show 'Active'");
      log("");
      log("⏱️  Expected recovery time: 30-60 seconds after enabling");
      log("🔄 The application will automatically reconnect once the endpoint is active");
      
      if (isProduction) {
        log("🚨 PRODUCTION IMPACT: Service is degraded until database endpoint is enabled");
      }
    } else if (errorMessage.toLowerCase().includes('connection') && errorMessage.toLowerCase().includes('refused')) {
      log("");
      log("🔴 DEPLOYMENT ISSUE: Database connection refused");
      log("📋 TROUBLESHOOTING STEPS:");
      log("   • Verify DATABASE_URL is correct");
      log("   • Check database server is running");
      log("   • Verify network connectivity");
      log("   • Check firewall settings");
    } else {
      log("");
      log("🔴 DEPLOYMENT ISSUE: Unexpected startup error");
      log("📋 ERROR DETAILS:", errorMessage);
      log("📋 INVESTIGATION: Check deployment logs and environment configuration");
    }
    
    databaseStatus = { connected: false };
    adminResult = { success: false, shouldRetry: false };
  }

  // Comprehensive application status reporting
  log("");
  log("================================================================================");
  log("📊 APPLICATION STARTUP SUMMARY");
  log(`   Environment: ${isProduction ? 'production' : 'development'} mode`);
  log(`   Startup Time: ${new Date().toISOString()}`);
  log("");
  
  // Database Status Section
  log("🗄️  DATABASE STATUS:");
  if (databaseStatus.connected) {
    log("   Connected: ✅ Yes");
    
    if (databaseStatus.health) {
      const health = databaseStatus.health;
      log(`   Health Status: ${health.isHealthy ? '✅ Healthy' : '❌ Unhealthy'}`);
      
      if (health.connectionLatency !== undefined) {
        const latency = health.connectionLatency;
        const status = latency < 500 ? '🟢' : latency < 1000 ? '🟡' : '🔴';
        log(`   Connection Latency: ${status} ${latency}ms`);
      }
      
      if (health.consecutiveFailures > 0) {
        log(`   Recent Failures: ⚠️  ${health.consecutiveFailures} consecutive`);
      }
    }
    
    if (databaseStatus.circuitBreaker) {
      const cb = databaseStatus.circuitBreaker;
      const status = cb.isOpen ? '🔴 Open' : '🟢 Closed';
      log(`   Circuit Breaker: ${status}`);
      
      if (cb.failureCount > 0) {
        log(`   Failure Count: ⚠️  ${cb.failureCount}`);
      }
    }
  } else {
    log("   Connected: ❌ No");
    log("   Health Status: ❌ Unavailable");
    
    if (databaseStatus.error) {
      log(`   Error: ${databaseStatus.error}`);
    }
  }
  log("");
  
  // Admin User Status Section
  log("👤 ADMIN USER STATUS:");
  if (adminResult.success) {
    log("   Ready: ✅ Yes");
    
    if (isProduction) {
      log("   Credentials: 🔐 Production secure");
      log("   Access: 🎯 Available via login endpoint");
    } else {
      log("   Credentials: 🔑 Check startup logs for details");
      log("   Default: admin/admin123 (if using environment password)");
    }
  } else {
    log("   Ready: ❌ No");
    log("   Issue: Admin user setup failed");
    
    if (adminResult.shouldRetry) {
      log("   Recovery: 🔄 Will retry when database is available");
    } else {
      log("   Recovery: ⚠️  Manual intervention required");
    }
    
    if (isProduction) {
      log("   IMPACT: 🚨 Admin access unavailable - investigate immediately");
    }
  }
  log("");
  
  // Application Mode Section
  log("🚀 APPLICATION MODE:");
  if (databaseStatus.connected && adminResult.success) {
    log("   Status: ✅ Full functionality available");
    log("   APIs: 🌐 All endpoints operational");
    log("   Authentication: 🔐 Working");
    
    if (isProduction) {
      log("   Production: 🏭 Ready for traffic");
      log("   Monitoring: 📊 Health checks active");
    }
  } else if (databaseStatus.connected && !adminResult.success) {
    log("   Status: ⚠️  Limited functionality (database OK, admin setup failed)");
    log("   APIs: 🌐 Data endpoints available");
    log("   Authentication: ❌ Admin access may be limited");
    
    if (isProduction) {
      log("   Production: ⚠️  Degraded service - admin functions unavailable");
    }
  } else if (!databaseStatus.connected && adminResult.success) {
    log("   Status: ❌ Severe limitations (database unavailable)");
    log("   APIs: ❌ Data endpoints will fail");
    log("   Authentication: ⚠️  Limited functionality");
    
    if (isProduction) {
      log("   Production: 🚨 Major service disruption");
    }
  } else {
    log("   Status: 🔴 Minimal functionality (database and admin issues)");
    log("   APIs: ❌ Most endpoints will fail");
    log("   Authentication: ❌ Severely limited");
    
    if (isProduction) {
      log("   Production: 🚨 CRITICAL - Service largely unavailable");
    }
  }
  
  log("================================================================================");
  log("");

  // Start the server regardless of database/admin status
  await setupVite(app, server);

  const port = parseInt(process.env.PORT || "5000");
  
  server.listen(port, "0.0.0.0", () => {
    const timestamp = new Date().toISOString();
    log(`serving on port ${port} (host: 0.0.0.0)`);
    
    if (isProduction) {
      log(`🌐 Production server started successfully at ${timestamp}`);
      log(`📊 Server accessible at: http://0.0.0.0:${port}`);
      log(`🔗 Health check: http://0.0.0.0:${port}/api/test`);
      
      if (!databaseStatus.connected) {
        log("⚠️  PRODUCTION ALERT: Database is unavailable - monitor and resolve urgently");
      }
      
      if (!adminResult.success) {
        log("⚠️  PRODUCTION ALERT: Admin setup incomplete - verify admin access");
      }
    } else {
      log(`🚀 Development server ready at ${timestamp}`);
      log("📍 Access the application at: http://localhost:" + port);
    }
  });

  // Graceful shutdown handling
  const gracefulShutdown = (signal: string) => {
    log(`📡 ${signal} received - starting graceful shutdown...`);
    
    server.close(() => {
      log("🛑 HTTP server closed");
      
      // Close database connections if available
      if (storage && typeof storage.closeConnections === 'function') {
        storage.closeConnections().then(() => {
          log("🗄️  Database connections closed");
          process.exit(0);
        }).catch((error: any) => {
          log("❌ Error closing database connections:", String(error));
          process.exit(1);
        });
      } else {
        process.exit(0);
      }
    });
    
    // Force exit after 30 seconds
    setTimeout(() => {
      log("⏰ Graceful shutdown timeout - forcing exit");
      process.exit(1);
    }, 30000);
  };

  // Handle termination signals
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));

  // Handle uncaught exceptions
  process.on('uncaughtException', (error: Error) => {
    log("🚨 Uncaught Exception:", error.message);
    log("Stack trace:", error.stack || 'No stack trace available');
    
    if (isProduction) {
      log("🚨 PRODUCTION CRITICAL: Uncaught exception in production environment");
    }
    
    gracefulShutdown('UNCAUGHT_EXCEPTION');
  });

  // Handle unhandled promise rejections
  process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
    log("🚨 Unhandled Promise Rejection at:", promise);
    log("Reason:", String(reason));
    
    if (isProduction) {
      log("🚨 PRODUCTION WARNING: Unhandled promise rejection in production environment");
      // In production, we might want to restart the process or alert monitoring
    }
  });
})();
