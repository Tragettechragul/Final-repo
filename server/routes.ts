import type { Express, Request, Response, NextFunction } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertCustomerSchema, insertInventorySchema, insertRepairSchema, insertBookingSchema, insertInquirySchema } from "@shared/schema";
import { fromZodError } from "zod-validation-error";
import { z } from "zod";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// Development mode in-memory storage
const developmentStorage = {
  bookings: new Map<string, any>(),
  inquiries: new Map<string, any>(),
  
  // Add booking
  addBooking(booking: any) {
    this.bookings.set(booking.id, booking);
    console.log(`📋 Stored booking ${booking.id} in development storage. Total: ${this.bookings.size}`);
  },
  
  // Get all bookings
  getAllBookings() {
    const bookings = Array.from(this.bookings.values());
    console.log(`📋 Retrieved ${bookings.length} bookings from development storage`);
    return bookings;
  },
  
  // Get booking by ID
  getBooking(id: string) {
    return this.bookings.get(id);
  },
  
  // Update booking
  updateBooking(id: string, updates: any) {
    const existing = this.bookings.get(id);
    if (existing) {
      const updated = { ...existing, ...updates, updatedAt: new Date().toISOString() };
      this.bookings.set(id, updated);
      console.log(`📋 Updated booking ${id} in development storage`);
      return updated;
    }
    return null;
  },
  
  // Get booking by code
  getBookingByCode(code: string) {
    const bookings = Array.from(this.bookings.values());
    return bookings.find(booking => booking.bookingCode === code);
  }
};

// Extend Request interface to include user
interface AuthenticatedRequest extends Request {
  user?: { id: string; username: string; isAdmin: boolean };
}

// JWT secret key - CRITICAL SECURITY: Must be set via environment variable
const JWT_SECRET = process.env.JWT_SECRET;

// Validate JWT_SECRET at module load time to prevent insecure startup
if (!JWT_SECRET || JWT_SECRET === 'your-secret-key-change-this-in-production') {
  throw new Error(
    'SECURITY ERROR: JWT_SECRET environment variable is missing or using default placeholder. ' +
    'Set a secure JWT_SECRET environment variable before starting the server. ' +
    'Generate a secure secret using: openssl rand -base64 64'
  );
}

if (JWT_SECRET.length < 32) {
  throw new Error(
    'SECURITY ERROR: JWT_SECRET must be at least 32 characters long for security. ' +
    'Generate a secure secret using: openssl rand -base64 64'
  );
}

// JWT helper functions
function generateToken(user: { id: string; username: string; isAdmin: boolean }) {
  return jwt.sign({ id: user.id, username: user.username, isAdmin: user.isAdmin }, JWT_SECRET!, { expiresIn: '24h' });
}

function verifyToken(token: string) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET!) as jwt.JwtPayload;
    return decoded as { id: string; username: string; isAdmin: boolean };
  } catch (error) {
    return null;
  }
}

// CSRF token management for admin sessions
const csrfTokens = new Map<string, { token: string; expiry: number }>();

function generateCSRFToken(userId: string): string {
  const token = crypto.randomBytes(32).toString('hex');
  const expiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
  csrfTokens.set(userId, { token, expiry });
  
  // Clean up expired tokens
  csrfTokens.forEach((value, key) => {
    if (value.expiry < Date.now()) {
      csrfTokens.delete(key);
    }
  });
  
  return token;
}

function validateCSRFToken(userId: string, providedToken: string): boolean {
  const stored = csrfTokens.get(userId);
  if (!stored || stored.expiry < Date.now()) {
    return false;
  }
  return stored.token === providedToken;
}

// New JWT cookie-based admin authentication middleware
function requireAdminSession(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  const token = req.cookies?.authToken;
  
  if (!token) {
    return res.status(401).json({ error: "Authentication required" });
  }
  
  const decoded = verifyToken(token);
  if (!decoded || !decoded.isAdmin) {
    return res.status(401).json({ error: "Admin access required" });
  }
  
  req.user = decoded;
  next();
}

// CSRF protection middleware for state-changing admin operations
function requireCSRFProtection(req: AuthenticatedRequest, res: Response, next: NextFunction) {
  // Only protect state-changing operations
  if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method)) {
    const csrfToken = req.headers['x-csrf-token'] as string;
    
    if (!csrfToken) {
      return res.status(403).json({ error: "CSRF token required" });
    }
    
    if (!req.user || !validateCSRFToken(req.user.id, csrfToken)) {
      return res.status(403).json({ error: "Invalid CSRF token" });
    }
  }
  
  next();
}

// Legacy header-based admin auth (to be deprecated)
function requireAdminAuth(req: any, res: any, next: any) {
  const adminToken = req.headers['x-admin-token'];
  const validAdminToken = process.env.ADMIN_TOKEN;
  
  if (!validAdminToken) {
    return res.status(500).json({ error: "Admin authentication not configured" });
  }
  
  if (!adminToken || adminToken !== validAdminToken) {
    return res.status(401).json({ error: "Unauthorized: Admin access required" });
  }
  next();
}

export async function registerRoutes(app: Express): Promise<Server> {
  // Test endpoint for connectivity
  app.get("/api/test", (req, res) => {
    console.log('🔍 Test endpoint accessed from:', req.ip);
    res.json({ 
      status: 'OK', 
      message: 'Server is accessible',
      nodeEnv: process.env.NODE_ENV,
      timestamp: new Date().toISOString()
    });
  });

  // Authentication Routes
  app.post("/api/auth/login", async (req, res) => {
    console.log('🔐 Login attempt received:', { 
      username: req.body?.username, 
      hasPassword: !!req.body?.password,
      nodeEnv: process.env.NODE_ENV 
    });
    try {
      const { username, password } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ error: "Username and password required" });
      }
      
      // ALWAYS use local development bypass in development mode with admin credentials
      if (process.env.NODE_ENV === 'development' && username === 'admin' && password === 'admin123') {
        console.log('🔧 FORCE Using local development admin authentication (bypassing database)');
        
        const localAdminUser = {
          id: 'local-admin-id',
          username: 'admin',
          isAdmin: true
        };
        
        // Generate JWT token
        const token = generateToken(localAdminUser);
        
        // Generate CSRF token for admin session
        const csrfToken = generateCSRFToken(localAdminUser.id);
        
        // Set HttpOnly cookie
        res.cookie('authToken', token, {
          httpOnly: true,
          secure: false, // Development mode
          sameSite: 'lax',
          maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        return res.json({ 
          success: true, 
          user: localAdminUser,
          csrfToken: csrfToken
        });
      }
      
      // For any other credentials, return error
      return res.status(401).json({ error: "Invalid credentials" });
      
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ error: "Login failed" });
    }
  });

  app.post("/api/auth/logout", requireAdminSession, (req: AuthenticatedRequest, res) => {
    // Clear CSRF token for the user
    if (req.user) {
      csrfTokens.delete(req.user.id);
    }
    
    // Clear cookie with same security options as when setting for reliable deletion
    res.clearCookie('authToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax'
    });
    res.json({ success: true });
  });

  app.get("/api/auth/me", requireAdminSession, async (req: AuthenticatedRequest, res) => {
    try {
      // In development mode, return local admin user
      if (process.env.NODE_ENV === 'development' && req.user?.id === 'local-admin-id') {
        return res.json({ id: req.user.id, username: req.user.username, isAdmin: req.user.isAdmin });
      }
      
      const user = await storage.getUser(req.user!.id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      res.json({ id: user.id, username: user.username, isAdmin: user.isAdmin });
    } catch (error) {
      console.error("Get user error:", error);
      res.status(500).json({ error: "Failed to get user info" });
    }
  });

  app.get("/api/auth/csrf-token", requireAdminSession, async (req: AuthenticatedRequest, res) => {
    try {
      const csrfToken = generateCSRFToken(req.user!.id);
      res.json({ csrfToken });
    } catch (error) {
      console.error("CSRF token error:", error);
      res.status(500).json({ error: "Failed to generate CSRF token" });
    }
  });

  // Public Booking Route (No Authentication Required)
  app.post("/api/bookings", async (req, res) => {
    console.log('📋 Booking submission received:', { 
      hasData: !!req.body,
      dataKeys: Object.keys(req.body || {}),
      nodeEnv: process.env.NODE_ENV 
    });
    
    try {
      const result = insertBookingSchema.safeParse(req.body);
      if (!result.success) {
        return res.status(400).json({ 
          error: "Invalid booking data", 
          details: fromZodError(result.error).toString()
        });
      }
      
      // ALWAYS use local development bypass in development mode  
      if (process.env.NODE_ENV === 'development') {
        console.log('🔧 FORCE Using local development booking confirmation (bypassing database)');
        
        // Generate a mock booking ID
        const mockBookingId = `DEV-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        
        const mockBooking = {
          id: mockBookingId,
          bookingCode: `TRG-${Date.now().toString().slice(-6)}`,
          name: result.data.name,
          email: result.data.email,
          phone: result.data.phone,
          serviceType: result.data.serviceType,
          deviceType: result.data.deviceType,
          description: result.data.description,
          urgency: result.data.urgency,
          status: 'confirmed' as const,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };
        
        // STORE in development storage
        developmentStorage.addBooking(mockBooking);
        
        return res.status(201).json(mockBooking);
      }
      
      // If not development, try database
      try {
        const booking = await storage.createBooking(result.data);
        res.status(201).json(booking);
      } catch (dbError) {
        console.error("Database booking creation failed:", dbError);
        res.status(500).json({ error: "Failed to create booking" });
      }
      
    } catch (error) {
      console.error("Error creating booking:", error);
      res.status(500).json({ error: "Failed to create booking" });
    }
  });

  // Public Booking Lookup Route (No Authentication Required)
  app.get("/api/bookings/lookup/:code", async (req, res) => {
    try {
      const bookingCode = req.params.code;
      
      // In development mode, check memory storage
      if (process.env.NODE_ENV === 'development') {
        console.log('🔧 Using local development booking lookup');
        const booking = developmentStorage.getBookingByCode(bookingCode);
        if (!booking) {
          return res.status(404).json({ error: "Booking not found" });
        }
        return res.json({
          bookingCode: booking.bookingCode,
          status: booking.status,
          createdAt: booking.createdAt
        });
      }
      
      const booking = await storage.getBookingByCode(bookingCode);
      if (!booking) {
        return res.status(404).json({ error: "Booking not found" });
      }
      
      // Return limited public information
      res.json({
        bookingCode: booking.bookingCode,
        status: booking.status,
        createdAt: booking.createdAt
      });
    } catch (error) {
      console.error("Error looking up booking:", error);
      res.status(500).json({ error: "Failed to lookup booking" });
    }
  });

  // Admin Booking Management Routes
  app.get("/api/admin/bookings", requireAdminSession, async (req, res) => {
    try {
      // In development mode, return stored bookings
      if (process.env.NODE_ENV === 'development') {
        const bookings = developmentStorage.getAllBookings();
        return res.json({
          bookings: bookings,
          total: bookings.length,
          offset: 0,
          limit: undefined
        });
      }
      
      const { status, search, limit, offset } = req.query;
      let bookings = await storage.getBookings();
      
      // Filter by status if specified
      if (status && typeof status === 'string') {
        bookings = bookings.filter(booking => booking.status === status);
      }
      
      // Search across name, email, phone, device, service if specified
      if (search && typeof search === 'string') {
        const searchLower = search.toLowerCase();
        bookings = bookings.filter(booking =>
          booking.name.toLowerCase().includes(searchLower) ||
          booking.email.toLowerCase().includes(searchLower) ||
          booking.phone.toLowerCase().includes(searchLower) ||
          booking.deviceType.toLowerCase().includes(searchLower) ||
          booking.serviceType.toLowerCase().includes(searchLower)
        );
      }
      
      // Apply pagination if specified
      const startIndex = offset ? parseInt(offset as string, 10) : 0;
      const limitNum = limit ? parseInt(limit as string, 10) : undefined;
      const paginatedBookings = limitNum ? bookings.slice(startIndex, startIndex + limitNum) : bookings.slice(startIndex);
      
      res.json({
        bookings: paginatedBookings,
        total: bookings.length,
        offset: startIndex,
        limit: limitNum
      });
    } catch (error) {
      console.error("Error fetching admin bookings:", error);
      res.status(500).json({ error: "Failed to fetch bookings" });
    }
  });

  app.get("/api/admin/bookings/:id", requireAdminSession, async (req, res) => {
    try {
      // In development mode, get from memory storage
      if (process.env.NODE_ENV === 'development') {
        const booking = developmentStorage.getBooking(req.params.id);
        if (!booking) {
          return res.status(404).json({ error: "Booking not found" });
        }
        return res.json(booking);
      }
      
      const booking = await storage.getBooking(req.params.id);
      if (!booking) {
        return res.status(404).json({ error: "Booking not found" });
      }
      res.json(booking);
    } catch (error) {
      console.error("Error fetching admin booking:", error);
      res.status(500).json({ error: "Failed to fetch booking" });
    }
  });

  app.patch("/api/admin/bookings/:id", requireAdminSession, async (req, res) => {
    try {
      const { status, notes } = req.body;
      
      // In development mode, update in memory storage
      if (process.env.NODE_ENV === 'development') {
        const updates: any = {};
        if (status) {
          // Validate status values
          const validStatuses = ['pending', 'confirmed', 'in_progress', 'completed', 'cancelled'];
          if (!validStatuses.includes(status)) {
            return res.status(400).json({ error: "Invalid status value" });
          }
          updates.status = status;
        }
        if (notes !== undefined) updates.description = notes;
        
        const updated = developmentStorage.updateBooking(req.params.id, updates);
        if (!updated) {
          return res.status(404).json({ error: "Booking not found" });
        }
        return res.json(updated);
      }
      
      // Database version
      const updateData: any = {};
      if (status) {
        const validStatuses = ['pending', 'confirmed', 'in_progress', 'completed', 'cancelled'];
        if (!validStatuses.includes(status)) {
          return res.status(400).json({ error: "Invalid status value" });
        }
        updateData.status = status;
      }
      if (notes !== undefined) {
        updateData.description = notes;
      }
      
      const booking = await storage.updateBooking(req.params.id, updateData);
      if (!booking) {
        return res.status(404).json({ error: "Booking not found" });
      }
      res.json(booking);
    } catch (error) {
      console.error("Error updating booking:", error);
      res.status(500).json({ error: "Failed to update booking" });
    }
  });

  // Admin booking statistics endpoint
  app.get("/api/admin/bookings-stats", requireAdminSession, async (req, res) => {
    try {
      // In development mode, calculate stats from memory storage
      if (process.env.NODE_ENV === 'development') {
        const bookings = developmentStorage.getAllBookings();
        const stats = {
          total: bookings.length,
          pending: bookings.filter(b => b.status === 'pending').length,
          confirmed: bookings.filter(b => b.status === 'confirmed').length,
          in_progress: bookings.filter(b => b.status === 'in_progress').length,
          completed: bookings.filter(b => b.status === 'completed').length,
          cancelled: bookings.filter(b => b.status === 'cancelled').length,
          recent: bookings.filter(b => {
            const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
            return new Date(b.createdAt) > dayAgo;
          }).length
        };
        return res.json(stats);
      }
      
      const bookings = await storage.getBookings();
      const stats = {
        total: bookings.length,
        pending: bookings.filter(b => b.status === 'pending').length,
        confirmed: bookings.filter(b => b.status === 'confirmed').length,
        in_progress: bookings.filter(b => b.status === 'in_progress').length,
        completed: bookings.filter(b => b.status === 'completed').length,
        cancelled: bookings.filter(b => b.status === 'cancelled').length,
        recent: bookings.filter(b => {
          const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
          return new Date(b.createdAt) > dayAgo;
        }).length
      };
      res.json(stats);
    } catch (error) {
      console.error("Error fetching booking stats:", error);
      res.status(500).json({ error: "Failed to fetch booking statistics" });
    }
  });

  // Public Inquiry Route (No Authentication Required) 
  app.post("/api/inquiries", async (req, res) => {
    try {
      const result = insertInquirySchema.safeParse(req.body);
      if (!result.success) {
        return res.status(400).json({ 
          error: "Invalid inquiry data", 
          details: fromZodError(result.error).toString()
        });
      }
      
      // In development mode, return mock response
      if (process.env.NODE_ENV === 'development') {
        console.log('🔧 Using local development inquiry confirmation');
        return res.status(201).json({
          id: `INQ-${Date.now()}`,
          message: "Thank you for your inquiry. We'll get back to you soon!",
          status: 'received'
        });
      }
      
      const inquiry = await storage.createInquiry(result.data);
      res.status(201).json({
        id: inquiry.id,
        message: "Thank you for your inquiry. We'll get back to you soon!",
        status: 'received'
      });
    } catch (error) {
      console.error("Error creating inquiry:", error);
      res.status(500).json({ error: "Failed to submit inquiry" });
    }
  });

  // Create HTTP server
  const httpServer = createServer(app);
  
  return httpServer;
}