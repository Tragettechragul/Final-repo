import { 
  type User, type InsertUser,
  type Customer, type InsertCustomer,
  type Inventory, type InsertInventory,
  type Repair, type InsertRepair,
  type Booking, type InsertBooking,
  type Inquiry, type InsertInquiry,
  users, customers, inventory, repairs, bookings, inquiries
} from "@shared/schema";
import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import { eq, desc, sql } from "drizzle-orm";
import * as bcrypt from "bcryptjs";

// Database connection configuration with retry logic
interface DatabaseConfig {
  maxRetries: number;
  retryDelay: number;
  connectionTimeout: number;
}

const dbConfig: DatabaseConfig = {
  maxRetries: 3,
  retryDelay: 1000, // 1 second
  connectionTimeout: 10000, // 10 seconds
};

// modify the interface with any CRUD methods
// you might need

export interface IStorage {
  // Users
  getUser(id: string): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  verifyPassword(user: User, password: string): boolean;
  listUsers(): Promise<User[]>;
  setUserAdmin(id: string, isAdmin: boolean): Promise<User>;
  
  // Customers
  getCustomers(): Promise<Customer[]>;
  getCustomer(id: string): Promise<Customer | undefined>;
  createCustomer(customer: InsertCustomer): Promise<Customer>;
  updateCustomer(id: string, customer: Partial<InsertCustomer>): Promise<Customer>;
  searchCustomers(query: string): Promise<Customer[]>;
  
  // Inventory
  getInventory(): Promise<Inventory[]>;
  getInventoryItem(id: string): Promise<Inventory | undefined>;
  createInventoryItem(item: InsertInventory): Promise<Inventory>;
  updateInventoryItem(id: string, item: Partial<InsertInventory>): Promise<Inventory>;
  getLowStockItems(): Promise<Inventory[]>;
  
  // Repairs
  getRepairs(): Promise<Repair[]>;
  getRepair(id: string): Promise<Repair | undefined>;
  createRepair(repair: InsertRepair): Promise<Repair>;
  updateRepair(id: string, repair: Partial<InsertRepair>): Promise<Repair>;
  getRepairsByCustomer(customerId: string): Promise<Repair[]>;
  
  // Bookings
  getBookings(): Promise<Booking[]>;
  getBooking(id: string): Promise<Booking | undefined>;
  getBookingByCode(bookingCode: string): Promise<Booking | undefined>;
  createBooking(booking: InsertBooking): Promise<Booking>;
  updateBooking(id: string, booking: Partial<InsertBooking>): Promise<Booking>;
  
  // Inquiries
  getInquiries(): Promise<Inquiry[]>;
  createInquiry(inquiry: InsertInquiry): Promise<Inquiry>;
  updateInquiryStatus(id: string, status: string): Promise<Inquiry>;
  
  // Public tracking
  getRepairByTrackingCode(trackingCode: string): Promise<{
    trackingCode: string;
    device: string;
    status: string;
    progress: number;
    expectedCompletion: Date | null;
  } | undefined>;
}

export class DatabaseStorage implements IStorage {
  private db: any;
  private connection: any;
  private isConnected: boolean = false;

  constructor() {
    try {
      this.initializeConnection();
    } catch (error) {
      // Store the initialization error for later reporting
      console.error('Database initialization failed:', error);
      this.isConnected = false;
    }
  }

  private initializeConnection() {
    if (!process.env.DATABASE_URL) {
      throw new Error('DATABASE_URL environment variable is not set. Please configure your database connection.');
    }

    // Add connection pooling by appending pooling parameters to the DATABASE_URL
    const databaseUrl = this.addConnectionPooling(process.env.DATABASE_URL);
    
    this.connection = neon(databaseUrl, {
      fetchOptions: {
        // Set connection timeout (increase for cold starts)
        signal: AbortSignal.timeout(15000), // 15 seconds instead of 10
      },
    });
    
    this.db = drizzle(this.connection);
  }

  private addConnectionPooling(url: string): string {
    const urlObj = new URL(url);
    
    // Add pooling parameters for better connection management
    urlObj.searchParams.set('pgbouncer', 'true');
    urlObj.searchParams.set('pool_timeout', '15');
    urlObj.searchParams.set('connect_timeout', '15');
    
    // For Neon specifically, also add pooling parameter
    if (urlObj.hostname.includes('neon.tech') || urlObj.hostname.includes('neon.')) {
      urlObj.searchParams.set('pooling', 'true');
      
      // Log if this appears to be a non-pooled hostname
      if (!urlObj.hostname.includes('pooler')) {
        console.log('Note: Consider using Neon pooled endpoint hostname (contains "pooler") for better connection pooling.');
      }
    }
    
    return urlObj.toString();
  }

  private async executeWithRetry<T>(operation: () => Promise<T>, operationName: string = 'database operation'): Promise<T> {
    let lastError: Error;
    
    for (let attempt = 1; attempt <= dbConfig.maxRetries; attempt++) {
      try {
        const result = await operation();
        this.isConnected = true;
        return result;
      } catch (error: any) {
        lastError = error;
        this.isConnected = false;
        
        console.error(`Database ${operationName} failed (attempt ${attempt}/${dbConfig.maxRetries}):`, error.message);
        
        // Check if it's a connection-related error that might benefit from retry
        if (this.isRetryableError(error) && attempt < dbConfig.maxRetries) {
          console.log(`Retrying ${operationName} in ${dbConfig.retryDelay}ms...`);
          await this.sleep(dbConfig.retryDelay * attempt); // Exponential backoff
          continue;
        }
        
        // If not retryable or max retries reached, throw the error
        throw error;
      }
    }
    
    throw lastError!;
  }

  private isRetryableError(error: any): boolean {
    const retryableErrorMessages = [
      'the endpoint has been disabled',
      'connection timeout',
      'econnreset',
      'enotfound',
      'econnrefused',
      'timeout',
      'network error',
      'timeouterror',
    ];
    
    // Check main error message
    const errorMessage = error.message?.toLowerCase() || '';
    if (retryableErrorMessages.some(msg => errorMessage.includes(msg))) {
      return true;
    }
    
    // Check error cause (for wrapped errors)
    const causeMessage = error.cause?.message?.toLowerCase() || '';
    if (causeMessage && retryableErrorMessages.some(msg => causeMessage.includes(msg))) {
      return true;
    }
    
    // Check DOMException name (for timeout errors)
    if (error.name === 'TimeoutError' || error.sourceError?.name === 'TimeoutError') {
      return true;
    }
    
    // Check error code
    const errorCode = error.code?.toLowerCase() || '';
    if (['econnreset', 'enotfound', 'econnrefused', 'etimedout'].includes(errorCode)) {
      return true;
    }
    
    return false;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  // Health check method to verify database connectivity
  async checkConnection(): Promise<{ connected: boolean; error?: string }> {
    try {
      await this.executeWithRetry(async () => {
        await this.db.execute(sql`SELECT 1`);
      }, 'connection check');
      return { connected: true };
    } catch (error: any) {
      return { connected: false, error: error.message };
    }
  }

  // Users
  async getUser(id: string): Promise<User | undefined> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select().from(users).where(eq(users.id, id)).limit(1);
      return result[0];
    }, 'getUser');
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select().from(users).where(eq(users.username, username)).limit(1);
      return result[0];
    }, 'getUserByUsername');
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    return await this.executeWithRetry(async () => {
      // Hash password with bcrypt using 12 salt rounds for security
      const hashedPassword = bcrypt.hashSync(insertUser.password, 12);
      const userWithHashedPassword = {
        ...insertUser,
        password: hashedPassword
      };
      
      const result = await this.db.insert(users).values(userWithHashedPassword).returning();
      return result[0];
    }, 'createUser');
  }

  verifyPassword(user: User, password: string): boolean {
    return bcrypt.compareSync(password, user.password);
  }

  async listUsers(): Promise<User[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(users);
    }, 'listUsers');
  }

  async setUserAdmin(id: string, isAdmin: boolean): Promise<User> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.update(users)
        .set({ isAdmin })
        .where(eq(users.id, id))
        .returning();
      return result[0];
    }, 'setUserAdmin');
  }

  // Customers
  async getCustomers(): Promise<Customer[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(customers).orderBy(desc(customers.createdAt));
    }, 'getCustomers');
  }

  async getCustomer(id: string): Promise<Customer | undefined> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select().from(customers).where(eq(customers.id, id)).limit(1);
      return result[0];
    }, 'getCustomer');
  }

  async createCustomer(customer: InsertCustomer): Promise<Customer> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.insert(customers).values({
        ...customer,
        updatedAt: new Date()
      }).returning();
      return result[0];
    }, 'createCustomer');
  }

  async updateCustomer(id: string, customer: Partial<InsertCustomer>): Promise<Customer> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.update(customers)
        .set({ ...customer, updatedAt: new Date() })
        .where(eq(customers.id, id))
        .returning();
      return result[0];
    }, 'updateCustomer');
  }

  async searchCustomers(query: string): Promise<Customer[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(customers)
        .where(sql`${customers.name} ILIKE ${`%${query}%`} OR ${customers.email} ILIKE ${`%${query}%`} OR ${customers.phone} ILIKE ${`%${query}%`}`)
        .orderBy(desc(customers.createdAt));
    }, 'searchCustomers');
  }

  // Inventory
  async getInventory(): Promise<Inventory[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(inventory).orderBy(inventory.name);
    }, 'getInventory');
  }

  async getInventoryItem(id: string): Promise<Inventory | undefined> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select().from(inventory).where(eq(inventory.id, id)).limit(1);
      return result[0];
    }, 'getInventoryItem');
  }

  async createInventoryItem(item: InsertInventory): Promise<Inventory> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.insert(inventory).values({
        ...item,
        updatedAt: new Date()
      }).returning();
      return result[0];
    }, 'createInventoryItem');
  }

  async updateInventoryItem(id: string, item: Partial<InsertInventory>): Promise<Inventory> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.update(inventory)
        .set({ ...item, updatedAt: new Date() })
        .where(eq(inventory.id, id))
        .returning();
      return result[0];
    }, 'updateInventoryItem');
  }

  async getLowStockItems(): Promise<Inventory[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(inventory)
        .where(sql`${inventory.stock} <= ${inventory.minStock}`)
        .orderBy(inventory.name);
    }, 'getLowStockItems');
  }

  // Repairs
  async getRepairs(): Promise<Repair[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(repairs).orderBy(desc(repairs.createdAt));
    }, 'getRepairs');
  }

  async getRepair(id: string): Promise<Repair | undefined> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select().from(repairs).where(eq(repairs.id, id)).limit(1);
      return result[0];
    }, 'getRepair');
  }

  async createRepair(repair: InsertRepair): Promise<Repair> {
    return await this.executeWithRetry(async () => {
      // Generate unique tracking code
      const trackingCode = `TR${Date.now().toString().slice(-8)}${Math.random().toString(36).substring(2, 5).toUpperCase()}`;
      
      const result = await this.db.insert(repairs).values({
        ...repair,
        trackingCode,
        updatedAt: new Date()
      }).returning();
      return result[0];
    }, 'createRepair');
  }

  async updateRepair(id: string, repair: Partial<InsertRepair>): Promise<Repair> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.update(repairs)
        .set({ ...repair, updatedAt: new Date() })
        .where(eq(repairs.id, id))
        .returning();
      return result[0];
    }, 'updateRepair');
  }

  async getRepairsByCustomer(customerId: string): Promise<Repair[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(repairs)
        .where(eq(repairs.customerId, customerId))
        .orderBy(desc(repairs.createdAt));
    }, 'getRepairsByCustomer');
  }

  // Bookings
  async getBookings(): Promise<Booking[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(bookings).orderBy(desc(bookings.createdAt));
    }, 'getBookings');
  }

  async getBooking(id: string): Promise<Booking | undefined> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select().from(bookings).where(eq(bookings.id, id)).limit(1);
      return result[0];
    }, 'getBooking');
  }

  async getBookingByCode(bookingCode: string): Promise<Booking | undefined> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select().from(bookings).where(eq(bookings.bookingCode, bookingCode)).limit(1);
      return result[0];
    }, 'getBookingByCode');
  }

  private async getNextBookingCode(): Promise<string> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select({ bookingCode: bookings.bookingCode })
        .from(bookings)
        .orderBy(desc(bookings.bookingCode))
        .limit(1);
      
      if (!result.length) {
        return "0001";
      }
      
      const lastCode = parseInt(result[0].bookingCode, 10);
      const nextCode = lastCode + 1;
      return nextCode.toString().padStart(4, '0');
    }, 'getNextBookingCode');
  }

  async createBooking(booking: InsertBooking): Promise<Booking> {
    return await this.executeWithRetry(async () => {
      // Generate next booking code
      const nextCode = await this.getNextBookingCode();
      
      const result = await this.db.insert(bookings).values({
        ...booking,
        bookingCode: nextCode
      }).returning();
      
      return result[0];
    }, 'createBooking');
  }

  async updateBooking(id: string, booking: Partial<InsertBooking>): Promise<Booking> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.update(bookings)
        .set({ ...booking, updatedAt: new Date() })
        .where(eq(bookings.id, id))
        .returning();
      return result[0];
    }, 'updateBooking');
  }

  // Inquiries
  async getInquiries(): Promise<Inquiry[]> {
    return await this.executeWithRetry(async () => {
      return await this.db.select().from(inquiries).orderBy(desc(inquiries.createdAt));
    }, 'getInquiries');
  }

  async createInquiry(inquiry: InsertInquiry): Promise<Inquiry> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.insert(inquiries).values(inquiry).returning();
      return result[0];
    }, 'createInquiry');
  }

  async updateInquiryStatus(id: string, status: string): Promise<Inquiry> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.update(inquiries)
        .set({ status })
        .where(eq(inquiries.id, id))
        .returning();
      return result[0];
    }, 'updateInquiryStatus');
  }

  // Public tracking by tracking code (minimal data exposure)
  async getRepairByTrackingCode(trackingCode: string): Promise<{ 
    trackingCode: string;
    device: string;
    status: string;
    progress: number;
    expectedCompletion: Date | null;
  } | undefined> {
    return await this.executeWithRetry(async () => {
      const result = await this.db.select({
        trackingCode: repairs.trackingCode,
        device: repairs.device,
        status: repairs.status,
        progress: repairs.progress,
        expectedCompletion: repairs.expectedCompletion
      }).from(repairs)
        .where(eq(repairs.trackingCode, trackingCode))
        .limit(1);
      return result[0];
    }, 'getRepairByTrackingCode');
  }
}

export const storage = new DatabaseStorage();
