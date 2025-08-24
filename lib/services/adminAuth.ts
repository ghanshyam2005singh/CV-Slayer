import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose, { Document, Schema } from 'mongoose';
import crypto from 'crypto';
import winston from 'winston';
import { Request, Response, NextFunction } from 'express';

// Production logger setup
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'warn' : 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/admin-auth.log' }),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' })
  ]
});

// Only add console logging in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Type definitions
interface AdminSession {
  sessionId: string;
  createdAt: Date;
  expiresAt: Date;
  ipAddress: string;
  userAgent: string;
}

interface IAdmin extends Document {
  email: string;
  password: string;
  role: 'admin' | 'super_admin';
  isActive: boolean;
  lastLogin?: Date;
  loginAttempts: number;
  lockUntil?: Date;
  passwordChangedAt: Date;
  sessions: AdminSession[];
  createdAt: Date;
  updatedAt: Date;
  cleanExpiredSessions(): Promise<IAdmin>;
}

interface LoginRequest {
  email?: string;
  password?: string;
  ipAddress?: string;
  userAgent?: string;
}

interface LoginResult {
  success: boolean;
  token?: string;
  expiresIn?: number;
  message?: string;
  user?: {
    id?: string;
    email: string;
    role: string;
    authMethod: 'environment' | 'database';
    lastLogin?: Date;
    sessionId: string;
  };
  loginTime?: string;
  error?: {
    message: string;
    code: string;
  };
}

interface LogoutResult {
  success: boolean;
  message?: string;
  error?: string;
}

interface CreateAdminResult {
  success: boolean;
  message?: string;
  admin?: {
    id: string;
    email: string;
    role: string;
    isActive: boolean;
    createdAt: Date;
  };
  error?: {
    message: string;
    code: string;
  };
}

interface ChangePasswordResult {
  success: boolean;
  message?: string;
  error?: {
    message: string;
    code: string;
  };
}

interface DeactivateAdminResult {
  success: boolean;
  message?: string;
  error?: string;
}

interface GetAllAdminsResult {
  success: boolean;
  admins?: Array<{
    id: string;
    email: string;
    role: string;
    isActive: boolean;
    lastLogin?: Date;
    createdAt: Date;
    activeSessions: number;
  }>;
  error?: string;
}

interface HealthCheckResult {
  healthy: boolean;
  timestamp: string;
  envAuth?: {
    configured: boolean;
    emailCount: number;
    hasPassword: boolean;
  };
  mongoAuth?: {
    connected: boolean;
    activeAdmins: number;
    hasAdmins: boolean;
    activeSessions: number;
  };
  jwt?: {
    configured: boolean;
    expiry: string;
    secretLength: number;
  };
  security?: {
    maxLoginAttempts: number;
    lockoutTimeMinutes: number;
    maxConcurrentSessions: number;
  };
  error?: string;
}

interface JWTPayload {
  adminId?: string;
  email: string;
  role: string;
  loginTime: string;
  authMethod: 'env' | 'mongodb';
  sessionId: string;
  ipAddress: string;
  iat: number;
}

interface AuthenticatedRequest extends Request {
  admin?: {
    id: string;
    email: string;
    role: string;
    authMethod: string;
    sessionId: string;
    loginTime: string;
    ipAddress: string;
  };
}

// Admin schema for MongoDB with enhanced security
const adminSchema = new Schema<IAdmin>({
  email: { 
    type: String, 
    required: true, 
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email format']
  },
  password: { 
    type: String, 
    required: true,
    minlength: 8
  },
  role: { 
    type: String, 
    default: 'admin',
    enum: ['admin', 'super_admin']
  },
  isActive: {
    type: Boolean,
    default: true
  },
  lastLogin: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0,
    max: 10
  },
  lockUntil: {
    type: Date,
    default: null
  },
  passwordChangedAt: {
    type: Date,
    default: Date.now
  },
  sessions: [{
    sessionId: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date,
    ipAddress: String,
    userAgent: String
  }],
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Indexes for better performance and security
adminSchema.index({ isActive: 1 });
adminSchema.index({ lockUntil: 1 });
adminSchema.index({ 'sessions.sessionId': 1 });
adminSchema.index({ 'sessions.expiresAt': 1 });

// Middleware to update updatedAt field
adminSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

// Method to clean expired sessions
adminSchema.methods.cleanExpiredSessions = function(): Promise<IAdmin> {
  this.sessions = this.sessions.filter((session: AdminSession) => session.expiresAt > new Date());
  return this.save();
};

const Admin = mongoose.model<IAdmin>('Admin', adminSchema);

class AdminAuth {
  private adminEmails: string[];
  private adminPassword?: string;
  private jwtSecret: string;
  private tokenExpiry: string;
  private maxLoginAttempts: number;
  private lockoutTime: number;
  private maxSessions: number;

  constructor() {
    // Environment variables validation
    this.validateEnvironment();
    
    this.adminEmails = this.parseAdminEmails(process.env.ADMIN_EMAILS);
    this.adminPassword = process.env.ADMIN_PASSWORD;
    this.jwtSecret = process.env.JWT_SECRET!;
    this.tokenExpiry = process.env.JWT_EXPIRY || '24h';
    this.maxLoginAttempts = parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5');
    this.lockoutTime = parseInt(process.env.LOCKOUT_TIME || '900000'); // 15 minutes
    this.maxSessions = parseInt(process.env.MAX_CONCURRENT_SESSIONS || '5');
    
    // BIND METHODS TO PRESERVE 'this' CONTEXT
    this.requireAuth = this.requireAuth.bind(this);
    this.login = this.login.bind(this);
    this.logout = this.logout.bind(this);
    this.checkHealth = this.checkHealth.bind(this);
    this.createAdmin = this.createAdmin.bind(this);
    this.changePassword = this.changePassword.bind(this);
    this.deactivateAdmin = this.deactivateAdmin.bind(this);
    this.getAllAdmins = this.getAllAdmins.bind(this);
    this.cleanupExpiredSessions = this.cleanupExpiredSessions.bind(this);
    
    // Start cleanup interval for expired sessions
    this.startSessionCleanup();
  }

  private validateEnvironment(): void {
    const missingVars: string[] = [];
    
    if (!process.env.JWT_SECRET) {
      missingVars.push('JWT_SECRET');
    }
    
    if (!process.env.ADMIN_EMAILS && !process.env.ADMIN_PASSWORD) {
      logger.warn('No admin credentials configured. Please set ADMIN_EMAILS and ADMIN_PASSWORD');
    }
    
    if (missingVars.length > 0) {
      const error = `Missing required environment variables: ${missingVars.join(', ')}`;
      logger.error('Environment validation failed', { missingVars });
      throw new Error(error);
    }
    
    // Validate JWT secret strength
    if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
      logger.warn('JWT_SECRET should be at least 32 characters long for security');
    }
    
    logger.info('Environment validation completed successfully');
  }

  private parseAdminEmails(emailString?: string): string[] {
    if (!emailString) {
      logger.warn('No ADMIN_EMAILS configured. Admin access will rely on database only.');
      return [];
    }
    
    const emails = emailString
      .split(',')
      .map(email => email.trim().toLowerCase())
      .filter(email => {
        // Enhanced email validation
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        const isValid = emailRegex.test(email) && email.length <= 254;
        if (!isValid) {
          logger.warn('Invalid email format detected', { email: email.substring(0, 5) + '***' });
        }
        return isValid;
      });
    
    if (emails.length === 0) {
      logger.warn('No valid emails found in ADMIN_EMAILS');
    } else {
      logger.info('Admin emails configured successfully', { count: emails.length });
    }
    
    return emails;
  }

  async login(
    email?: string,
    password?: string,
    ipAddress: string = 'unknown',
    userAgent: string = 'unknown'
  ): Promise<LoginResult> {
    const loginStartTime = Date.now();
    const sessionId = crypto.randomUUID();
    
    try {
      const normalizedEmail = email?.toLowerCase()?.trim();
      
      // Basic validation
      if (!email || !password) {
        logger.warn('Login attempt with missing credentials', { 
          ip: ipAddress,
          hasEmail: !!email,
          hasPassword: !!password
        });
        return {
          success: false,
          error: { 
            message: 'Email and password are required',
            code: 'MISSING_CREDENTIALS'
          }
        };
      }

      // Email format validation
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!normalizedEmail || !emailRegex.test(normalizedEmail) || normalizedEmail.length > 254) {
        logger.warn('Login attempt with invalid email format', { 
          ip: ipAddress,
          email: normalizedEmail?.substring(0, 5) + '***'
        });
        return {
          success: false,
          error: { 
            message: 'Invalid email format',
            code: 'INVALID_EMAIL'
          }
        };
      }

      // Password length validation
      if (password.length < 8 || password.length > 128) {
        logger.warn('Login attempt with invalid password length', { 
          ip: ipAddress,
          email: normalizedEmail.substring(0, 5) + '***',
          passwordLength: password.length
        });
        return {
          success: false,
          error: { 
            message: 'Invalid credentials',
            code: 'INVALID_CREDENTIALS'
          }
        };
      }

      // Environment variable authentication (if configured)
      if (this.adminEmails.length > 0 && this.adminPassword) {
        if (this.adminEmails.includes(normalizedEmail) && password === this.adminPassword) {
          const tokenPayload: JWTPayload = {
            email: normalizedEmail,
            role: 'admin',
            loginTime: new Date().toISOString(),
            authMethod: 'env',
            sessionId: sessionId,
            ipAddress: ipAddress,
            iat: Math.floor(Date.now() / 1000)
          };

          const accessToken = jwt.sign(tokenPayload, this.jwtSecret, { 
            expiresIn: this.tokenExpiry,
            issuer: 'cv-slayer-api',
            audience: 'cv-slayer-admin',
            subject: normalizedEmail
          });

          const expiresInSeconds = this.parseTokenExpiry(this.tokenExpiry);
          const loginDuration = Date.now() - loginStartTime;

          logger.info('Environment admin login successful', {
            email: normalizedEmail.substring(0, 5) + '***',
            ip: ipAddress,
            sessionId: sessionId.substring(0, 8) + '...',
            loginDuration
          });

          return {
            success: true,
            token: accessToken,
            expiresIn: expiresInSeconds,
            message: 'Login successful',
            user: {
              email: normalizedEmail,
              role: 'admin',
              authMethod: 'environment',
              sessionId: sessionId
            },
            loginTime: tokenPayload.loginTime
          };
        }
      }

      // MongoDB authentication (with enhanced security)
      try {
        if (mongoose.connection.readyState === 1) {
          const admin = await Admin.findOne({ 
            email: normalizedEmail,
            isActive: true
          }).maxTimeMS(5000);
          
          if (!admin) {
            logger.warn('Login attempt for non-existent admin', { 
              ip: ipAddress,
              email: normalizedEmail.substring(0, 5) + '***'
            });
            // Return same error as invalid password to prevent email enumeration
            return {
              success: false,
              error: { 
                message: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
              }
            };
          }

          // Check if account is locked
          if (admin.lockUntil && admin.lockUntil > new Date()) {
            const remainingTime = Math.ceil((admin.lockUntil.getTime() - Date.now()) / 1000 / 60);
            logger.warn('Login attempt on locked account', { 
              ip: ipAddress,
              email: normalizedEmail.substring(0, 5) + '***',
              remainingTime
            });
            return {
              success: false,
              error: { 
                message: `Account locked. Try again in ${remainingTime} minutes`,
                code: 'ACCOUNT_LOCKED'
              }
            };
          }

          // Verify password with timing-safe comparison
          const isPasswordValid = await bcrypt.compare(password, admin.password);
          
          if (!isPasswordValid) {
            // Increment login attempts
            admin.loginAttempts += 1;
            
            if (admin.loginAttempts >= this.maxLoginAttempts) {
              admin.lockUntil = new Date(Date.now() + this.lockoutTime);
              admin.loginAttempts = 0;
              logger.warn('Account locked due to too many failed attempts', { 
                ip: ipAddress,
                email: normalizedEmail.substring(0, 5) + '***',
                attempts: admin.loginAttempts
              });
            }
            
            await admin.save();
            
            logger.warn('Failed login attempt', { 
              ip: ipAddress,
              email: normalizedEmail.substring(0, 5) + '***',
              attempts: admin.loginAttempts
            });
            
            return {
              success: false,
              error: { 
                message: 'Invalid credentials',
                code: 'INVALID_CREDENTIALS'
              }
            };
          }

          // Clean expired sessions before adding new one
          await admin.cleanExpiredSessions();
          
          // Check max concurrent sessions
          if (admin.sessions.length >= this.maxSessions) {
            // Remove oldest session
            admin.sessions.sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime());
            admin.sessions.shift();
            logger.info('Removed oldest session due to max sessions limit', {
              email: normalizedEmail.substring(0, 5) + '***',
              maxSessions: this.maxSessions
            });
          }

          // Successful login - reset attempts and update last login
          admin.loginAttempts = 0;
          admin.lockUntil = undefined;
          admin.lastLogin = new Date();
          
          // Add new session
          const expiresAt = new Date(Date.now() + (this.parseTokenExpiry(this.tokenExpiry) * 1000));
          admin.sessions.push({
            sessionId: sessionId,
            createdAt: new Date(),
            expiresAt: expiresAt,
            ipAddress: ipAddress,
            userAgent: userAgent.substring(0, 200) // Limit user agent length
          });
          
          await admin.save();

          const tokenPayload: JWTPayload = {
            adminId: admin._id.toString(),
            email: normalizedEmail,
            role: admin.role,
            loginTime: new Date().toISOString(),
            authMethod: 'mongodb',
            sessionId: sessionId,
            ipAddress: ipAddress,
            iat: Math.floor(Date.now() / 1000)
          };

          const accessToken = jwt.sign(tokenPayload, this.jwtSecret, { 
            expiresIn: this.tokenExpiry,
            issuer: 'cv-slayer-api',
            audience: 'cv-slayer-admin',
            subject: admin._id.toString()
          });

          const expiresInSeconds = this.parseTokenExpiry(this.tokenExpiry);
          const loginDuration = Date.now() - loginStartTime;

          logger.info('Database admin login successful', {
            adminId: admin._id.toString(),
            email: normalizedEmail.substring(0, 5) + '***',
            ip: ipAddress,
            sessionId: sessionId.substring(0, 8) + '...',
            loginDuration,
            role: admin.role
          });

          return {
            success: true,
            token: accessToken,
            expiresIn: expiresInSeconds,
            message: 'Login successful',
            user: {
              id: admin._id.toString(),
              email: normalizedEmail,
              role: admin.role,
              authMethod: 'database',
              lastLogin: admin.lastLogin,
              sessionId: sessionId
            },
            loginTime: tokenPayload.loginTime
          };
        }
      } catch (mongoError: any) {
        logger.error('MongoDB authentication error', {
          error: mongoError.message,
          ip: ipAddress,
          email: normalizedEmail.substring(0, 5) + '***'
        });
        
        // If MongoDB is down but env auth is available, don't fail completely
        if (this.adminEmails.length === 0) {
          return {
            success: false,
            error: { 
              message: 'Authentication service temporarily unavailable',
              code: 'SERVICE_UNAVAILABLE'
            }
          };
        }
      }

      logger.warn('Authentication failed - no valid auth method', { 
        ip: ipAddress,
        email: normalizedEmail.substring(0, 5) + '***'
      });

      return {
        success: false,
        error: { 
          message: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        }
      };

    } catch (error: any) {
      const loginDuration = Date.now() - loginStartTime;
      logger.error('Login error', {
        error: error.message,
        ip: ipAddress,
        loginDuration,
        stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
      });
      
      return {
        success: false,
        error: { 
          message: 'Authentication failed',
          code: 'AUTH_ERROR'
        }
      };
    }
  }

  async logout(sessionId?: string, adminId?: string): Promise<LogoutResult> {
    try {
      if (!sessionId) {
        return {
          success: false,
          error: 'Session ID required for logout'
        };
      }

      // For database admins, remove session from database
      if (adminId && mongoose.connection.readyState === 1) {
        const admin = await Admin.findById(adminId);
        if (admin) {
          admin.sessions = admin.sessions.filter(session => session.sessionId !== sessionId);
          await admin.save();
          
          logger.info('Session removed from database', {
            adminId: adminId,
            sessionId: sessionId.substring(0, 8) + '...'
          });
        }
      }

      logger.info('Admin logout successful', {
        sessionId: sessionId.substring(0, 8) + '...',
        adminId: adminId || 'env-admin'
      });

      return {
        success: true,
        message: 'Logout successful'
      };

    } catch (error: any) {
      logger.error('Logout error', {
        error: error.message,
        sessionId: sessionId?.substring(0, 8) + '...',
        adminId: adminId
      });
      
      return {
        success: false,
        error: 'Logout failed'
      };
    }
  }

  async createAdmin(
    email?: string,
    password?: string,
    role: 'admin' | 'super_admin' = 'admin',
    createdBy: string = 'system'
  ): Promise<CreateAdminResult> {
    try {
      const normalizedEmail = email?.toLowerCase()?.trim();
      
      // Validation
      if (!email || !password) {
        return {
          success: false,
          error: { 
            message: 'Email and password are required',
            code: 'MISSING_FIELDS'
          }
        };
      }

      // Email validation
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!normalizedEmail || !emailRegex.test(normalizedEmail) || normalizedEmail.length > 254) {
        return {
          success: false,
          error: { 
            message: 'Invalid email format',
            code: 'INVALID_EMAIL'
          }
        };
      }

      // Password validation
      if (password.length < 8 || password.length > 128) {
        return {
          success: false,
          error: { 
            message: 'Password must be between 8-128 characters long',
            code: 'INVALID_PASSWORD'
          }
        };
      }

      // Role validation
      if (!['admin', 'super_admin'].includes(role)) {
        return {
          success: false,
          error: { 
            message: 'Invalid role specified',
            code: 'INVALID_ROLE'
          }
        };
      }

      // Check if admin already exists
      const existingAdmin = await Admin.findOne({ email: normalizedEmail });
      if (existingAdmin) {
        logger.warn('Attempt to create duplicate admin', {
          email: normalizedEmail.substring(0, 5) + '***',
          createdBy
        });
        return {
          success: false,
          error: { 
            message: 'Admin with this email already exists',
            code: 'ADMIN_EXISTS'
          }
        };
      }

      // Hash password with high cost factor
      const saltRounds = 12;
      const hashedPassword = await bcrypt.hash(password, saltRounds);

      // Create admin
      const admin = new Admin({
        email: normalizedEmail,
        password: hashedPassword,
        role: role,
        isActive: true,
        passwordChangedAt: new Date()
      });

      await admin.save();

      logger.info('Admin created successfully', {
        adminId: admin._id.toString(),
        email: normalizedEmail.substring(0, 5) + '***',
        role: admin.role,
        createdBy
      });

      return {
        success: true,
        message: 'Admin created successfully',
        admin: {
          id: admin._id.toString(),
          email: admin.email,
          role: admin.role,
          isActive: admin.isActive,
          createdAt: admin.createdAt
        }
      };

    } catch (error: any) {
      logger.error('Create admin error', {
        error: error.message,
        email: email?.substring(0, 5) + '***',
        stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
      });
      
      return {
        success: false,
        error: { 
          message: 'Failed to create admin',
          code: 'CREATE_ERROR'
        }
      };
    }
  }

  async changePassword(
    adminId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<ChangePasswordResult> {
    try {
      if (!currentPassword || !newPassword) {
        return {
          success: false,
          error: { 
            message: 'Current and new passwords are required',
            code: 'MISSING_PASSWORDS'
          }
        };
      }

      if (newPassword.length < 8 || newPassword.length > 128) {
        return {
          success: false,
          error: { 
            message: 'New password must be between 8-128 characters long',
            code: 'INVALID_PASSWORD'
          }
        };
      }

      // Check password complexity
      const hasUpperCase = /[A-Z]/.test(newPassword);
      const hasLowerCase = /[a-z]/.test(newPassword);
      const hasNumbers = /\d/.test(newPassword);

      if (!hasUpperCase || !hasLowerCase || !hasNumbers) {
        return {
          success: false,
          error: { 
            message: 'Password must contain uppercase, lowercase, and numbers',
            code: 'WEAK_PASSWORD'
          }
        };
      }

      const admin = await Admin.findById(adminId);
      if (!admin || !admin.isActive) {
        return {
          success: false,
          error: { 
            message: 'Admin not found',
            code: 'ADMIN_NOT_FOUND'
          }
        };
      }

      // Verify current password
      const isCurrentPasswordValid = await bcrypt.compare(currentPassword, admin.password);
      if (!isCurrentPasswordValid) {
        logger.warn('Invalid current password in change attempt', {
          adminId: adminId,
          email: admin.email.substring(0, 5) + '***'
        });
        return {
          success: false,
          error: { 
            message: 'Current password is incorrect',
            code: 'INVALID_CURRENT_PASSWORD'
          }
        };
      }

      // Check if new password is different from current
      const isSamePassword = await bcrypt.compare(newPassword, admin.password);
      if (isSamePassword) {
        return {
          success: false,
          error: { 
            message: 'New password must be different from current password',
            code: 'SAME_PASSWORD'
          }
        };
      }

      // Hash new password
      const saltRounds = 12;
      const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

      // Update password and invalidate all sessions
      admin.password = hashedNewPassword;
      admin.passwordChangedAt = new Date();
      admin.sessions = []; // Clear all sessions to force re-login
      await admin.save();

      logger.info('Password changed successfully', {
        adminId: adminId,
        email: admin.email.substring(0, 5) + '***'
      });

      return {
        success: true,
        message: 'Password changed successfully. Please log in again.'
      };

    } catch (error: any) {
      logger.error('Change password error', {
        error: error.message,
        adminId: adminId,
        stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
      });
      
      return {
        success: false,
        error: { 
          message: 'Failed to change password',
          code: 'CHANGE_PASSWORD_ERROR'
        }
      };
    }
  }

  async deactivateAdmin(adminId: string, deactivatedBy: string = 'system'): Promise<DeactivateAdminResult> {
    try {
      const admin = await Admin.findById(adminId);
      if (!admin) {
        return {
          success: false,
          error: 'Admin not found'
        };
      }

      admin.isActive = false;
      admin.sessions = []; // Clear all sessions
      await admin.save();

      logger.info('Admin deactivated', {
        adminId: adminId,
        email: admin.email.substring(0, 5) + '***',
        deactivatedBy
      });

      return {
        success: true,
        message: 'Admin deactivated successfully'
      };

    } catch (error: any) {
      logger.error('Deactivate admin error', {
        error: error.message,
        adminId: adminId
      });
      
      return {
        success: false,
        error: 'Failed to deactivate admin'
      };
    }
  }

  async getAllAdmins(requestedBy: string = 'system'): Promise<GetAllAdminsResult> {
    try {
      const admins = await Admin.find(
        {},
        {
          email: 1,
          role: 1,
          isActive: 1,
          lastLogin: 1,
          createdAt: 1,
          sessions: 1
        }
      ).sort({ createdAt: -1 });

      const adminData = admins.map(admin => ({
        id: admin._id.toString(),
        email: admin.email,
        role: admin.role,
        isActive: admin.isActive,
        lastLogin: admin.lastLogin,
        createdAt: admin.createdAt,
        activeSessions: admin.sessions.filter(session => session.expiresAt > new Date()).length
      }));

      logger.info('Admin list retrieved', {
        requestedBy,
        count: adminData.length
      });

      return {
        success: true,
        admins: adminData
      };

    } catch (error: any) {
      logger.error('Get all admins error', {
        error: error.message,
        requestedBy
      });
      
      return {
        success: false,
        error: 'Failed to retrieve admin list'
      };
    }
  }

  private parseTokenExpiry(expiry: string): number {
    const timeUnit = expiry.slice(-1);
    const timeValue = parseInt(expiry.slice(0, -1));
    
    switch (timeUnit) {
      case 'h': return timeValue * 3600;
      case 'm': return timeValue * 60;
      case 'd': return timeValue * 86400;
      case 's': return timeValue;
      default: return 86400; // 24 hours default
    }
  }

  requireAuth(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          success: false,
          error: { 
            message: 'Authorization header required',
            code: 'MISSING_AUTH_HEADER'
          }
        });
        return;
      }

      const token = authHeader.replace('Bearer ', '');

      if (!token) {
        res.status(401).json({
          success: false,
          error: { 
            message: 'Access token required',
            code: 'MISSING_TOKEN'
          }
        });
        return;
      }

      // Verify JWT token
      const decoded = jwt.verify(token, this.jwtSecret, {
        issuer: 'cv-slayer-api',
        audience: 'cv-slayer-admin'
      }) as JWTPayload;
      
      if (decoded.role !== 'admin' && decoded.role !== 'super_admin') {
        logger.warn('Insufficient permissions attempt', {
          email: decoded.email?.substring(0, 5) + '***',
          role: decoded.role,
          ip: req.ip
        });
        
        res.status(403).json({
          success: false,
          error: { 
            message: 'Admin access required',
            code: 'INSUFFICIENT_PERMISSIONS'
          }
        });
        return;
      }

      // For database admins, verify session is still valid
      if (decoded.authMethod === 'mongodb' && decoded.sessionId) {
        setImmediate(async () => {
          try {
            const admin = await Admin.findById(decoded.adminId);
            if (admin && admin.isActive) {
              const session = admin.sessions.find(s => s.sessionId === decoded.sessionId);
              if (!session || session.expiresAt <= new Date()) {
                logger.warn('Invalid or expired session detected', {
                  adminId: decoded.adminId,
                  sessionId: decoded.sessionId?.substring(0, 8) + '...'
                });
              }
            }
          } catch (error: any) {
            logger.error('Session validation error', { error: error.message });
          }
        });
      }

      // Set admin info in request
      req.admin = {
        id: decoded.adminId || 'env-admin',
        email: decoded.email,
        role: decoded.role,
        authMethod: decoded.authMethod || 'env',
        sessionId: decoded.sessionId,
        loginTime: decoded.loginTime,
        ipAddress: decoded.ipAddress
      };

      next();

    } catch (error: any) {
      let errorMessage = 'Invalid or expired token';
      let errorCode = 'INVALID_TOKEN';

      if (error.name === 'TokenExpiredError') {
        errorMessage = 'Session expired. Please log in again.';
        errorCode = 'TOKEN_EXPIRED';
      } else if (error.name === 'JsonWebTokenError') {
        errorMessage = 'Invalid token format';
        errorCode = 'MALFORMED_TOKEN';
      } else if (error.name === 'NotBeforeError') {
        errorMessage = 'Token not active yet';
        errorCode = 'TOKEN_NOT_ACTIVE';
      }

      logger.warn('Authentication failed', {
        error: errorMessage,
        ip: req.ip,
        userAgent: req.get('User-Agent')?.substring(0, 100)
      });

      res.status(401).json({
        success: false,
        error: { 
          message: errorMessage,
          code: errorCode
        }
      });
    }
  }

  private async cleanupExpiredSessions(): Promise<void> {
    try {
      if (mongoose.connection.readyState === 1) {
        const result = await Admin.updateMany(
          {},
          {
            $pull: {
              sessions: {
                expiresAt: { $lte: new Date() }
              }
            }
          }
        );

        if (result.modifiedCount > 0) {
          logger.info('Expired sessions cleaned up', {
            modifiedAdmins: result.modifiedCount
          });
        }
      }
    } catch (error: any) {
      logger.error('Session cleanup error', { error: error.message });
    }
  }

  private startSessionCleanup(): void {
    // Clean up expired sessions every hour
    setInterval(() => {
      this.cleanupExpiredSessions();
    }, 60 * 60 * 1000);
    
    logger.info('Session cleanup interval started');
  }

  async checkHealth(): Promise<HealthCheckResult> {
    try {
      let mongoAdminCount = 0;
      let mongoConnected = false;
      let activeSessions = 0;
      
      try {
        if (mongoose.connection.readyState === 1) {
          mongoConnected = true;
          mongoAdminCount = await Admin.countDocuments({ isActive: true }).maxTimeMS(3000);
          
          // Count active sessions
          const admins = await Admin.find({}, { sessions: 1 }).maxTimeMS(3000);
          activeSessions = admins.reduce((total, admin) => {
            return total + admin.sessions.filter(session => session.expiresAt > new Date()).length;
          }, 0);
        }
      } catch (mongoError: any) {
        logger.warn('MongoDB health check failed', { error: mongoError.message });
      }
      
      const healthData: HealthCheckResult = {
        healthy: true,
        timestamp: new Date().toISOString(),
        envAuth: {
          configured: this.adminEmails.length > 0 && !!this.adminPassword,
          emailCount: this.adminEmails.length,
          hasPassword: !!this.adminPassword
        },
        mongoAuth: {
          connected: mongoConnected,
          activeAdmins: mongoAdminCount,
          hasAdmins: mongoAdminCount > 0,
          activeSessions: activeSessions
        },
        jwt: {
          configured: !!this.jwtSecret,
          expiry: this.tokenExpiry,
          secretLength: this.jwtSecret ? this.jwtSecret.length : 0
        },
        security: {
          maxLoginAttempts: this.maxLoginAttempts,
          lockoutTimeMinutes: this.lockoutTime / 1000 / 60,
          maxConcurrentSessions: this.maxSessions
        }
      };
      
      logger.info('Health check completed', {
        mongoConnected,
        activeAdmins: mongoAdminCount,
        activeSessions
      });
      
      return healthData;
    } catch (error: any) {
      logger.error('Health check error', { error: error.message });
      return {
        healthy: false,
        error: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }
}

// Create and export singleton instance
const adminAuth = new AdminAuth();

export default adminAuth;
export { AdminAuth, type AuthenticatedRequest };