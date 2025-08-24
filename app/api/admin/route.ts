import { NextRequest, NextResponse } from 'next/server';
import mongoose from 'mongoose';
import winston from 'winston';
// import logger from '@/lib/services/logger';
import adminAuth from '@/lib/services/adminAuth';
import { z } from 'zod';

// Production logger setup
const logger = winston.createLogger({
  level: process.env.NODE_ENV === 'production' ? 'warn' : 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Only add console logging in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Validation schemas using Zod
const loginSchema = z.object({
  email: z.string().email('Valid email is required').toLowerCase(),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .max(100, 'Password must be less than 100 characters')
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, 'Password must contain uppercase, lowercase, and number')
});

const paginationSchema = z.object({
  page: z.coerce.number().min(1).max(1000).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  status: z.string().optional(),
  roastLevel: z.string().optional(),
  minScore: z.coerce.number().min(0).max(100).optional()
});

// Types
interface DashboardData {
  totalResumes: number;
  todayResumes: number;
  averageScore: number;
  recentResumes: TransformedResume[];
  overview: {
    totalResumes: number;
    todayResumes: number;
    averageScore: number;
    completionRate: number;
  };
  statistics: {
    statusDistribution: Record<string, number>;
    roastLevelStats: Record<string, number>;
    processedToday: number;
  };
  recentActivity: TransformedResume[];
  systemInfo: {
    serverTime: string;
    dbConnection: string;
    version: string;
    error?: string;
  };
}

interface TransformedResume {
  id: string;
  fileName: string;
  displayName?: string;
  fileSize?: number;
  fileType?: string;
  score: number;
  uploadedAt: Date | string;
  personalInfo: {
    name: string;
    email: string;
    phone: string;
    linkedin: string;
    address: string;
  };
  roastLevel: string;
  language: string;
  roastType: string;
  gender: string;
  hasEmail: boolean;
  hasPhone: boolean;
  hasLinkedIn: boolean;
  contactValidation?: any;
  wordCount: number;
  pageCount: number;
  analytics?: any;
  fullData?: any;
}

// Rate limiting using simple in-memory store (consider Redis for production)
const rateLimitStore = new Map<string, { count: number; resetTime: number }>();

function rateLimit(windowMs: number, maxRequests: number) {
  return (request: NextRequest) => {
    const clientIP = request.ip || request.headers.get('x-forwarded-for') || 'unknown';
    const key = `${clientIP}:${request.nextUrl.pathname}`;
    const now = Date.now();
    
    const record = rateLimitStore.get(key);
    
    if (!record || now > record.resetTime) {
      rateLimitStore.set(key, { count: 1, resetTime: now + windowMs });
      return false; // Not rate limited
    }
    
    if (record.count >= maxRequests) {
      return true; // Rate limited
    }
    
    record.count++;
    return false; // Not rate limited
  };
}

const adminLoginLimiter = rateLimit(15 * 60 * 1000, process.env.NODE_ENV === 'production' ? 5 : 10);
const adminDataLimiter = rateLimit(5 * 60 * 1000, process.env.NODE_ENV === 'production' ? 30 : 100);

// Helper functions
function getClientInfo(request: NextRequest) {
  return {
    ip: request.ip || request.headers.get('x-forwarded-for') || 'unknown',
    userAgent: request.headers.get('user-agent')?.substring(0, 100) || 'unknown'
  };
}

function createErrorResponse(message: string, code: string, status: number = 400) {
  return NextResponse.json({
    success: false,
    error: { message, code }
  }, { status });
}

function createSuccessResponse(data: any, status: number = 200) {
  return NextResponse.json({
    success: true,
    data
  }, { status });
}

// Transform resume data
function transformResume(resume: any): TransformedResume {
  const personalInfo = resume.extractedInfo?.personalInfo || resume.personalInfo || {};
  const fileInfo = resume.fileInfo || {};
  const analysis = resume.analysis || {};
  const preferences = resume.preferences || {};
  const contactValidation = resume.contactValidation || {};
  
  return {
    id: resume.resumeId || resume._id?.toString(),
    fileName: fileInfo.originalFileName || fileInfo.fileName || 'Unknown File',
    displayName: personalInfo.name || fileInfo.originalFileName?.replace(/\.[^/.]+$/, "") || 'Unknown',
    fileSize: fileInfo.fileSize || 0,
    fileType: fileInfo.mimeType || 'unknown',
    score: analysis.overallScore || 0,
    uploadedAt: resume.timestamps?.uploadedAt || resume.createdAt,
    
    personalInfo: {
      name: personalInfo.name || 'Not extracted',
      email: personalInfo.email || personalInfo.contactInfo?.email || 'Not found',
      phone: personalInfo.phone || personalInfo.contactInfo?.phone || 'Not found',
      linkedin: personalInfo.socialProfiles?.linkedin || personalInfo.linkedin || 'Not found',
      address: personalInfo.address?.full || personalInfo.address || 'Not found'
    },
    
    roastLevel: preferences.roastLevel || 'unknown',
    language: preferences.language || 'unknown',
    roastType: preferences.roastType || 'unknown',
    gender: preferences.gender || 'unknown',
    
    hasEmail: contactValidation.hasEmail || false,
    hasPhone: contactValidation.hasPhone || false,
    hasLinkedIn: contactValidation.hasLinkedIn || false,
    contactValidation: contactValidation,
    
    wordCount: analysis.resumeAnalytics?.wordCount || 0,
    pageCount: analysis.resumeAnalytics?.pageCount || 1,
    analytics: analysis.resumeAnalytics || {},
    
    fullData: resume
  };
}

// POST /api/admin - Admin Login
export async function POST(request: NextRequest) {
  const clientInfo = getClientInfo(request);
  
  try {
    // Rate limiting check
    if (adminLoginLimiter(request)) {
      logger.warn('Admin login rate limit exceeded', { ip: clientInfo.ip });
      return createErrorResponse(
        'Too many login attempts. Please try again later.',
        'ADMIN_LOGIN_RATE_LIMIT',
        429
      );
    }

    // Parse and validate request body
    const body = await request.json().catch(() => null);
    if (!body) {
      return createErrorResponse('Invalid JSON body', 'INVALID_JSON', 400);
    }

    const validationResult = loginSchema.safeParse(body);
    if (!validationResult.success) {
      logger.warn('Admin login validation error', {
        errors: validationResult.error.errors,
        ip: clientInfo.ip
      });
      
      return createErrorResponse(
        'Invalid input data',
        'VALIDATION_ERROR',
        400
      );
    }

    const { email, password } = validationResult.data;
    
    logger.info('Admin login attempt', {
      email: email.replace(/(.{2}).*(@.*)/, '$1***$2'),
      ip: clientInfo.ip,
      userAgent: clientInfo.userAgent
    });
    
    const result = await adminAuth.login(email, password, clientInfo.ip, clientInfo.userAgent);
    
    if (result.success) {
      logger.info('Admin login successful', {
        email: email.replace(/(.{2}).*(@.*)/, '$1***$2'),
        ip: clientInfo.ip
      });
      
      return NextResponse.json(result, { status: 200 });
    } else {
      logger.warn('Admin login failed', {
        email: email.replace(/(.{2}).*(@.*)/, '$1***$2'),
        ip: clientInfo.ip,
        reason: result.error?.message
      });
      
      return NextResponse.json(result, { status: 401 });
    }
    
  } catch (error: any) {
    logger.error('Admin login error', {
      error: error.message,
      ip: clientInfo.ip,
      stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
    });
    
    return createErrorResponse(
      'Authentication system error',
      'AUTH_SYSTEM_ERROR',
      500
    );
  }
}

// GET /api/admin - Dashboard Data & Resume List
export async function GET(request: NextRequest) {
  const clientInfo = getClientInfo(request);
  
  try {
    // Rate limiting check
    if (adminDataLimiter(request)) {
      return createErrorResponse(
        'Too many requests to admin endpoints.',
        'ADMIN_DATA_RATE_LIMIT',
        429
      );
    }

    // Check authentication
    const authResult = await checkAuth(request) as { success: boolean; response?: NextResponse; admin?: any };
    if (!authResult.success) {
      return authResult.response;
    }

    const { searchParams } = new URL(request.url);
    const action = searchParams.get('action') || 'dashboard';

    switch (action) {
      case 'dashboard':
        return await handleDashboard(request, authResult.admin);
      
      case 'resumes':
        return await handleResumesList(request, authResult.admin);
      
      case 'resume':
        const resumeId = searchParams.get('id');
        if (!resumeId) {
          return createErrorResponse('Resume ID is required', 'MISSING_RESUME_ID', 400);
        }
        return await handleResumeDetails(request, authResult.admin, resumeId);
      
      default:
        return createErrorResponse('Invalid action', 'INVALID_ACTION', 400);
    }

  } catch (error: any) {
    logger.error('Admin API error', {
      error: error.message,
      ip: clientInfo.ip,
      stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
    });
    
    return createErrorResponse(
      'Internal server error',
      'INTERNAL_ERROR',
      500
    );
  }
}

// Authentication check helper
async function checkAuth(request: NextRequest) {
  try {
    const authHeader = request.headers.get('authorization');
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        success: false,
        response: createErrorResponse(
          'Authorization header required',
          'MISSING_AUTH_HEADER',
          401
        )
      };
    }

    // Create a mock request object for adminAuth.requireAuth
    const mockReq: any = {
      headers: { authorization: authHeader },
      ip: request.ip || request.headers.get('x-forwarded-for') || 'unknown',
      get: (header: string) => request.headers.get(header.toLowerCase())
    };

    return new Promise((resolve) => {
      const mockRes: any = {
        status: (code: number) => ({
          json: (data: any) => resolve({
            success: false,
            response: NextResponse.json(data, { status: code })
          })
        })
      };

      const mockNext = () => {
        resolve({
          success: true,
          admin: mockReq.admin
        });
      };

      adminAuth.requireAuth(mockReq, mockRes, mockNext);
    });

  } catch (error: any) {
    return {
      success: false,
      response: createErrorResponse(
        'Authentication failed',
        'AUTH_ERROR',
        401
      )
    };
  }
}

// Dashboard handler
async function handleDashboard(request: NextRequest, admin: any) {
  try {
    // Verify database connection
    if (mongoose.connection.readyState !== 1) {
      logger.error('Database not connected for dashboard');
      throw new Error('Database connection not available');
    }
    
    if (!mongoose.connection.db) {
      throw new Error('Database connection not available');
    }
    const collection = mongoose.connection.db.collection('resumes');
    
    const [
      totalResumes,
      todayResumes,
      avgScoreResult,
      recentResumes
    ] = await Promise.all([
      collection.countDocuments({}),
      collection.countDocuments({
        'timestamps.uploadedAt': { 
          $gte: new Date(new Date().setHours(0, 0, 0, 0)) 
        }
      }),
      collection.aggregate([
        { 
          $match: { 
            'analysis.overallScore': { $exists: true, $ne: null, $gte: 0, $lte: 100 }
          }
        },
        { 
          $group: { 
            _id: null, 
            avgScore: { $avg: '$analysis.overallScore' },
            count: { $sum: 1 }
          }
        }
      ]).toArray(),
      collection.find({})
        .sort({ 'timestamps.uploadedAt': -1 })
        .limit(10)
        .toArray()
    ]);
    
    const averageScore = avgScoreResult.length > 0 && avgScoreResult[0] 
      ? Math.round(avgScoreResult[0].avgScore * 10) / 10 
      : 0;
    
    const transformedRecentResumes = recentResumes.map(transformResume);
    
    const dashboardData: DashboardData = {
      totalResumes,
      todayResumes,
      averageScore,
      recentResumes: transformedRecentResumes,
      
      overview: {
        totalResumes,
        todayResumes,
        averageScore,
        completionRate: totalResumes > 0 ? Math.round((recentResumes.length / totalResumes) * 100) : 0
      },
      
      statistics: {
        statusDistribution: { completed: recentResumes.length },
        roastLevelStats: {},
        processedToday: todayResumes
      },
      
      recentActivity: transformedRecentResumes,
      
      systemInfo: {
        serverTime: new Date().toISOString(),
        dbConnection: 'healthy',
        version: process.env.npm_package_version || '1.0.0'
      }
    };
    
    logger.info('Dashboard data generated successfully', {
      admin: admin?.email,
      totalResumes,
      averageScore,
      recentCount: transformedRecentResumes.length
    });
    
    return createSuccessResponse(dashboardData);
    
  } catch (error: any) {
    logger.error('Dashboard data error', {
      error: error.message,
      admin: admin?.email,
      stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
    });
    
    // Return fallback data instead of error
    const fallbackData: DashboardData = {
      totalResumes: 0,
      todayResumes: 0,
      averageScore: 0,
      recentResumes: [],
      overview: {
        totalResumes: 0,
        todayResumes: 0,
        averageScore: 0,
        completionRate: 0
      },
      statistics: {
        statusDistribution: {},
        roastLevelStats: {},
        processedToday: 0
      },
      recentActivity: [],
      systemInfo: {
        serverTime: new Date().toISOString(),
        dbConnection: 'error',
        version: process.env.npm_package_version || '1.0.0',
        error: 'Failed to load dashboard data'
      }
    };
    
    return createSuccessResponse(fallbackData);
  }
}

// Resumes list handler
async function handleResumesList(request: NextRequest, admin: any) {
  const { searchParams } = new URL(request.url);
  
  const validationResult = paginationSchema.safeParse({
    page: searchParams.get('page'),
    limit: searchParams.get('limit'),
    status: searchParams.get('status'),
    roastLevel: searchParams.get('roastLevel'),
    minScore: searchParams.get('minScore')
  });
  
  if (!validationResult.success) {
    return createErrorResponse('Invalid pagination parameters', 'VALIDATION_ERROR', 400);
  }
  
  const { page, limit, status, roastLevel, minScore } = validationResult.data;
  const skip = (page - 1) * limit;
  
  const filters: any = {};
  if (status) filters['processingStatus.current'] = status;
  if (roastLevel) filters['preferences.roastLevel'] = roastLevel;
  if (minScore) filters['analysis.overallScore'] = { $gte: minScore };
  
  try {
    const collection = mongoose.connection.db.collection('resumes');
    
    const [totalCount, resumes] = await Promise.all([
      collection.countDocuments(filters),
      collection.find(filters)
        .sort({ 'timestamps.uploadedAt': -1 })
        .skip(skip)
        .limit(limit)
        .toArray()
    ]);
    
    const transformedResumes = resumes.map(transformResume);
    const totalPages = Math.ceil(totalCount / limit);
    
    return createSuccessResponse({
      resumes: transformedResumes,
      pagination: {
        totalCount,
        currentPage: page,
        totalPages,
        pageSize: limit,
        hasNextPage: page < totalPages,
        hasPrevPage: page > 1
      }
    });
    
  } catch (error: any) {
    logger.error('Resumes list error', {
      error: error.message,
      admin: admin?.email,
      stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
    });
    
    return createErrorResponse(
      'Failed to fetch resumes',
      'RESUMES_FETCH_ERROR',
      500
    );
  }
}

// Resume details handler
async function handleResumeDetails(request: NextRequest, admin: any, resumeId: string) {
  // Validate resume ID format
  if (!resumeId || resumeId.length < 8 || !/^[a-fA-F0-9\-]{8,}$/.test(resumeId)) {
    return createErrorResponse('Invalid resume ID format', 'INVALID_RESUME_ID', 400);
  }
  
  try {
    const collection = mongoose.connection.db.collection('resumes');
    
    let resume = await collection.findOne({ resumeId });
    
    if (!resume && mongoose.Types.ObjectId.isValid(resumeId)) {
      resume = await collection.findOne({ _id: new mongoose.Types.ObjectId(resumeId) });
    }
    
    if (!resume) {
      return createErrorResponse(
        'Resume not found',
        'RESUME_NOT_FOUND',
        404
      );
    }
    
    // Include full data with proper personal info
    const fullResumeData = {
      ...resume,
      personalInfo: resume.extractedInfo?.personalInfo || resume.personalInfo || {},
      securityInfo: {
        countryCode: resume.securityInfo?.countryCode,
        sessionId: resume.securityInfo?.sessionId?.substring(0, 8) + '...',
        clientIPHash: resume.securityInfo?.clientIPHash ? '[HASHED]' : null,
        userAgentHash: resume.securityInfo?.userAgentHash ? '[HASHED]' : null
      }
    };
    
    return createSuccessResponse(fullResumeData);
    
  } catch (error: any) {
    logger.error('Resume details error', {
      error: error.message,
      requestedId: resumeId,
      admin: admin?.email,
      stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
    });
    
    return createErrorResponse(
      'Failed to fetch resume details',
      'RESUME_DETAILS_ERROR',
      500
    );
  }
}