import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import { connectDB } from '@/lib/config/database';
import fileProcessor from '@/lib/services/fileProcessor';
import geminiService from '@/lib/services/geminiService';
import { saveResumeData } from '@/lib/services/resumeStorage';
import logger from '@/lib/services/logger';

// Rate limiting store (use Redis in production)
interface RateLimitEntry {
  count: number;
  resetTime: number;
}

const rateLimitStore = new Map<string, RateLimitEntry>();

// Security headers
function setSecurityHeaders(response: NextResponse): string {
  const requestId = crypto.randomUUID();
  
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  response.headers.set('Pragma', 'no-cache');
  response.headers.set('Expires', '0');
  response.headers.set('X-Request-ID', requestId);
  
  if (process.env.NODE_ENV === 'production') {
    response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  
  return requestId;
}

// Rate limiting check
function checkRateLimit(clientIP: string): boolean {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes
  const maxRequests = 3;
  
  const entry = rateLimitStore.get(clientIP);
  
  if (!entry) {
    rateLimitStore.set(clientIP, { count: 1, resetTime: now + windowMs });
    return true;
  }
  
  if (now > entry.resetTime) {
    rateLimitStore.set(clientIP, { count: 1, resetTime: now + windowMs });
    return true;
  }
  
  if (entry.count >= maxRequests) {
    return false;
  }
  
  entry.count++;
  return true;
}

// Parse multipart form data
async function parseFormData(request: NextRequest) {
  const formData = await request.formData();
  
  const file = formData.get('resume') as File;
  const gender = formData.get('gender') as string;
  const roastLevel = formData.get('roastLevel') as string;
  const roastType = formData.get('roastType') as string;
  const language = formData.get('language') as string;
  
  if (!file) {
    throw new Error('No file uploaded');
  }

  if (file.size > 5 * 1024 * 1024) {
  throw new Error('FILE_TOO_LARGE');
}
  
  const buffer = Buffer.from(await file.arrayBuffer());
  
  const fileUpload = {
    originalname: file.name,
    mimetype: file.type,
    size: file.size,
    buffer,
  };
  
  const preferences = {
    gender: gender?.toLowerCase() || 'other',
    roastLevel: roastLevel?.toLowerCase() || 'ache',
    roastType: roastType?.toLowerCase() || 'serious',
    language: language?.toLowerCase() || 'english',
  };
  
  return { file: fileUpload, preferences };
}

// POST /api/resume/analyze
export async function POST(req: NextRequest) {
  const startTime = Date.now();
  let requestId: string = '';
  
  try {
    // Connect to database
    await connectDB();
    
    // Get client IP
    const clientIP = req.headers.get('x-forwarded-for') || 
                     req.headers.get('x-real-ip') || 
                     req.ip || 
                     'unknown';
    
    // Check rate limit
    if (!checkRateLimit(clientIP)) {
      const response = NextResponse.json(
        {
          success: false,
          error: {
            message: 'Too many resume analysis requests. Please try again in 15 minutes.',
            status: 429,
            code: 'RATE_LIMIT_EXCEEDED',
            retryAfter: 900,
          },
        },
        { status: 429 }
      );
      setSecurityHeaders(response);
      return response;
    }
    
    // Parse form data
    const { file, preferences } = await parseFormData(req);
    
    // Validate preferences
    const validGenders = ['male', 'female', 'other'];
    const validRoastLevels = ['pyar', 'ache', 'dhang'];
    const validRoastTypes = ['funny', 'serious', 'sarcastic', 'motivational'];
    const validLanguages = ['english', 'hindi', 'hinglish'];
    
    if (!validGenders.includes(preferences.gender) ||
        !validRoastLevels.includes(preferences.roastLevel) ||
        !validRoastTypes.includes(preferences.roastType) ||
        !validLanguages.includes(preferences.language)) {
      const response = NextResponse.json(
        {
          success: false,
          error: {
            message: 'Invalid preferences provided',
            status: 400,
            code: 'INVALID_PREFERENCES',
          },
        },
        { status: 400 }
      );
      setSecurityHeaders(response);
      return response;
    }
    
    // Validate and extract text from file
    let resumeText: string;
    try {
      fileProcessor.validateFile(file);
      resumeText = await fileProcessor.extractText(file);
    } catch (error: any) {
      let errorMessage = 'Failed to process the resume file';
      let errorCode = 'FILE_PROCESSING_ERROR';
      
      const errorMap: { [key: string]: { message: string; code: string } } = {
        'FILE_TOO_LARGE': {
          message: 'File size too large. Maximum size allowed is 5MB.',
          code: 'FILE_TOO_LARGE'
        },
        'UNSUPPORTED_FILE_TYPE': {
          message: 'Invalid file type. Please upload PDF or DOCX files only.',
          code: 'INVALID_FILE_TYPE'
        },
        'EMPTY_FILE': {
          message: 'The uploaded file is empty. Please upload a valid resume.',
          code: 'EMPTY_FILE'
        },
        'NO_TEXT_CONTENT': {
          message: 'No readable text found in the document.',
          code: 'NO_TEXT_CONTENT'
        },
        'INSUFFICIENT_TEXT_CONTENT': {
          message: 'Document content is too short to analyze.',
          code: 'INSUFFICIENT_CONTENT'
        }
      };
      
      const mappedError = errorMap[error.message];
      if (mappedError) {
        errorMessage = mappedError.message;
        errorCode = mappedError.code;
      }
      
      const response = NextResponse.json(
        {
          success: false,
          error: {
            message: errorMessage,
            status: 400,
            code: errorCode,
          },
        },
        { status: 400 }
      );
      setSecurityHeaders(response);
      return response;
    }
    
    // Validate extracted text
    if (!resumeText || resumeText.trim().length < 100) {
      const response = NextResponse.json(
        {
          success: false,
          error: {
            message: 'Resume content is too short. Please upload a complete resume with at least 100 characters.',
            status: 400,
            code: 'INSUFFICIENT_CONTENT',
          },
        },
        { status: 400 }
      );
      setSecurityHeaders(response);
      return response;
    }
    
    // AI Analysis
    let analysis;
    try {
      analysis = await geminiService.analyzeResume(resumeText, preferences);
    } catch (error: any) {
      const response = NextResponse.json(
        {
          success: false,
          error: {
            message: 'AI analysis service is temporarily unavailable. Please try again in a few moments.',
            status: 503,
            code: 'AI_SERVICE_UNAVAILABLE',
            retryAfter: 60,
          },
        },
        { status: 503 }
      );
      setSecurityHeaders(response);
      return response;
    }
    
    if (!analysis.success) {
      const response = NextResponse.json(
        {
          success: false,
          error: {
            message: analysis.error || 'AI analysis failed. Please try again.',
            status: 502,
            code: analysis.code || 'AI_ANALYSIS_FAILED',
          },
        },
        { status: 502 }
      );
      setSecurityHeaders(response);
      return response;
    }
    
    // Save to storage (non-blocking)
    const metadata = {
      clientIP,
      userAgent: req.headers.get('user-agent') || '',
      requestId: crypto.randomUUID(),
      countryCode: req.headers.get('cf-ipcountry') || 'unknown',
    };
    
    // Don't await this to avoid blocking the response
    saveResumeData(file, resumeText, analysis.data, preferences, metadata)
      .catch(error => console.error('Storage error:', error));
    
    const processingTime = Date.now() - startTime;
    
    // Prepare response
    const response = NextResponse.json({
      success: true,
      data: {
        ...analysis.data,
        metadata: {
          requestId: metadata.requestId,
          processingTime,
          modelUsed: 'gemini-1.5-flash',
          analysisVersion: '3.0',
          timestamp: new Date().toISOString(),
        },
      },
    });
    
    requestId = setSecurityHeaders(response);
    return response;
    
  } catch (error: any) {
    const processingTime = Date.now() - startTime;
    
    console.error('Resume analysis error:', {
      error: error.message,
      stack: error.stack,
      processingTime,
      requestId
    });
    
    const response = NextResponse.json(
      {
        success: false,
        error: {
          message: 'An unexpected error occurred while analyzing your resume. Please try again.',
          status: 500,
          code: 'INTERNAL_SERVER_ERROR',
          supportInfo: 'If this error persists, please contact support.',
        },
      },
      { status: 500 }
    );
    
    setSecurityHeaders(response);
    return response;
  }
}

// GET /api/resume/test
export async function GET(req: NextRequest) {
  try {
    await connectDB();
    
    const response = NextResponse.json({
      success: true,
      message: 'CV Slayer Resume API is operational',
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || '1.0.0',
      status: 'healthy',
      endpoints: {
        analyze: 'POST /api/resume/analyze',
        test: 'GET /api/resume/test',
        info: 'GET /api/resume/info',
      },
      services: {
        database: 'connected',
        fileProcessor: fileProcessor.isReady() ? 'ready' : 'not ready',
        geminiService: 'ready',
      },
    });
    
    setSecurityHeaders(response);
    return response;
  } catch (error: any) {
    const response = NextResponse.json(
      {
        success: false,
        message: 'Service health check failed',
        error: process.env.NODE_ENV === 'production' ? 'Internal error' : error.message,
        timestamp: new Date().toISOString(),
      },
      { status: 500 }
    );
    
    setSecurityHeaders(response);
    return response;
  }
}