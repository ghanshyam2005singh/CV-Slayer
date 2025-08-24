import mongoose, { Document, Schema } from 'mongoose';

interface IResume extends Document {
  resumeId: string;
  fileInfo: {
    fileName: string;
    originalFileName: string;
    fileSize: number;
    mimeType: string;
    fileHash: string;
  };
  extractedInfo: {
    personalInfo: {
      name?: string;
      email?: string;
      phone?: string;
      address: {
        full?: string;
        city?: string;
        state?: string;
        country?: string;
        zipCode?: string;
      };
      socialProfiles: {
        linkedin?: string;
        github?: string;
        portfolio?: string;
        website?: string;
        twitter?: string;
      };
    };
    professionalSummary?: string;
    skills: {
      technical: string[];
      soft: string[];
      languages: string[];
      tools: string[];
      frameworks: string[];
    };
    experience: Array<{
      title?: string;
      company?: string;
      location?: string;
      startDate?: string;
      endDate?: string;
      duration?: string;
      description?: string;
      achievements: string[];
      technologies: string[];
    }>;
    education: Array<{
      degree?: string;
      field?: string;
      institution?: string;
      location?: string;
      graduationYear?: string;
      gpa?: string;
      honors: string[];
      coursework: string[];
    }>;
    certifications: Array<{
      name?: string;
      issuer?: string;
      dateObtained?: string;
      expirationDate?: string;
      credentialId?: string;
      url?: string;
    }>;
    projects: Array<{
      name?: string;
      description?: string;
      role?: string;
      duration?: string;
      technologies: string[];
      achievements: string[];
      url?: string;
      github?: string;
    }>;
    awards: string[];
    volunteerWork: string[];
    interests: string[];
    references?: string;
  };
  analysis: {
    overallScore: number;
    feedback: string;
    strengths: string[];
    weaknesses: string[];
    improvements: Array<{
      priority: 'low' | 'medium' | 'high';
      title?: string;
      description?: string;
      example?: string;
    }>;
    resumeAnalytics: {
      wordCount?: number;
      pageCount?: number;
      sectionCount?: number;
      bulletPointCount?: number;
      quantifiableAchievements?: number;
      actionVerbsUsed?: number;
      industryKeywords: string[];
      readabilityScore?: number;
      atsCompatibility?: string;
      missingElements: string[];
      strongElements: string[];
    };
    contactValidation: {
      hasEmail?: boolean;
      hasPhone?: boolean;
      hasLinkedIn?: boolean;
      hasAddress?: boolean;
      emailValid?: boolean;
      phoneValid?: boolean;
      linkedInValid?: boolean;
    };
  };
  preferences: {
    roastLevel: string;
    language: string;
    roastType?: string;
    gender?: string;
  };
  timestamps: {
    uploadedAt: Date;
    analyzedAt?: Date;
    updatedAt: Date;
  };
  metadata: {
    clientIP?: string;
    userAgent?: string;
    countryCode?: string;
    gdprConsent?: boolean;
    requestId?: string;
    processingTime?: number;
  };
}

const resumeSchema = new Schema<IResume>({
  resumeId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  
  fileInfo: {
    fileName: { type: String, required: true },
    originalFileName: { type: String, required: true },
    fileSize: { type: Number, required: true },
    mimeType: { type: String, required: true },
    fileHash: { type: String, default: 'unknown' }
  },
  
  extractedInfo: {
    personalInfo: {
      name: String,
      email: String,
      phone: String,
      address: {
        full: String,
        city: String,
        state: String,
        country: String,
        zipCode: String
      },
      socialProfiles: {
        linkedin: String,
        github: String,
        portfolio: String,
        website: String,
        twitter: String
      }
    },
    professionalSummary: String,
    skills: {
      technical: [String],
      soft: [String],
      languages: [String],
      tools: [String],
      frameworks: [String]
    },
    experience: [{
      title: String,
      company: String,
      location: String,
      startDate: String,
      endDate: String,
      duration: String,
      description: String,
      achievements: [String],
      technologies: [String]
    }],
    education: [{
      degree: String,
      field: String,
      institution: String,
      location: String,
      graduationYear: String,
      gpa: String,
      honors: [String],
      coursework: [String]
    }],
    certifications: [{
      name: String,
      issuer: String,
      dateObtained: String,
      expirationDate: String,
      credentialId: String,
      url: String
    }],
    projects: [{
      name: String,
      description: String,
      role: String,
      duration: String,
      technologies: [String],
      achievements: [String],
      url: String,
      github: String
    }],
    awards: [String],
    volunteerWork: [String],
    interests: [String],
    references: String
  },
  
  analysis: {
    overallScore: { type: Number, required: true, min: 0, max: 100 },
    feedback: { type: String, required: true },
    strengths: [String],
    weaknesses: [String],
    improvements: [{
      priority: { type: String, enum: ['low', 'medium', 'high'] },
      title: String,
      description: String,
      example: String
    }],
    resumeAnalytics: {
      wordCount: Number,
      pageCount: Number,
      sectionCount: Number,
      bulletPointCount: Number,
      quantifiableAchievements: Number,
      actionVerbsUsed: Number,
      industryKeywords: [String],
      readabilityScore: Number,
      atsCompatibility: String,
      missingElements: [String],
      strongElements: [String]
    },
    contactValidation: {
      hasEmail: Boolean,
      hasPhone: Boolean,
      hasLinkedIn: Boolean,
      hasAddress: Boolean,
      emailValid: Boolean,
      phoneValid: Boolean,
      linkedInValid: Boolean
    }
  },
  
  preferences: {
    roastLevel: { type: String, required: true },
    language: { type: String, required: true },
    roastType: String,
    gender: String
  },
  
  timestamps: {
    uploadedAt: { type: Date, default: Date.now, required: true },
    analyzedAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
  },
  
  metadata: {
    clientIP: String,
    userAgent: String,
    countryCode: String,
    gdprConsent: Boolean,
    requestId: String,
    processingTime: Number
  }
}, {
  timestamps: { createdAt: 'createdAt', updatedAt: 'modifiedAt' }
});

// Add indexes for performance
resumeSchema.index({ 'timestamps.uploadedAt': -1 });
resumeSchema.index({ 'analysis.overallScore': -1 });
resumeSchema.index({ 'preferences.roastLevel': 1 });
resumeSchema.index({ 'metadata.clientIP': 1 });

// Pre-save middleware to update timestamps
resumeSchema.pre('save', function(next) {
  this.timestamps.updatedAt = new Date();
  next();
});

const Resume = mongoose.models.Resume || mongoose.model<IResume>('Resume', resumeSchema);

export default Resume;
export type { IResume };