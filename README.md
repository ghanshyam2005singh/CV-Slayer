# 🩸 CV Slayer 😈 — AI-Powered Resume Roaster

CV Slayer is not your typical resume reviewer. It's the dark-humored, brutally honest, slightly unhinged AI that delivers the feedback you never wanted to hear... but probably needed. Choose your roast intensity and watch your resume get professionally shredded with style, humor, and actionable insights.

## 🚨 DISCLAIMER
> **This tool is for entertainment and educational purposes only.**  
> It uses AI-generated humor, satire, and constructive criticism.  
> Don't take it personally — take it as motivation to improve.  
> Results are AI-generated and may not reflect professional HR standards.

---

## 🔥 Roast Modes & Personalization

| Mode         | Description                                          | Intensity Level | Target Style           |
|--------------|------------------------------------------------------|----------------|-------------------------|
| **Pyar Se 💘**   | Gentle feedback with humor and constructive tips    | Mild 😊        | Encouraging + Helpful   |
| **Ache Se 😬**   | Honest critique with wit and real talk              | Medium 😏      | Balanced + Satirical    |
| **Dhang Se 😈**  | No-holds-barred, savage professional roasting       | Brutal 🔥      | Unfiltered + Direct     |

### **Personalization Options**
- **Gender**: Tailors tone and examples (Male/Female/Other)
- **Language**: English, Hindi, or Hinglish
- **Style**: Funny, Serious, Sarcastic, or Motivational
- **Professional Level**: Entry, Mid-level, Senior, Executive

---

## 🏗️ Architecture & Tech Stack

### **Modern Full-Stack Implementation**
```
🌐 Frontend: Next.js 14 + React 18 + TypeScript
🚀 Styling: Tailwind CSS + Framer Motion
🤖 AI Service: Google Gemini API
📄 Processing: PDF-parse + Mammoth (DOCX)
🗄️ Database: MongoDB + Mongoose
🔐 Security: JWT + bcrypt + Rate Limiting
☁️ Deployment: Vercel (Frontend) + Serverless Functions
```

### **Project Structure**
```
cv-slayer/
├── app/                          # Next.js App Router
│   ├── admin/                    # Admin dashboard
│   │   └── page.tsx             # Admin panel interface
│   ├── api/                     # API routes
│   │   ├── admin/               # Admin endpoints
│   │   ├── resume/              # Resume processing
│   │   └── auth/                # Authentication
│   ├── globals.css              # Global styles
│   ├── layout.tsx               # Root layout
│   └── page.tsx                 # Landing page
├── components/                   # Reusable components
│   ├── AdminPanel.tsx           # Admin dashboard component
│   ├── FileUploader.tsx         # File upload interface
│   ├── ResultsDisplay.tsx       # Analysis results
│   └── Analytics.tsx            # Google Analytics
├── lib/                         # Utility libraries
│   ├── database.ts              # MongoDB connection
│   ├── gemini.ts                # AI service
│   ├── auth.ts                  # Authentication utilities
│   └── validators.ts            # Input validation
├── types/                       # TypeScript definitions
├── public/                      # Static assets
├── .env.local                   # Environment variables
├── next.config.js               # Next.js configuration
├── tailwind.config.js           # Tailwind configuration
└── package.json                 # Dependencies
```

---

## 📦 Installation & Setup

### **Prerequisites**
- Node.js 18+ 
- MongoDB database (local or Atlas)
- Google Gemini API key

### **Quick Start**
```bash
# Clone the repository
git clone https://github.com/yourusername/cv-slayer.git
cd cv-slayer

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env.local
# Edit .env.local with your configuration

# Run development server
npm run dev
```

### **Complete Package Installation**
```bash
# Core Dependencies
npm install next@latest react@latest react-dom@latest typescript @types/node @types/react @types/react-dom

# UI & Animation
npm install framer-motion tailwindcss @tailwindcss/typography autoprefixer postcss

# Backend & Database
npm install @google/generative-ai mongodb mongoose bcryptjs jsonwebtoken

# File Processing
npm install pdf-parse mammoth docx-parser multer

# Security & Validation
npm install express-rate-limit helmet compression zod joi validator

# Development Dependencies
npm install --save-dev @types/bcryptjs @types/jsonwebtoken @types/multer eslint eslint-config-next prettier
```

### **Environment Configuration**
```env
# AI Service
GEMINI_API_KEY=your_gemini_api_key_here

# Database
MONGODB_URI=mongodb://localhost:27017/cv-slayer
# Or MongoDB Atlas: mongodb+srv://username:password@cluster.mongodb.net/cv-slayer

# Authentication & Security
JWT_SECRET=your_super_secure_jwt_secret_minimum_32_characters
ADMIN_EMAIL=admin@cvslayer.com
ADMIN_PASSWORD=your_secure_admin_password
BCRYPT_SALT_ROUNDS=12

# File Upload Limits
MAX_FILE_SIZE=5242880                # 5MB
ALLOWED_FILE_TYPES=pdf,doc,docx

# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000          # 15 minutes
RATE_LIMIT_MAX_REQUESTS=100
RESUME_RATE_LIMIT_MAX=10

# Application Settings
NODE_ENV=development
NEXT_PUBLIC_APP_URL=http://localhost:3000

# Optional: Analytics
NEXT_PUBLIC_GA_ID=G-XXXXXXXXXX
```

---

## 🚀 Deployment

### **Vercel Deployment (Recommended)**
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel

# Set environment variables in Vercel dashboard
# Add MongoDB connection string for production
```

### **Manual Deployment Steps**
1. **Build the application**:
   ```bash
   npm run build
   ```

2. **Set up production database**:
   - Use MongoDB Atlas for production
   - Update `MONGODB_URI` in production environment

3. **Configure environment variables**:
   - Add all `.env.local` variables to your hosting platform
   - Use secure, production-ready secrets

4. **Deploy**:
   - Push to GitHub and connect to Vercel
   - Or deploy to your preferred hosting platform

---

## 📊 Features & Capabilities

### **Core Features**
- 🤖 **AI-Powered Analysis**: Advanced resume evaluation using Google Gemini
- 📈 **Scoring System**: Comprehensive 0-100 scoring with detailed breakdown
- 🎯 **Personalized Feedback**: Tailored advice based on experience level and industry
- 📱 **Responsive Design**: Works seamlessly on desktop, tablet, and mobile
- 🔒 **Secure Processing**: Files are processed and immediately deleted
- ⚡ **Fast Performance**: Optimized for speed and user experience

### **Analysis Categories**
- **Contact Information**: Email, phone, LinkedIn profile validation
- **Professional Summary**: Clarity, impact, and relevance assessment
- **Work Experience**: Achievement quantification and skill demonstration
- **Skills Section**: Relevance, organization, and market demand analysis
- **Education**: Relevance and presentation evaluation
- **Formatting**: ATS compatibility and visual appeal
- **Keywords**: Industry-specific terminology and optimization
- **Overall Impact**: Professional presentation and competitive positioning

---

## 📱 Usage Examples

### **API Endpoints**
```typescript
// Upload and analyze resume
POST /api/resume/analyze
Content-Type: multipart/form-data

// Get analysis results
GET /api/resume/{id}

```

### **Example Response**
```json
{
  "success": true,
  "data": {
    "id": "resume_12345",
    "score": 75,
    "personalInfo": {
      "name": "John Doe",
      "email": "john.doe@email.com",
      "phone": "+1-555-0123"
    },
    "analysis": {
      "overallScore": 75,
      "feedback": "Your resume shows solid experience...",
      "strengths": ["Clear work history", "Quantified achievements"],
      "weaknesses": ["Missing keywords", "Generic objective"],
      "suggestions": ["Add industry-specific skills", "Improve summary"]
    },
    "analytics": {
      "wordCount": 425,
      "pageCount": 1,
      "sectionCount": 6,
      "atsCompatibility": "Good"
    }
  }
}
```

---

## 🛡️ Security & Privacy

### **Data Protection**
- ✅ **Zero File Storage**: PDFs/DOCX files are processed and immediately deleted
- ✅ **Encrypted Storage**: All data encrypted at rest and in transit
- ✅ **Rate Limiting**: Prevents abuse and ensures fair usage
- ✅ **Input Validation**: Comprehensive sanitization of all inputs
- ✅ **Admin Security**: JWT-based authentication with secure admin panel
- ✅ **GDPR Compliant**: User data can be deleted upon request

### **Security Headers**
- Content Security Policy (CSP)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin

---

## 🧪 Testing & Development

### **Development Commands**
```bash
# Start development server
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run linting
npm run lint

# Type checking
npm run type-check
```

### **API Testing**
```bash
# Health check
curl http://localhost:3000/api/health

# Upload resume (replace with actual file)
curl -X POST \
  -F "resume=@path/to/resume.pdf" \
  -F "preferences={\"roastLevel\":\"medium\",\"language\":\"english\"}" \
  http://localhost:3000/api/resume/analyze
```

---

## 🎯 Roadmap & Future Features

### **Upcoming Features**
- 🤖 **Multi-AI Integration**: Claude, GPT-4, and Gemini comparison
- 📊 **Industry Benchmarking**: Compare against industry standards
- 🎨 **Resume Templates**: AI-suggested improvements with visual templates
- 📧 **Email Reports**: Detailed analysis sent to user's email
- 🔗 **LinkedIn Integration**: Direct import from LinkedIn profiles
- 📱 **Mobile App**: Native iOS/Android applications
- 🌍 **Multi-language Support**: Support for 20+ languages
- 🏢 **Company-specific Analysis**: Tailored feedback for specific companies

### **Technical Improvements**
- WebSocket real-time processing updates
- Advanced caching with Redis
- Microservices architecture
- Enhanced AI prompt engineering
- Automated testing suite
- Performance monitoring dashboard

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### **Development Setup**
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Google Gemini API** for advanced AI capabilities
- **Vercel** for seamless deployment platform
- **MongoDB** for robust data storage
- **Next.js team** for the amazing framework
- **Open source community** for the incredible tools and libraries

---

## 📞 Support & Contact

- **Website**: [cv-slayer.vercel.app](https://cv-slayer.vercel.app)
- **Issues**: [GitHub Issues](https://github.com/yourusername/cv-slayer/issues)
- **Email**: support@cvslayer.com
- **Twitter**: [@cvslayer](https://twitter.com/cvslayer)

---

**Made with ❤️ and a lot of ☕ by Iron Industry**

*Remember: The best resume is one that gets you interviews. CV Slayer helps you get there faster.* 🚀