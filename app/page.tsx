'use client';

import React, { useState, useCallback, useMemo, useEffect, useRef } from 'react';
import Navbar from '@/components/Navbar';
import ResultsDisplay from '@/components/ResultsDisplay';

// Error Boundary Component
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    if (process.env.NODE_ENV === 'development') {
      console.error('Error caught by boundary:', error, errorInfo);
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-100 p-4">
          <div className="bg-white rounded-xl shadow-lg p-8 max-w-md w-full text-center">
            <div className="text-4xl mb-4">⚠️</div>
            <h2 className="text-xl font-semibold mb-2">Something went wrong</h2>
            <p className="mb-6">We apologize for the inconvenience. Please refresh the page and try again.</p>
            <button 
              onClick={() => window.location.reload()}
              className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition"
            >
              🔄 Reload Page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

interface FormData {
  gender: 'male' | 'female' | 'other';
  roastLevel: 'pyar' | 'ache' | 'dhang';
  roastType: 'funny' | 'serious' | 'sarcastic' | 'motivational';
  language: 'english' | 'hindi' | 'hinglish';
}

interface Results {
  score: number;
  roastFeedback: string;
  improvements: string[];
  strengths: string[];
  weaknesses: string[];
  originalFileName: string;
}

export default function HomePage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [results, setResults] = useState<Results | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);
  const [loadingStep, setLoadingStep] = useState('');
  const [formData, setFormData] = useState<FormData>({
    gender: 'male',
    roastLevel: 'pyar',
    roastType: 'funny',
    language: 'english'
  });

  const fileInputRef = useRef<HTMLInputElement>(null);

  const API_CONFIG = useMemo(() => ({
    baseURL: process.env.NODE_ENV === 'production' 
      ? window.location.origin 
      : process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000',
    timeout: 180000,
    maxFileSize: 10 * 1024 * 1024,
    allowedTypes: [
      'application/pdf',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/msword'
    ]
  }), []);

  const validateFile = useCallback((file: File | null): string | null => {
    if (!file) return 'Please select a resume file';
    if (!API_CONFIG.allowedTypes.includes(file.type)) {
      return 'Please upload only PDF or Word documents (.pdf, .doc, .docx)';
    }
    if (file.size > API_CONFIG.maxFileSize) {
      return `File size must be less than ${API_CONFIG.maxFileSize / (1024 * 1024)}MB`;
    }
    if (file.size === 0) {
      return 'Selected file appears to be empty';
    }
    return null;
  }, [API_CONFIG]);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setError('');
    if (file) {
      const validationError = validateFile(file);
      if (validationError) {
        setError(validationError);
        setSelectedFile(null);
        e.target.value = '';
        return;
      }
      setSelectedFile(file);
    } else {
      setSelectedFile(null);
    }
  }, [validateFile]);

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
    const { name, value } = e.target;
    const validValues = {
      gender: ['male', 'female', 'other'],
      roastLevel: ['pyar', 'ache', 'dhang'],
      roastType: ['funny', 'serious', 'sarcastic', 'motivational'],
      language: ['english', 'hindi', 'hinglish']
    };
    if (validValues[name as keyof typeof validValues]?.includes(value)) {
      setFormData(prev => ({ ...prev, [name]: value }));
      setError('');
    }
  }, []);

  const handleReset = useCallback(() => {
    setResults(null);
    setSelectedFile(null);
    setError('');
    setLoadingStep('');
    setIsLoading(false);
    setFormData({
      gender: 'male',
      roastLevel: 'pyar',
      roastType: 'funny',
      language: 'english'
    });
    if (fileInputRef.current) fileInputRef.current.value = '';
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreedToTerms) {
      setError('Please accept the Terms & Conditions to continue');
      return;
    }
    if (!selectedFile) {
      setError('Please select a resume file');
      return;
    }
    const validationError = validateFile(selectedFile);
    if (validationError) {
      setError(validationError);
      return;
    }
    setIsLoading(true);
    setError('');
    setLoadingStep('uploading');

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), API_CONFIG.timeout);

    try {
      const formDataToSend = new FormData();
      formDataToSend.append('resume', selectedFile);
      formDataToSend.append('gender', formData.gender);
      formDataToSend.append('roastLevel', formData.roastLevel);
      formDataToSend.append('roastType', formData.roastType);
      formDataToSend.append('language', formData.language);
      formDataToSend.append('consentGiven', 'true');
      formDataToSend.append('termsAccepted', 'true');

      setLoadingStep('analyzing');

      const apiUrl = `${API_CONFIG.baseURL}/api/resume/analyze`;
      const response = await fetch(apiUrl, {
        method: 'POST',
        body: formDataToSend,
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });

      clearTimeout(timeoutId);
      setLoadingStep('processing');

      if (!response.ok) {
        let errorMessage = 'Analysis failed. Please try again.';
        try {
          const errorData = await response.json();
          errorMessage = errorData.error?.message || errorData.message || errorMessage;
        } catch {
          const statusMessages: Record<number, string> = {
            400: 'Invalid file or request',
            409: 'This resume file has already been analyzed. Please upload a different file.',
            413: 'File too large',
            429: 'Too many requests. Please wait and try again',
            500: 'Server error. Please try again later',
            503: 'Service temporarily unavailable'
          };
          errorMessage = statusMessages[response.status] || `Error ${response.status}`;
        }
        throw new Error(errorMessage);
      }

      const responseText = await response.text();
      let result;
      try {
        result = JSON.parse(responseText);
      } catch {
        throw new Error('Invalid server response');
      }

      let processedData;
      if (result.data) {
        processedData = result.data;
      } else if (result.success !== false) {
        processedData = {
          score: result.score,
          roastFeedback: result.roastFeedback,
          improvements: result.improvements || [],
          strengths: result.strengths || [],
          weaknesses: result.weaknesses || []
        };
      } else {
        throw new Error(result.error?.message || 'Analysis failed');
      }

      if (!processedData.roastFeedback && !processedData.score) {
        throw new Error('Incomplete analysis received');
      }

      const finalResults: Results = {
        ...processedData,
        originalFileName: selectedFile.name,
        score: Number(processedData.score) || 0,
        roastFeedback: processedData.roastFeedback || '',
        improvements: Array.isArray(processedData.improvements) ? processedData.improvements : [],
        strengths: Array.isArray(processedData.strengths) ? processedData.strengths : [],
        weaknesses: Array.isArray(processedData.weaknesses) ? processedData.weaknesses : []
      };

      setLoadingStep('complete');
      setTimeout(() => {
        setResults(finalResults);
        setIsLoading(false);
        setLoadingStep('');
      }, 1000);

    } catch (error: any) {
      clearTimeout(timeoutId);
      let userMessage;
      if (error.name === 'AbortError') {
        userMessage = 'Request timed out. Please try with a smaller file';
      } else if (error.message.includes('fetch') || error.message.includes('Network')) {
        userMessage = 'Connection failed. Please check your internet and try again';
      } else {
        userMessage = error.message || 'An error occurred. Please try again';
      }
      setError(userMessage);
      setIsLoading(false);
      setLoadingStep('');
    }
  }, [selectedFile, formData, agreedToTerms, validateFile, API_CONFIG]);

  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(''), 8000);
      return () => clearTimeout(timer);
    }
  }, [error]);

  // Results view
  if (results) {
    return (
      <ErrorBoundary>
        <div className="bg-gray-100 min-h-screen">
          <Navbar />
          <main className="pt-16">
            <ResultsDisplay results={results} onReset={handleReset} />
          </main>
        </div>
      </ErrorBoundary>
    );
  }

  // Loading view
  if (isLoading) {
    const getLoadingMessage = () => {
      const messages = {
        hindi: {
          uploading: 'आपका resume upload हो रहा है...',
          analyzing: 'AI आपका resume analyze कर रहा है...',
          processing: 'Feedback तैयार हो रहा है...',
          complete: 'Analysis पूरा हो गया!'
        },
        hinglish: {
          uploading: 'Resume upload ho raha hai...',
          analyzing: 'AI analysis kar raha hai...',
          processing: 'Feedback ready kar rahe hain...',
          complete: 'Bas ho gaya!'
        },
        english: {
          uploading: 'Uploading your resume...',
          analyzing: 'AI is analyzing your resume...',
          processing: 'Generating personalized feedback...',
          complete: 'Analysis complete!'
        }
      };
      return messages[formData.language]?.[loadingStep as keyof typeof messages.english] || 'Processing...';
    };

    const getProgressPercentage = () => {
      const percentages: Record<string, number> = { 
        uploading: 25, 
        analyzing: 50, 
        processing: 75, 
        complete: 100 
      };
      return percentages[loadingStep] || 0;
    };

    return (
      <ErrorBoundary>
        <div className="bg-gray-100 min-h-screen">
          <Navbar />
          <main className="flex flex-col items-center justify-center min-h-screen">
            <div className="bg-white rounded-xl shadow-lg p-8 max-w-lg w-full mx-4">
              <div className="flex justify-center space-x-4 mb-8">
                <span className="text-4xl">📄</span>
                <span className="text-4xl">🤖</span>
                <span className="text-4xl">🔥</span>
              </div>
              <div className="mb-8">
                <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
                  <div 
                    className="bg-blue-600 h-3 rounded-full transition-all duration-500"
                    style={{ width: `${getProgressPercentage()}%` }}
                  />
                </div>
                <div className="text-sm text-gray-600">{getProgressPercentage()}%</div>
              </div>
              <h2 className="text-2xl font-bold text-gray-900 mb-4">{getLoadingMessage()}</h2>
              <div>
                {formData.roastLevel === 'dhang' && (
                  <div className="flex items-center space-x-2 text-red-600">
                    <span className="text-2xl">😈</span>
                    <span>
                      {formData.language === 'hindi' && "तैयार हो जाओ कड़वी सच्चाई के लिए!"}
                      {formData.language === 'hinglish' && "Brutal honesty incoming, brace yourself!"}
                      {formData.language === 'english' && "Preparing some brutal honesty..."}
                    </span>
                  </div>
                )}
                {formData.roastLevel === 'ache' && (
                  <div className="flex items-center space-x-2 text-yellow-600">
                    <span className="text-2xl">🤔</span>
                    <span>
                      {formData.language === 'hindi' && "संतुलित feedback तैयार कर रहे हैं"}
                      {formData.language === 'hinglish' && "Balanced feedback aa raha hai"}
                      {formData.language === 'english' && "Preparing balanced feedback..."}
                    </span>
                  </div>
                )}
                {formData.roastLevel === 'pyar' && (
                  <div className="flex items-center space-x-2 text-green-600">
                    <span className="text-2xl">😊</span>
                    <span>
                      {formData.language === 'hindi' && "प्यार से feedback दे रहे हैं"}
                      {formData.language === 'hinglish' && "Gentle feedback ban raha hai"}
                      {formData.language === 'english' && "Preparing gentle feedback..."}
                    </span>
                  </div>
                )}
              </div>
            </div>
          </main>
        </div>
      </ErrorBoundary>
    );
  }

  // Main application
  return (
    <ErrorBoundary>
      <div className="bg-gray-100 min-h-screen">
        <Navbar />
        {/* Hero Section */}
        <section className="py-16">
          <div className="container mx-auto px-4 flex flex-col md:flex-row items-center justify-between">
            <div className="max-w-lg">
              <h1 className="text-5xl font-bold text-gray-900 mb-4">CV Slayer</h1>
              <h2 className="text-2xl font-semibold text-blue-700 mb-4">Resume Roaster</h2>
              <p className="mb-6 text-gray-700">Get brutally honest AI-powered feedback on your resume with humor, insights, and actionable improvements.</p>
              <div className="flex space-x-2 mb-6">
                <span className="bg-blue-100 text-blue-700 px-3 py-1 rounded-full text-sm font-semibold">🤖 AI-Powered</span>
                <span className="bg-gray-100 text-gray-700 px-3 py-1 rounded-full text-sm font-semibold">🎭 Multiple Styles</span>
                <span className="bg-gray-100 text-gray-700 px-3 py-1 rounded-full text-sm font-semibold">🌍 Multi-Language</span>
              </div>
              <a href="#upload" className="bg-blue-600 text-white px-6 py-3 rounded-lg font-bold shadow hover:bg-blue-700 transition">
                Start Roasting 🔥
              </a>
            </div>
            <div className="mt-8 md:mt-0 flex space-x-4">
              <span className="text-6xl">📄</span>
              <span className="text-6xl">🤖</span>
              <span className="text-6xl">🔥</span>
              <span className="text-6xl">📊</span>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section className="py-16">
          <div className="container mx-auto px-4">
            <h2 className="text-3xl font-bold mb-4 text-center text-gray-900">Why Choose CV Slayer?</h2>
            <p className="text-center mb-8 text-gray-600">Professional resume analysis with personality</p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="bg-white p-6 rounded-xl shadow text-center">
                <div className="text-3xl mb-2">🤖</div>
                <h3 className="font-semibold mb-2 text-gray-900">AI-Powered Analysis</h3>
                <p className="text-gray-600">Advanced machine learning analyzes content, structure, and ATS compatibility</p>
              </div>
              <div className="bg-white p-6 rounded-xl shadow text-center">
                <div className="text-3xl mb-2">🎭</div>
                <h3 className="font-semibold mb-2 text-gray-900">Multiple Personalities</h3>
                <p className="text-gray-600">Choose from gentle guidance to brutal honesty - whatever motivates you</p>
              </div>
              <div className="bg-white p-6 rounded-xl shadow text-center">
                <div className="text-3xl mb-2">🌍</div>
                <h3 className="font-semibold mb-2 text-gray-900">Multi-Language Support</h3>
                <p className="text-gray-600">Get feedback in English, Hindi, or Hinglish for better understanding</p>
              </div>
            </div>
          </div>
        </section>

        {/* Upload Section */}
        <section id="upload" className="py-16">
          <div className="container mx-auto px-4">
            <div className="max-w-xl mx-auto bg-white rounded-xl shadow-lg p-8">
              {error && (
                <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl flex items-center space-x-3" role="alert">
                  <span className="text-xl">⚠️</span>
                  <span className="text-red-800 flex-1">{error}</span>
                  <button 
                    className="text-red-500 hover:text-red-700"
                    onClick={() => setError('')}
                    aria-label="Close error"
                  >
                    ×
                  </button>
                </div>
              )}
              <form onSubmit={handleSubmit} className="space-y-8">
                <div>
                  <label htmlFor="resumeFile" className="block cursor-pointer">
                    <div className={`border-2 border-dashed rounded-xl p-8 text-center transition-colors ${selectedFile ? 'border-blue-400 bg-blue-50' : 'border-gray-300 hover:border-blue-400'}`}>
                      <div className="text-4xl mb-2">📄</div>
                      <div className="mb-2">
                        <span className="font-medium">{selectedFile ? selectedFile.name : "Choose your resume"}</span>
                        <span className="block text-gray-500">PDF, DOC, DOCX up to 10MB</span>
                      </div>
                      <div className="inline-block bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium mt-2">Browse</div>
                    </div>
                  </label>
                  <input 
                    type="file" 
                    id="resumeFile" 
                    accept=".pdf,.docx,.doc"
                    onChange={handleFileChange}
                    disabled={isLoading}
                    required
                    ref={fileInputRef}
                    className="hidden"
                  />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="block mb-1 font-medium text-gray-700">Gender</label>
                    <select name="gender" value={formData.gender} onChange={handleInputChange} disabled={isLoading} className="w-full border rounded-lg px-3 py-2">
                      <option value="male">Male</option>
                      <option value="female">Female</option>
                      <option value="other">Other/Neutral</option>
                    </select>
                  </div>
                  <div>
                    <label className="block mb-1 font-medium text-gray-700">Roast Level</label>
                    <select name="roastLevel" value={formData.roastLevel} onChange={handleInputChange} disabled={isLoading} className="w-full border rounded-lg px-3 py-2">
                      <option value="pyar">😊 Gentle (Supportive)</option>
                      <option value="ache">🤔 Balanced (Honest)</option>
                      <option value="dhang">😈 Savage (Brutal)</option>
                    </select>
                  </div>
                  <div>
                    <label className="block mb-1 font-medium text-gray-700">Style</label>
                    <select name="roastType" value={formData.roastType} onChange={handleInputChange} disabled={isLoading} className="w-full border rounded-lg px-3 py-2">
                      <option value="funny">😄 Funny</option>
                      <option value="serious">🎯 Professional</option>
                      <option value="sarcastic">😏 Sarcastic</option>
                      <option value="motivational">💪 Motivational</option>
                    </select>
                  </div>
                  <div>
                    <label className="block mb-1 font-medium text-gray-700">Language</label>
                    <select name="language" value={formData.language} onChange={handleInputChange} disabled={isLoading} className="w-full border rounded-lg px-3 py-2">
                      <option value="english">🇺🇸 English</option>
                      <option value="hindi">🇮🇳 Hindi</option>
                      <option value="hinglish">🌍 Hinglish</option>
                    </select>
                  </div>
                </div>
                <div className="flex items-center space-x-3">
                  <input 
                    type="checkbox" 
                    checked={agreedToTerms}
                    onChange={(e) => setAgreedToTerms(e.target.checked)}
                    disabled={isLoading}
                    required
                  />
                  <span>
                    I agree to the{' '}
                    <button 
                      type="button" 
                      className="underline text-blue-600"
                      onClick={() => setShowTermsModal(true)}
                    >
                      Terms of Service & Privacy Policy
                    </button>
                  </span>
                </div>
                <button 
                  type="submit" 
                  className="w-full bg-blue-600 text-white py-4 px-8 rounded-xl font-semibold text-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition flex items-center justify-center space-x-3"
                  disabled={!selectedFile || !agreedToTerms || isLoading}
                >
                  <span>{isLoading ? 'Analyzing...' : 'Roast My Resume!'}</span>
                  <span className="text-xl">🚀</span>
                </button>
              </form>
            </div>
          </div>
        </section>

        {/* Terms Modal */}
        {showTermsModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50" onClick={() => setShowTermsModal(false)}>
            <div className="bg-white rounded-xl max-w-2xl w-full max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
              <div className="flex items-center justify-between p-6 border-b border-gray-200">
                <h3 className="text-xl font-semibold text-gray-900">Terms of Service & Privacy Policy</h3>
                <button 
                  className="text-gray-400 hover:text-gray-600 text-2xl"
                  onClick={() => setShowTermsModal(false)}
                >
                  ×
                </button>
              </div>
              <div className="p-6">
                <section className="mb-4">
                  <h4 className="font-semibold mb-2">🔐 Privacy & Data Processing</h4>
                  <p>Your resume is processed temporarily for analysis. Files are automatically deleted after processing. We use industry-standard security measures to protect your data.</p>
                </section>
                <section className="mb-4">
                  <h4 className="font-semibold mb-2">🤖 AI Analysis</h4>
                  <p>We use advanced AI to analyze your resume content and provide feedback. Your data helps improve our service through anonymized machine learning.</p>
                </section>
                <section>
                  <h4 className="font-semibold mb-2">📞 Contact</h4>
                  <p>For questions about our services: outlercodie.com@gmail.com</p>
                </section>
              </div>
              <div className="flex items-center justify-end space-x-3 p-6 border-t border-gray-200">
                <button 
                  className="px-4 py-2 text-gray-600 hover:text-gray-800"
                  onClick={() => setShowTermsModal(false)}
                >
                  Close
                </button>
                <button 
                  className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                  onClick={() => {
                    setAgreedToTerms(true);
                    setShowTermsModal(false);
                  }}
                >
                  Accept Terms
                </button>
              </div>
            </div>
          </div>
        )}

        {/* How It Works */}
        <section className="py-16">
          <div className="container mx-auto px-4">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
              <div className="bg-white p-6 rounded-xl shadow text-center">
                <div className="text-xl font-bold mb-2 text-blue-700">1</div>
                <div className="text-3xl mb-2">📤</div>
                <h3 className="font-semibold mb-2 text-gray-900">Upload</h3>
                <p className="text-gray-600">Upload your resume securely</p>
              </div>
              <div className="bg-white p-6 rounded-xl shadow text-center">
                <div className="text-xl font-bold mb-2 text-blue-700">2</div>
                <div className="text-3xl mb-2">⚙️</div>
                <h3 className="font-semibold mb-2 text-gray-900">Customize</h3>
                <p className="text-gray-600">Choose your roasting preferences</p>
              </div>
              <div className="bg-white p-6 rounded-xl shadow text-center">
                <div className="text-xl font-bold mb-2 text-blue-700">3</div>
                <div className="text-3xl mb-2">🤖</div>
                <h3 className="font-semibold mb-2 text-gray-900">Analyze</h3>
                <p className="text-gray-600">AI processes and analyzes</p>
              </div>
              <div className="bg-white p-6 rounded-xl shadow text-center">
                <div className="text-xl font-bold mb-2 text-blue-700">4</div>
                <div className="text-3xl mb-2">📊</div>
                <h3 className="font-semibold mb-2 text-gray-900">Results</h3>
                <p className="text-gray-600">Get detailed feedback</p>
              </div>
            </div>
          </div>
        </section>

        {/* Sample Results */}
        <section id="examples" className="py-16">
          <div className="container mx-auto px-4">
            <h2 className="text-3xl font-bold mb-4 text-center text-gray-900">Sample Roasts</h2>
            <p className="text-center mb-8 text-gray-600">See what different styles look like</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              <div className="bg-white p-6 rounded-xl shadow">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xl">😄 Funny Style</span>
                  <span className="text-sm bg-green-100 text-green-800 px-2 py-1 rounded">Gentle</span>
                </div>
                <blockquote className="mb-2 text-gray-700">
                  "Your resume says 'Excel expert' but I bet you still Google how to make pie charts! 😅 Let's add some actual numbers to back up those claims."
                </blockquote>
                <div className="text-sm text-gray-500">
                  <strong>Focus:</strong> Humor with constructive feedback
                </div>
              </div>
              <div className="bg-white p-6 rounded-xl shadow">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xl">😈 Savage Style</span>
                  <span className="text-sm bg-red-100 text-red-800 px-2 py-1 rounded">Brutal</span>
                </div>
                <blockquote className="mb-2 text-gray-700">
                  "Bhai, tumhara resume dekh ke lagta hai ChatGPT ne 5 minute mein banaya hai. Itna generic content dekh ke recruiter ko neend aa jayegi!"
                </blockquote>
                <div className="text-sm text-gray-500">
                  <strong>Focus:</strong> Brutal honesty with real talk
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer id="contact" className="bg-white border-t border-gray-200 py-10 px-4">
          <div className="container mx-auto">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-6">
              <div>
                <h3 className="font-bold text-xl mb-2 text-blue-700">CV Slayer</h3>
                <p className="mb-2 text-gray-700">Making resumes better, one roast at a time.</p>
                <div className="flex space-x-4">
                  <button onClick={() => setShowTermsModal(true)} className="underline text-blue-600">Privacy Policy</button>
                  <button onClick={() => setShowTermsModal(true)} className="underline text-blue-600">Terms of Service</button>
                </div>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-gray-900">Contact</h4>
                <p className="mb-1 text-gray-700">outlercodie.com@gmail.com</p>
                <p><a href='https://iron-industry.tech' className="underline text-blue-600">Iron Industry</a></p>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-gray-900">Iron Industry</h4>
                <p className="mb-1 text-gray-700">Building innovative solutions</p>
                <p className="text-gray-700">🔒 Your data is secure</p>
              </div>
            </div>
            <div className="text-center text-sm text-gray-400">
              &copy; 2024 Iron Industry. All rights reserved.
            </div>
          </div>
        </footer>
      </div>
    </ErrorBoundary>
  );
}