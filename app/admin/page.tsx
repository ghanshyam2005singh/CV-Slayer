'use client';

import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface PersonalInfo {
  name?: string;
  email?: string;
  phone?: string;
  linkedin?: string;
  address?: string;
}

interface ContactValidation {
  hasEmail?: boolean;
  hasPhone?: boolean;
  hasLinkedIn?: boolean;
  hasAddress?: boolean;
  emailValid?: boolean;
  phoneValid?: boolean;
  linkedInValid?: boolean;
}

interface Resume {
  id: string;
  originalFileName: string;
  displayName?: string;
  fileSize: number;
  uploadedAt: string;
  score: number;
  personalInfo: PersonalInfo;
  language: string;
  roastType: string;
  roastLevel: string;
  wordCount: number;
  pageCount: number;
  hasEmail: boolean;
  hasPhone: boolean;
  hasLinkedIn: boolean;
  contactValidation: ContactValidation;
  fullData?: any;
}

interface DashboardData {
  totalResumes: number;
  todayResumes: number;
  averageScore: number;
  recentResumes: Resume[];
}

interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
}

const AdminPage: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [dashboardData, setDashboardData] = useState<DashboardData | null>(null);
  const [resumes, setResumes] = useState<Resume[]>([]);
  const [currentView, setCurrentView] = useState<'dashboard' | 'resumes' | 'analytics'>('dashboard');
  const [selectedResume, setSelectedResume] = useState<any>(null);
  const [showResumeModal, setShowResumeModal] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // Toast management
  const addToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = Date.now() + Math.random();
    const newToast: Toast = { id, message, type };
    
    setToasts(prev => [...prev, newToast]);
    
    setTimeout(() => {
      setToasts(prev => prev.filter(toast => toast.id !== id));
    }, 5000);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  // Text cleaning utility
  const cleanText = useCallback((text: any): string => {
    if (!text || typeof text !== 'string') return String(text || '');
    
    return text
      .replace(/â€™/g, "'")
      .replace(/â€œ/g, '"')
      .replace(/â€\u009d/g, '"')
      .replace(/â€"/g, '—')
      .replace(/â€¢/g, '•')
      .replace(/Â/g, '')
      .replace(/&#x27;/g, "'")
      .replace(/&#39;/g, "'")
      .replace(/&quot;/g, '"')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .trim();
  }, []);

  // Token validation
  const isTokenValid = useCallback(() => {
    const token = localStorage.getItem('adminToken');
    const expiry = localStorage.getItem('adminTokenExpiry');
    return token && expiry && Date.now() < parseInt(expiry);
  }, []);

  // Logout handler
  const handleLogout = useCallback(() => {
    ['adminToken', 'adminTokenExpiry', 'adminUser'].forEach(item => 
      localStorage.removeItem(item)
    );
    setIsAuthenticated(false);
    setDashboardData(null);
    setResumes([]);
    addToast('Logged out successfully', 'info');
  }, [addToast]);

  // API request helper
  const apiRequest = useCallback(async (endpoint: string, options: RequestInit = {}) => {
    if (!isTokenValid()) {
      setIsAuthenticated(false);
      throw new Error('Session expired');
    }

    const token = localStorage.getItem('adminToken');
    const response = await fetch(`/api${endpoint}`, {
      ...options,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...options.headers
      }
    });

    if (response.status === 401) {
      handleLogout();
      throw new Error('Session expired');
    }

   if (!response.ok) {
  let errorData = {};
  try {
    errorData = await response.json();
  } catch {
    errorData = { error: { message: response.statusText } };
  }
  throw new Error(errorData.error?.message || `Request failed (${response.status})`);
}

    return response.json();
  }, [isTokenValid, handleLogout]);

  // Login handler
  const handleLogin = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) return;

    setLoading(true);

    try {
      const response = await fetch('/api/admin', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: email.trim(), password })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error?.message || 'Login failed');
      }

      const result = await response.json();
      
      if (result.success && result.token) {
        const expiryTime = Date.now() + (30 * 60 * 1000); // 30 minutes
        localStorage.setItem('adminToken', result.token);
        localStorage.setItem('adminTokenExpiry', expiryTime.toString());
        localStorage.setItem('adminUser', JSON.stringify({ email }));
        
        setIsAuthenticated(true);
        setEmail('');
        setPassword('');
        addToast('Login successful', 'success');
        
        // Load initial data
        setTimeout(loadDashboard, 100);
      } else {
        throw new Error('Invalid login response');
      }
    } catch (error: any) {
      addToast(
        error.message.includes('fetch') 
          ? 'Cannot connect to server' 
          : error.message,
        'error'
      );
    } finally {
      setLoading(false);
    }
  }, [email, password, addToast]);

  // Load dashboard data
  const loadDashboard = useCallback(async () => {
    try {
      setLoading(true);
      const result = await apiRequest('/admin');
      
      if (result.success && result.data) {
        const processedData: DashboardData = {
          totalResumes: result.data.totalResumes || 0,
          todayResumes: result.data.todayResumes || 0,
          averageScore: result.data.averageScore || 0,
          recentResumes: (result.data.recentResumes || []).map((resume: any) => ({
            id: resume.id,
            displayName: cleanText(resume.personalInfo?.name || resume.displayName || resume.fileName || 'Unknown'),
            originalFileName: cleanText(resume.fileName || ''),
            fileSize: resume.fileSize || 0,
            uploadedAt: resume.uploadedAt,
            score: resume.score || 0,
            personalInfo: {
              name: cleanText(resume.personalInfo?.name || 'Not extracted'),
              email: cleanText(resume.personalInfo?.email || 'Not found'),
              phone: cleanText(resume.personalInfo?.phone || 'Not found'),
              linkedin: cleanText(resume.personalInfo?.linkedin || 'Not found'),
              address: cleanText(resume.personalInfo?.address || 'Not found')
            },
            hasEmail: resume.hasEmail || false,
            hasPhone: resume.hasPhone || false,
            hasLinkedIn: resume.hasLinkedIn || false,
            roastLevel: resume.roastLevel || 'N/A',
            language: resume.language || 'N/A',
            roastType: resume.roastType || 'N/A',
            wordCount: resume.wordCount || 0,
            pageCount: resume.pageCount || 1,
            contactValidation: resume.contactValidation || {},
            fullData: resume.fullData || resume
          }))
        };
        
        setDashboardData(processedData);
      } else {
        setDashboardData({
          totalResumes: 0,
          todayResumes: 0,
          averageScore: 0,
          recentResumes: []
        });
      }
    } catch (error: any) {
      addToast(`Dashboard error: ${error.message}`, 'error');
      setDashboardData({
        totalResumes: 0,
        todayResumes: 0,
        averageScore: 0,
        recentResumes: []
      });
    } finally {
      setLoading(false);
    }
  }, [apiRequest, cleanText, addToast]);

  // Load resumes
  const loadResumes = useCallback(async () => {
    try {
      setLoading(true);
      const result = await apiRequest('/admin/resumes');
      
      if (result.success && result.data) {
        const resumesData = Array.isArray(result.data) ? result.data : 
                           Array.isArray(result.data.resumes) ? result.data.resumes : [];
        
        setResumes(resumesData.map((resume: any) => {
          const personalInfo = resume.personalInfo || {};
          
          return {
            id: resume.id,
            originalFileName: cleanText(resume.fileName || 'Unknown'),
            fileSize: resume.fileSize || 0,
            uploadedAt: resume.uploadedAt || new Date().toISOString(),
            score: resume.score || 0,
            displayName: cleanText(personalInfo.name || resume.fileName?.replace(/\.[^/.]+$/, "") || 'Unknown'),
            personalInfo: {
              name: cleanText(personalInfo.name || 'Not extracted'),
              email: cleanText(personalInfo.email || 'Not found'),
              phone: cleanText(personalInfo.phone || 'Not found'),
              linkedin: cleanText(personalInfo.linkedin || 'Not found'),
              address: cleanText(personalInfo.address || 'Not found')
            },
            language: resume.language || 'N/A',
            roastType: resume.roastType || 'N/A',
            roastLevel: resume.roastLevel || 'N/A',
            wordCount: resume.wordCount || resume.analytics?.wordCount || 0,
            pageCount: resume.pageCount || resume.analytics?.pageCount || 1,
            hasEmail: resume.hasEmail || false,
            hasPhone: resume.hasPhone || false,
            hasLinkedIn: resume.hasLinkedIn || false,
            contactValidation: resume.contactValidation || {},
            fullData: resume.fullData || resume
          };
        }));
      } else {
        setResumes([]);
      }
    } catch (error: any) {
      addToast(`Resumes error: ${error.message}`, 'error');
      setResumes([]);
    } finally {
      setLoading(false);
    }
  }, [apiRequest, cleanText, addToast]);

  // Handle resume click
  const handleResumeClick = useCallback(async (resume: Resume) => {
    try {
      const result = await apiRequest(`/admin/resume/${resume.id}`);
      if (result.success && result.data) {
        setSelectedResume(result.data);
      } else {
        setSelectedResume(resume.fullData || resume);
      }
      setShowResumeModal(true);
    } catch (error) {
      setSelectedResume(resume.fullData || resume);
      setShowResumeModal(true);
    }
  }, [apiRequest]);

  // Check authentication on mount
  useEffect(() => {
    if (isTokenValid()) {
      setIsAuthenticated(true);
      loadDashboard();
    }
  }, [isTokenValid, loadDashboard]);

  // Analytics calculations
  const analyticsData = useMemo(() => {
    if (!dashboardData) return null;

    const totalScore = dashboardData.recentResumes.reduce((sum, resume) => sum + resume.score, 0);
    const avgScore = dashboardData.recentResumes.length > 0 ? totalScore / dashboardData.recentResumes.length : 0;
    
    const highScoreCount = dashboardData.recentResumes.filter(r => r.score >= 80).length;
    const mediumScoreCount = dashboardData.recentResumes.filter(r => r.score >= 60 && r.score < 80).length;
    const lowScoreCount = dashboardData.recentResumes.filter(r => r.score < 60).length;

    const contactStats = {
      email: dashboardData.recentResumes.filter(r => r.hasEmail).length,
      phone: dashboardData.recentResumes.filter(r => r.hasPhone).length,
      linkedin: dashboardData.recentResumes.filter(r => r.hasLinkedIn).length
    };

    return {
      avgScore,
      scoreDistribution: { high: highScoreCount, medium: mediumScoreCount, low: lowScoreCount },
      contactStats,
      totalAnalyzed: dashboardData.recentResumes.length
    };
  }, [dashboardData]);

  // Resume details renderer
  const renderResumeDetails = () => {
    if (!selectedResume) return null;
    
    const fileInfo = selectedResume.fileInfo || {};
    const analysis = selectedResume.analysis || {};
    const personalInfo = selectedResume.personalInfo || {};
    const preferences = selectedResume.preferences || {};
    const contactValidation = selectedResume.contactValidation || {};
    
    return (
      <div className="space-y-6">
        {/* Basic Information */}
        <div className="bg-gray-50 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center gap-2">
            <span>📄</span>
            Basic Information
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
            <p><strong>File:</strong> {cleanText(fileInfo.originalFileName || fileInfo.fileName || selectedResume.originalFileName || 'Unknown')}</p>
            <p><strong>Size:</strong> {((fileInfo.fileSize || selectedResume.fileSize || 0) / 1024).toFixed(2)} KB</p>
            <p><strong>Score:</strong> {selectedResume.score || analysis.overallScore || 0}/100</p>
            <p><strong>Uploaded:</strong> {new Date(selectedResume.uploadedAt || selectedResume.createdAt || Date.now()).toLocaleString()}</p>
            <p><strong>Pages:</strong> {selectedResume.pageCount || 1}</p>
            <p><strong>Words:</strong> {selectedResume.wordCount || 0}</p>
          </div>
        </div>

        {/* Personal Information */}
        <div className="bg-blue-50 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center gap-2">
            <span>👤</span>
            Personal Information
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
            <p><strong>Name:</strong> {cleanText(personalInfo.name || 'Not extracted')}</p>
            <p><strong>Email:</strong> {cleanText(personalInfo.email || 'Not found')}</p>
            <p><strong>Phone:</strong> {cleanText(personalInfo.phone || 'Not found')}</p>
            <p><strong>LinkedIn:</strong> {cleanText(personalInfo.linkedin || 'Not found')}</p>
            <p><strong>Address:</strong> {cleanText(personalInfo.address || 'Not found')}</p>
          </div>
        </div>

        {/* Analysis Results */}
        {(analysis.feedback || analysis.overallScore) && (
          <div className="bg-green-50 rounded-lg p-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center gap-2">
              <span>📊</span>
              Analysis Results
            </h3>
            <div className="space-y-4">
              {analysis.overallScore && (
                <p><strong>Overall Score:</strong> 
                  <span className="ml-2 px-3 py-1 bg-green-100 text-green-800 rounded-full text-sm font-medium">
                    {analysis.overallScore}/100
                  </span>
                </p>
              )}
              
              {analysis.feedback && (
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">🤖 AI Feedback:</h4>
                  <div className="bg-white p-3 rounded border text-sm">
                    {cleanText(analysis.feedback)}
                  </div>
                </div>
              )}

              {analysis.strengths && analysis.strengths.length > 0 && (
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">💪 Strengths:</h4>
                  <ul className="space-y-1 text-sm">
                    {analysis.strengths.map((strength: string, index: number) => (
                      <li key={index} className="flex items-start gap-2">
                        <span className="text-green-600">•</span>
                        <span>{cleanText(strength)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {analysis.weaknesses && analysis.weaknesses.length > 0 && (
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">⚠️ Areas for Improvement:</h4>
                  <ul className="space-y-1 text-sm">
                    {analysis.weaknesses.map((weakness: string, index: number) => (
                      <li key={index} className="flex items-start gap-2">
                        <span className="text-orange-600">•</span>
                        <span>{cleanText(weakness)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Contact Validation */}
        <div className="bg-yellow-50 rounded-lg p-4">
          <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center gap-2">
            <span>📞</span>
            Contact Information Status
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="flex items-center gap-2">
              <span className={`text-lg ${contactValidation.hasEmail || selectedResume.hasEmail ? 'text-green-500' : 'text-red-500'}`}>
                {contactValidation.hasEmail || selectedResume.hasEmail ? '✅' : '❌'}
              </span>
              <span className="text-sm">Email</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`text-lg ${contactValidation.hasPhone || selectedResume.hasPhone ? 'text-green-500' : 'text-red-500'}`}>
                {contactValidation.hasPhone || selectedResume.hasPhone ? '✅' : '❌'}
              </span>
              <span className="text-sm">Phone</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`text-lg ${contactValidation.hasLinkedIn || selectedResume.hasLinkedIn ? 'text-green-500' : 'text-red-500'}`}>
                {contactValidation.hasLinkedIn || selectedResume.hasLinkedIn ? '✅' : '❌'}
              </span>
              <span className="text-sm">LinkedIn</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`text-lg ${contactValidation.hasAddress ? 'text-green-500' : 'text-red-500'}`}>
                {contactValidation.hasAddress ? '✅' : '❌'}
              </span>
              <span className="text-sm">Address</span>
            </div>
          </div>
        </div>

        {/* User Preferences */}
        {Object.keys(preferences).length > 0 && (
          <div className="bg-indigo-50 rounded-lg p-4">
            <h3 className="text-lg font-semibold text-gray-900 mb-3 flex items-center gap-2">
              <span>⚙️</span>
              User Preferences
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
              <p><strong>Language:</strong> {preferences.language || selectedResume.language || 'N/A'}</p>
              <p><strong>Roast Level:</strong> {preferences.roastLevel || selectedResume.roastLevel || 'N/A'}</p>
              <p><strong>Roast Type:</strong> {preferences.roastType || selectedResume.roastType || 'N/A'}</p>
              <p><strong>Gender:</strong> {preferences.gender || 'N/A'}</p>
            </div>
          </div>
        )}
      </div>
    );
  };

  // Login UI
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-xl shadow-lg p-8 w-full max-w-md"
        >
          <div className="text-center mb-6">
            <div className="w-16 h-16 bg-gradient-to-br from-slate-700 to-slate-900 rounded-xl flex items-center justify-center mx-auto mb-4">
              <span className="text-white text-2xl">🛡️</span>
            </div>
            <h1 className="text-2xl font-bold text-gray-900">Admin Panel</h1>
            <p className="text-gray-600">CV Slayer Dashboard</p>
          </div>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <input
                type="email"
                placeholder="Email Address"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={loading}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-slate-500 focus:border-transparent transition-colors"
              />
            </div>
            
            <div>
              <input
                type="password"
                placeholder="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-slate-500 focus:border-transparent transition-colors"
              />
            </div>
            
            <motion.button
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
              type="submit" 
              disabled={loading || !email || !password}
              className="w-full bg-slate-900 text-white py-3 rounded-lg hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                    className="w-4 h-4 border-2 border-white border-t-transparent rounded-full"
                  />
                  Signing in...
                </>
              ) : (
                <>
                  <span>🔐</span>
                  Sign In
                </>
              )}
            </motion.button>
          </form>
        </motion.div>
      </div>
    );
  }

  // Main Admin UI
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Toast Container */}
      <div className="fixed top-4 right-4 z-50 space-y-2">
        <AnimatePresence>
          {toasts.map((toast) => (
            <motion.div
              key={toast.id}
              initial={{ opacity: 0, y: -50, scale: 0.9 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -50, scale: 0.9 }}
              className={`
                p-4 rounded-lg shadow-lg max-w-sm
                ${toast.type === 'success' ? 'bg-green-500 text-white' : ''}
                ${toast.type === 'error' ? 'bg-red-500 text-white' : ''}
                ${toast.type === 'warning' ? 'bg-yellow-500 text-white' : ''}
                ${toast.type === 'info' ? 'bg-blue-500 text-white' : ''}
              `}
            >
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <span>
                    {toast.type === 'success' && '✓'}
                    {toast.type === 'error' && '✕'}
                    {toast.type === 'warning' && '!'}
                    {toast.type === 'info' && 'i'}
                  </span>
                  {toast.message}
                </span>
                <button 
                  onClick={() => removeToast(toast.id)}
                  className="ml-2 text-white hover:text-gray-200"
                >
                  ×
                </button>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* Header */}
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-gradient-to-br from-slate-700 to-slate-900 rounded-lg flex items-center justify-center">
                <span className="text-white font-bold text-sm">📊</span>
              </div>
              <h1 className="text-xl font-bold text-gray-900">CV Slayer Admin</h1>
            </div>
            
            <div className="flex items-center gap-4">
              <nav className="flex gap-1">
                <button 
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    currentView === 'dashboard' 
                      ? 'bg-slate-100 text-slate-900' 
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
                  }`}
                  onClick={() => { setCurrentView('dashboard'); loadDashboard(); }}
                  disabled={loading}
                >
                  📈 Dashboard
                </button>
                <button 
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    currentView === 'resumes' 
                      ? 'bg-slate-100 text-slate-900' 
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
                  }`}
                  onClick={() => { setCurrentView('resumes'); loadResumes(); }}
                  disabled={loading}
                >
                  📄 Resumes ({resumes.length})
                </button>
                <button 
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                    currentView === 'analytics' 
                      ? 'bg-slate-100 text-slate-900' 
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
                  }`}
                  onClick={() => setCurrentView('analytics')}
                  disabled={loading}
                >
                  📊 Analytics
                </button>
              </nav>
              
              <button 
                onClick={handleLogout}
                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors text-sm flex items-center gap-2"
              >
                <span>🚪</span>
                Logout
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {loading && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-lg p-6 flex items-center gap-3">
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
                className="w-6 h-6 border-3 border-slate-300 border-t-slate-600 rounded-full"
              />
              <p className="text-gray-900">Loading...</p>
            </div>
          </div>
        )}

        {/* Dashboard View */}
        {currentView === 'dashboard' && !loading && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                    <span className="text-2xl">📄</span>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-gray-600">Total Resumes</h3>
                    <p className="text-2xl font-bold text-gray-900">{dashboardData?.totalResumes || 0}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                    <span className="text-2xl">📅</span>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-gray-600">Today's Uploads</h3>
                    <p className="text-2xl font-bold text-gray-900">{dashboardData?.todayResumes || 0}</p>
                  </div>
                </div>
              </div>
              
              <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 bg-yellow-100 rounded-lg flex items-center justify-center">
                    <span className="text-2xl">⭐</span>
                  </div>
                  <div>
                    <h3 className="text-sm font-medium text-gray-600">Average Score</h3>
                    <p className="text-2xl font-bold text-gray-900">{(dashboardData?.averageScore || 0).toFixed(1)}/100</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Recent Resumes */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="p-6 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">📋 Recent Resumes</h3>
              </div>
              <div className="p-6">
                {dashboardData?.recentResumes?.length > 0 ? (
                  <div className="space-y-3">
                    {dashboardData.recentResumes.slice(0, 10).map((resume, index) => (
                      <motion.div
                        key={resume.id || index}
                        whileHover={{ scale: 1.01 }}
                        onClick={() => handleResumeClick(resume)}
                        className="p-4 border border-gray-200 rounded-lg hover:border-gray-300 cursor-pointer transition-colors"
                      >
                        <div className="flex items-center justify-between">
                          <div>
                            <h4 className="font-medium text-gray-900">
                              {resume.personalInfo?.name || resume.displayName || resume.originalFileName || 'Unknown File'}
                            </h4>
                            <p className="text-sm text-gray-600">
                              <strong>Email:</strong> {resume.personalInfo?.email || 'Not found'}
                            </p>
                            <p className="text-sm text-gray-600">
                              Score: {resume.score || 0}/100 • {new Date(resume.uploadedAt).toLocaleDateString()}
                            </p>
                            <div className="flex gap-2 mt-2">
                              <span className={`text-xs px-2 py-1 rounded ${resume.hasEmail ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                📧 {resume.hasEmail ? '✓' : '✗'}
                              </span>
                              <span className={`text-xs px-2 py-1 rounded ${resume.hasPhone ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                📱 {resume.hasPhone ? '✓' : '✗'}
                              </span>
                              <span className={`text-xs px-2 py-1 rounded ${resume.hasLinkedIn ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                                💼 {resume.hasLinkedIn ? '✓' : '✗'}
                              </span>
                            </div>
                          </div>
                          <div className="flex items-center gap-3">
                            <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                              resume.score >= 80 ? 'bg-green-100 text-green-800' :
                              resume.score >= 60 ? 'bg-yellow-100 text-yellow-800' :
                              'bg-red-100 text-red-800'
                            }`}>
                              {resume.score}/100
                            </span>
                            <span className="text-gray-400">→</span>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <span className="text-4xl mb-2 block">📭</span>
                    <p className="text-gray-600">No resumes uploaded yet</p>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}

        {/* Resumes View */}
        {currentView === 'resumes' && !loading && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            <div className="bg-white rounded-xl shadow-sm border border-gray-200">
              <div className="p-6 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900">📄 All Resumes ({resumes.length})</h3>
              </div>
              <div className="p-6">
                {resumes.length > 0 ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {resumes.map((resume, index) => (
                      <motion.div
                        key={resume.id || index}
                        whileHover={{ scale: 1.02 }}
                        onClick={() => handleResumeClick(resume)}
                        className="p-4 border border-gray-200 rounded-lg hover:border-gray-300 cursor-pointer transition-colors"
                      >
                        <div className="flex items-start justify-between mb-3">
                          <h4 className="font-medium text-gray-900 truncate">
                            {(resume.personalInfo?.name || resume.displayName)?.length > 25 
                              ? (resume.personalInfo?.name || resume.displayName).substring(0, 25) + '...'
                              : (resume.personalInfo?.name || resume.displayName)
                            }
                          </h4>
                          <span className={`px-2 py-1 text-xs rounded-full font-medium ${
                            resume.score >= 80 ? 'bg-green-100 text-green-800' :
                            resume.score >= 60 ? 'bg-yellow-100 text-yellow-800' :
                            'bg-red-100 text-red-800'
                          }`}>
                            {resume.score}/100
                          </span>
                        </div>
                        
                        <div className="space-y-2 text-sm text-gray-600">
                          <p><strong>Name:</strong> {resume.personalInfo?.name || 'Not extracted'}</p>
                          <p><strong>Email:</strong> {resume.personalInfo?.email || 'Not found'}</p>
                          <p><strong>File:</strong> {resume.originalFileName}</p>
                          <p><strong>Size:</strong> {(resume.fileSize / 1024).toFixed(1)} KB</p>
                          <p><strong>Uploaded:</strong> {new Date(resume.uploadedAt).toLocaleDateString()}</p>
                          
                          <div className="flex gap-2 mt-3">
                            <span className={`text-xs px-2 py-1 rounded ${resume.hasEmail ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                              📧 {resume.hasEmail ? '✓' : '✗'}
                            </span>
                            <span className={`text-xs px-2 py-1 rounded ${resume.hasPhone ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                              📱 {resume.hasPhone ? '✓' : '✗'}
                            </span>
                            <span className={`text-xs px-2 py-1 rounded ${resume.hasLinkedIn ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                              💼 {resume.hasLinkedIn ? '✓' : '✗'}
                            </span>
                          </div>
                        </div>
                      </motion.div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-8">
                    <span className="text-4xl mb-2 block">📭</span>
                    <p className="text-gray-600">No resumes found</p>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}

        {/* Analytics View */}
        {currentView === 'analytics' && !loading && analyticsData && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-6"
          >
            {/* Score Distribution */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">📊 Score Distribution</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="text-center p-4 bg-green-50 rounded-lg">
                  <div className="text-2xl font-bold text-green-600">{analyticsData.scoreDistribution.high}</div>
                  <div className="text-sm text-gray-600">High Scores (80-100)</div>
                </div>
                <div className="text-center p-4 bg-yellow-50 rounded-lg">
                  <div className="text-2xl font-bold text-yellow-600">{analyticsData.scoreDistribution.medium}</div>
                  <div className="text-sm text-gray-600">Medium Scores (60-79)</div>
                </div>
                <div className="text-center p-4 bg-red-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{analyticsData.scoreDistribution.low}</div>
                  <div className="text-sm text-gray-600">Low Scores (0-59)</div>
                </div>
              </div>
            </div>

            {/* Contact Information Stats */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">📞 Contact Information Coverage</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="text-center p-4 bg-blue-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{analyticsData.contactStats.email}</div>
                  <div className="text-sm text-gray-600">Resumes with Email</div>
                  <div className="text-xs text-gray-500">
                    {analyticsData.totalAnalyzed > 0 ? ((analyticsData.contactStats.email / analyticsData.totalAnalyzed) * 100).toFixed(1) : 0}%
                  </div>
                </div>
                <div className="text-center p-4 bg-purple-50 rounded-lg">
                  <div className="text-2xl font-bold text-purple-600">{analyticsData.contactStats.phone}</div>
                  <div className="text-sm text-gray-600">Resumes with Phone</div>
                  <div className="text-xs text-gray-500">
                    {analyticsData.totalAnalyzed > 0 ? ((analyticsData.contactStats.phone / analyticsData.totalAnalyzed) * 100).toFixed(1) : 0}%
                  </div>
                </div>
                <div className="text-center p-4 bg-indigo-50 rounded-lg">
                  <div className="text-2xl font-bold text-indigo-600">{analyticsData.contactStats.linkedin}</div>
                  <div className="text-sm text-gray-600">Resumes with LinkedIn</div>
                  <div className="text-xs text-gray-500">
                    {analyticsData.totalAnalyzed > 0 ? ((analyticsData.contactStats.linkedin / analyticsData.totalAnalyzed) * 100).toFixed(1) : 0}%
                  </div>
                </div>
              </div>
            </div>

            {/* Overall Stats */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">📈 Overall Statistics</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <div className="text-3xl font-bold text-gray-900">{analyticsData.avgScore.toFixed(1)}/100</div>
                  <div className="text-sm text-gray-600">Average Resume Score</div>
                </div>
                <div>
                  <div className="text-3xl font-bold text-gray-900">{analyticsData.totalAnalyzed}</div>
                  <div className="text-sm text-gray-600">Total Resumes Analyzed</div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </main>

      {/* Resume Modal */}
      <AnimatePresence>
        {showResumeModal && selectedResume && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowResumeModal(false)}
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
          >
            <motion.div
  initial={{ scale: 0.9, opacity: 0 }}
  animate={{ scale: 1, opacity: 1 }}
  exit={{ scale: 0.9, opacity: 0 }}
  onClick={(e) => e.stopPropagation()}
  className="bg-white rounded-xl max-w-4xl w-full max-h-[90vh] overflow-hidden"
>
  <div className="flex items-center justify-between p-6 border-b border-gray-200">
    <h2 className="text-xl font-semibold text-gray-900">📄 Resume Details</h2>
    <button 
      className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
      onClick={() => setShowResumeModal(false)}
    >
      <span className="text-xl">×</span>
    </button>
  </div>
  <div className="p-6 overflow-y-auto max-h-[calc(90vh-120px)]">
    {renderResumeDetails()}
  </div>
</motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default AdminPage;