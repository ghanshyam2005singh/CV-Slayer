'use client';

import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface Improvement {
  priority: 'high' | 'medium' | 'low';
  title: string;
  description: string;
  example?: string;
}

interface Results {
  score: number;
  roastFeedback: string;
  improvements: Improvement[];
  strengths: string[];
  weaknesses: string[];
  originalFileName: string;
}

interface ResultsDisplayProps {
  results: Results;
  onReset: () => void;
}

interface Toast {
  id: number;
  message: string;
  type: 'success' | 'error' | 'warning' | 'info';
  duration: number;
}

const ResultsDisplay: React.FC<ResultsDisplayProps> = ({ results, onReset }) => {
  const [activeTab, setActiveTab] = useState<'feedback' | 'improvements' | 'analysis'>('feedback');
  const [isSharing, setIsSharing] = useState(false);
  const [isPrinting, setIsPrinting] = useState(false);
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  // Decode HTML entities safely
  const decodeHtmlEntities = useCallback((text: string): string => {
    if (typeof text !== 'string') return '';
    const txt = document.createElement('textarea');
    txt.innerHTML = text;
    return txt.value;
  }, []);

  // Score calculation with validation
  const sanitizedScore = useMemo(() => {
    if (!results?.score) return 0;
    const numScore = Number(results.score);
    return isNaN(numScore) ? 0 : Math.max(0, Math.min(100, Math.round(numScore)));
  }, [results]);

  // File name sanitization
  const sanitizedFileName = useMemo(() => {
    if (!results?.originalFileName) return 'Unknown File';
    const fileName = results.originalFileName;
    return fileName.length > 50 ? fileName.substring(0, 47) + '...' : fileName;
  }, [results]);

  // Validate improvements
  const validImprovements = useMemo(() => {
    if (!results?.improvements || !Array.isArray(results.improvements)) return [];
    
    return results.improvements
      .filter(imp => imp && typeof imp === 'object')
      .map(improvement => ({
        priority: (['high', 'medium', 'low'] as const).includes(improvement.priority) 
          ? improvement.priority 
          : 'medium' as const,
        title: typeof improvement.title === 'string' 
          ? improvement.title.replace(/[<>]/g, '').substring(0, 100) 
          : 'Improvement',
        description: typeof improvement.description === 'string' 
          ? improvement.description.replace(/[<>]/g, '').substring(0, 300) 
          : '',
        example: typeof improvement.example === 'string' 
          ? improvement.example.replace(/[<>]/g, '').substring(0, 200) 
          : ''
      }))
      .slice(0, 10);
  }, [results]);

  // Validate strengths and weaknesses
  const validStrengths = useMemo(() => {
    if (!results?.strengths || !Array.isArray(results.strengths)) return [];
    return results.strengths
      .filter(item => typeof item === 'string' && item.trim().length > 0)
      .map(item => item.replace(/[<>]/g, '').substring(0, 150))
      .slice(0, 8);
  }, [results]);

  const validWeaknesses = useMemo(() => {
    if (!results?.weaknesses || !Array.isArray(results.weaknesses)) return [];
    return results.weaknesses
      .filter(item => typeof item === 'string' && item.trim().length > 0)
      .map(item => item.replace(/[<>]/g, '').substring(0, 150))
      .slice(0, 8);
  }, [results]);

  // Toast management
  const addToast = useCallback((message: string, type: Toast['type'] = 'info', duration = 4000) => {
    const id = Date.now() + Math.random();
    const newToast: Toast = { id, message, type, duration };
    
    setToasts(prev => [...prev, newToast]);
    
    setTimeout(() => {
      setToasts(prev => prev.filter(toast => toast.id !== id));
    }, duration);
  }, []);

  const removeToast = useCallback((id: number) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  // Score utilities
  const getScoreColor = useCallback((score: number) => {
    if (score >= 80) return '#10b981'; // Emerald-500
    if (score >= 60) return '#f59e0b'; // Amber-500
    return '#ef4444'; // Red-500
  }, []);

  const getScoreLabel = useCallback((score: number) => {
    if (score >= 80) return 'Excellent';
    if (score >= 60) return 'Good';
    return 'Needs Work';
  }, []);

  // Copy to clipboard
  const copyToClipboard = useCallback(async (text: string) => {
    try {
      const sanitizedText = typeof text === 'string' ? text.substring(0, 1000) : '';
      
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(sanitizedText);
      } else {
        const textArea = document.createElement('textarea');
        textArea.value = sanitizedText;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
      }
      
      addToast('Copied to clipboard!', 'success');
    } catch (error) {
      addToast('Copy failed. Please select and copy manually.', 'error');
    }
  }, [addToast]);

  // Print functionality
  const handlePrint = useCallback(async () => {
    setIsPrinting(true);
    addToast('Preparing your report...', 'info');

    try {
      const printStyles = document.createElement('style');
      printStyles.textContent = `
        @media print {
          .no-print { display: none !important; }
          .print-only { display: block !important; }
          body { print-color-adjust: exact; }
          .results-container { box-shadow: none !important; margin: 0; }
        }
      `;
      document.head.appendChild(printStyles);

      await new Promise(resolve => setTimeout(resolve, 100));
      window.print();

      addToast('Report ready for download!', 'success');

      setTimeout(() => {
        if (document.head.contains(printStyles)) {
          document.head.removeChild(printStyles);
        }
      }, 1000);
    } catch (error) {
      addToast('Unable to generate report. Please try again.', 'error');
    } finally {
      setIsPrinting(false);
    }
  }, [addToast]);

  // Share functionality
  const handleShare = useCallback(async () => {
    setIsSharing(true);
    addToast('Preparing share content...', 'info');

    try {
      const shareData = {
        title: 'CV Slayer Results',
        text: `My resume scored ${sanitizedScore}/100 on CV Slayer! Get professional feedback on your resume too.`,
        url: window.location.origin
      };

      if (navigator.share && navigator.canShare?.(shareData)) {
        await navigator.share(shareData);
        addToast('Shared successfully!', 'success');
      } else {
        await copyToClipboard(shareData.text + ' ' + shareData.url);
        addToast('Share link copied to clipboard!', 'success');
      }
    } catch (error: any) {
      if (error.name === 'AbortError') {
        addToast('Share cancelled', 'info', 2000);
        return;
      }
      addToast('Share failed. Content copied to clipboard instead.', 'warning');
      await copyToClipboard(`My resume scored ${sanitizedScore}/100 on CV Slayer! ${window.location.origin}`);
    } finally {
      setIsSharing(false);
    }
  }, [sanitizedScore, copyToClipboard, addToast]);

  // Sanitize text content
  const sanitizeText = useCallback((text: string) => {
    if (typeof text !== 'string') return [];
    return text
      .replace(/[<>]/g, '')
      .substring(0, 2000)
      .split('\n')
      .filter(line => line.trim().length > 0)
      .slice(0, 50);
  }, []);

  if (!results) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
        <div className="text-center">
          <div className="text-6xl mb-4">📄</div>
          <h3 className="text-xl font-semibold text-gray-900 mb-2">No Results Available</h3>
          <p className="text-gray-600 mb-4">The analysis results could not be loaded.</p>
          <button 
            onClick={onReset}
            className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Toast Container */}
      <div className="fixed top-4 right-4 z-50 space-y-2 no-print">
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

      {/* Confirmation Dialog */}
      <AnimatePresence>
        {showResetConfirm && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4 no-print"
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="bg-white rounded-xl p-6 max-w-md w-full"
            >
              <h3 className="text-lg font-semibold mb-4">Start New Analysis?</h3>
              <p className="text-gray-600 mb-6">
                This will clear your current results and start a new resume analysis.
              </p>
              <div className="flex gap-3">
                <button
                  onClick={() => setShowResetConfirm(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    setShowResetConfirm(false);
                    onReset();
                  }}
                  className="flex-1 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
                >
                  Yes, Start New
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="max-w-4xl mx-auto p-4 pt-8">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6"
        >
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 mb-2">Resume Analysis Complete</h1>
              <p className="text-gray-600">Analysis for: <span className="font-medium">{sanitizedFileName}</span></p>
            </div>
            <button
              onClick={() => setShowResetConfirm(true)}
              className="no-print px-4 py-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors flex items-center gap-2"
            >
              <span className="text-lg">🔄</span>
              New Analysis
            </button>
          </div>
        </motion.div>

        {/* Score Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-6"
        >
          <div className="flex items-center gap-8">
            <div className="relative">
              <div 
                className="w-32 h-32 rounded-full border-8 flex items-center justify-center"
                style={{ borderColor: getScoreColor(sanitizedScore) }}
              >
                <div className="text-center">
                  <div 
                    className="text-3xl font-bold"
                    style={{ color: getScoreColor(sanitizedScore) }}
                  >
                    {sanitizedScore}
                  </div>
                  <div className="text-sm text-gray-500">/ 100</div>
                </div>
              </div>
            </div>
            <div className="flex-1">
              <h2 className="text-xl font-semibold text-gray-900 mb-2">
                Overall Resume Score
              </h2>
              <div 
                className="inline-block px-3 py-1 rounded-full text-sm font-medium text-white mb-3"
                style={{ backgroundColor: getScoreColor(sanitizedScore) }}
              >
                {getScoreLabel(sanitizedScore)}
              </div>
              <div className="bg-gray-200 rounded-full h-3 mb-2">
                <div 
                  className="h-3 rounded-full transition-all duration-1000"
                  style={{ 
                    width: `${sanitizedScore}%`,
                    backgroundColor: getScoreColor(sanitizedScore)
                  }}
                />
              </div>
              <p className="text-gray-600">
                {sanitizedScore >= 80 && "Outstanding resume! You're ready to impress employers."}
                {sanitizedScore >= 60 && sanitizedScore < 80 && "Good foundation with room for strategic improvements."}
                {sanitizedScore < 60 && "Let's transform your resume into a powerful tool."}
              </p>
            </div>
          </div>
        </motion.div>

        {/* Tabs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden"
        >
          <div className="border-b border-gray-200">
            <nav className="flex">
              {[
                { id: 'feedback', label: 'Feedback', icon: '🔥' },
                { id: 'improvements', label: 'Improvements', icon: '💡', count: validImprovements.length },
                { id: 'analysis', label: 'Analysis', icon: '📊' }
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`
                    px-6 py-4 flex items-center gap-2 font-medium transition-colors
                    ${activeTab === tab.id 
                      ? 'text-blue-600 border-b-2 border-blue-600 bg-blue-50' 
                      : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
                    }
                  `}
                >
                  <span>{tab.icon}</span>
                  <span>{tab.label}</span>
                  {tab.count !== undefined && (
                    <span className="bg-gray-200 text-gray-700 text-xs px-2 py-1 rounded-full">
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </nav>
          </div>

          <div className="p-6">
            <AnimatePresence mode="wait">
              {activeTab === 'feedback' && (
                <motion.div
                  key="feedback"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="space-y-4"
                >
                  <div className="flex items-center justify-between">
                    <h3 className="text-lg font-semibold text-gray-900">Professional Feedback</h3>
                    <button
                      onClick={() => copyToClipboard(results.roastFeedback)}
                      className="no-print px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors flex items-center gap-2"
                    >
                      <span>📋</span>
                      Copy
                    </button>
                  </div>
                  <div className="prose max-w-none">
                    {sanitizeText(decodeHtmlEntities(results.roastFeedback)).map((paragraph, index) => (
                      <p key={index} className="text-gray-700 leading-relaxed mb-4">
                        {paragraph}
                      </p>
                    ))}
                  </div>
                </motion.div>
              )}

              {activeTab === 'improvements' && (
                <motion.div
                  key="improvements"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="space-y-4"
                >
                  <h3 className="text-lg font-semibold text-gray-900">Improvement Suggestions</h3>
                  {validImprovements.length > 0 ? (
                    <div className="space-y-4">
                      {validImprovements.map((improvement, index) => (
                        <div
                          key={index}
                          className={`
                            p-4 rounded-lg border-l-4
                            ${improvement.priority === 'high' ? 'border-red-500 bg-red-50' : ''}
                            ${improvement.priority === 'medium' ? 'border-yellow-500 bg-yellow-50' : ''}
                            ${improvement.priority === 'low' ? 'border-green-500 bg-green-50' : ''}
                          `}
                        >
                          <div className="flex items-center gap-2 mb-2">
                            <span>
                              {improvement.priority === 'high' && '🔴'}
                              {improvement.priority === 'medium' && '🟡'}
                              {improvement.priority === 'low' && '🟢'}
                            </span>
                            <span className="text-sm font-medium text-gray-600 uppercase">
                              {improvement.priority} Priority
                            </span>
                          </div>
                          <h4 className="font-semibold text-gray-900 mb-2">
                            {decodeHtmlEntities(improvement.title)}
                          </h4>
                          <p className="text-gray-700 mb-3">
                            {decodeHtmlEntities(improvement.description)}
                          </p>
                          {improvement.example && (
                            <div className="bg-white p-3 rounded border">
                              <strong className="text-sm text-gray-600">Example:</strong>
                              <p className="text-gray-700 mt-1">
                                {decodeHtmlEntities(improvement.example)}
                              </p>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <span className="text-4xl mb-2 block">✨</span>
                      <p className="text-gray-600">No specific improvements identified. Your resume looks good!</p>
                    </div>
                  )}
                </motion.div>
              )}

              {activeTab === 'analysis' && (
                <motion.div
                  key="analysis"
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="space-y-6"
                >
                  <h3 className="text-lg font-semibold text-gray-900">Detailed Analysis</h3>
                  <div className="grid md:grid-cols-2 gap-6">
                    <div className="bg-green-50 rounded-lg p-4">
                      <h4 className="font-semibold text-green-900 mb-3 flex items-center gap-2">
                        <span>✅</span>
                        Strengths ({validStrengths.length})
                      </h4>
                      {validStrengths.length > 0 ? (
                        <ul className="space-y-2">
                          {validStrengths.map((strength, index) => (
                            <li key={index} className="flex items-start gap-2 text-green-800">
                              <span className="text-green-600 mt-1">•</span>
                              <span>{decodeHtmlEntities(strength)}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-green-700">No specific strengths identified.</p>
                      )}
                    </div>

                    <div className="bg-blue-50 rounded-lg p-4">
                      <h4 className="font-semibold text-blue-900 mb-3 flex items-center gap-2">
                        <span>🎯</span>
                        Areas to Improve ({validWeaknesses.length})
                      </h4>
                      {validWeaknesses.length > 0 ? (
                        <ul className="space-y-2">
                          {validWeaknesses.map((weakness, index) => (
                            <li key={index} className="flex items-start gap-2 text-blue-800">
                              <span className="text-blue-600 mt-1">•</span>
                              <span>{decodeHtmlEntities(weakness)}</span>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-blue-700">No specific areas for improvement identified.</p>
                      )}
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

        {/* Action Buttons */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="flex gap-4 mt-6 no-print"
        >
          <button
            onClick={handlePrint}
            disabled={isPrinting}
            className="flex-1 bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
          >
            <span>📄</span>
            {isPrinting ? 'Preparing...' : 'Download Report'}
          </button>
          <button
            onClick={handleShare}
            disabled={isSharing}
            className="flex-1 bg-gray-600 text-white px-6 py-3 rounded-lg hover:bg-gray-700 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
          >
            <span>📤</span>
            {isSharing ? 'Sharing...' : 'Share Results'}
          </button>
        </motion.div>
      </div>
    </div>
  );
};

export default ResultsDisplay;