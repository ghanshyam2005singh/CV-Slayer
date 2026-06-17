import React, { useState, useCallback, useMemo, useEffect, useRef } from 'react';
import './App.css';
import Navbar from './components/Navbar';
import ResultsDisplay from './components/ResultsDisplay';
import AdminPanel from './components/AdminPanel';

// Simple Error Boundary
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="error-boundary">
          <div className="error-content">
            <div className="error-icon">⚠️</div>
            <h2>Something went wrong</h2>
            <p>Please refresh the page and try again.</p>
            <button onClick={() => window.location.reload()} className="error-reload-btn">
              🔄 Reload Page
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [results, setResults] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [agreedToTerms, setAgreedToTerms] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);
  const [loadingStep, setLoadingStep] = useState('');
  const [roastMsgIndex, setRoastMsgIndex] = useState(0);
  const [terminalLines, setTerminalLines] = useState([]);
  const roastIntervalRef = useRef(null);
  const terminalIntervalRef = useRef(null);

  const roastMessages = [
    "Found 'team player' written 3 times. Interesting strategy.",
    "Scanning for actual numbers in your achievements...",
    "Detected buzzword cluster in skills section.",
    "Cross-referencing with 10,000 real resumes...",
    "Checking if your job titles match your bullets...",
    "Your 'Excel expert' claim is under careful review.",
    "Counting how many times you said 'passionate'...",
    "Looking for that projects section... still looking...",
    "ATS compatibility check in progress. Praying for you.",
    "Found generic objective statement. Adding to evidence pile.",
    "Verifying your '5+ years of experience' claim...",
    "Evaluating damage to career prospects. Stay calm.",
  ];

  const terminalSteps = {
    uploading: [
      '> Receiving resume file...',
      '> File format: valid ✓',
      '> Extracting text content...',
    ],
    analyzing: [
      '> Parsing sections: Experience, Skills, Education...',
      '> Running ATS compatibility check...',
      '> Detecting buzzwords and filler phrases...',
      '> Comparing against job market data...',
      '> Checking quantifiable achievements...',
    ],
    processing: [
      '> Scoring content quality...',
      '> Generating improvement suggestions...',
      '> Crafting your personalized roast...',
      '> Compiling final report...',
    ],
    complete: [
      '> Analysis complete ✓',
    ],
  };

  useEffect(() => {
    if (!isLoading) {
      clearInterval(roastIntervalRef.current);
      clearInterval(terminalIntervalRef.current);
      setRoastMsgIndex(0);
      setTerminalLines([]);
      return;
    }

    roastIntervalRef.current = setInterval(() => {
      setRoastMsgIndex(i => (i + 1) % roastMessages.length);
    }, 2800);

    return () => {
      clearInterval(roastIntervalRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLoading]);

  useEffect(() => {
    if (!isLoading || !loadingStep) return;
    const lines = terminalSteps[loadingStep] || [];
    setTerminalLines([]);
    let i = 0;
    terminalIntervalRef.current = setInterval(() => {
      if (i < lines.length) {
        setTerminalLines(prev => [...prev, lines[i]]);
        i++;
      } else {
        clearInterval(terminalIntervalRef.current);
      }
    }, 600);
    return () => clearInterval(terminalIntervalRef.current);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loadingStep, isLoading]);

  const [formData, setFormData] = useState({
    gender: 'male',
    roastLevel: 'pyar',
    roastType: 'funny',
    language: 'english'
  });

  // Simple API config
  const API_CONFIG = useMemo(() => ({
    baseURL: process.env.NODE_ENV === 'production' 
      ? process.env.REACT_APP_API_URL || 'https://cv-slayer.onrender.com'
      : 'http://localhost:5000',
    timeout: 120000,
    maxFileSize: 10 * 1024 * 1024
  }), []);

  // Simple file validation
  const validateFile = useCallback((file) => {
    if (!file) return 'Please select a resume file';
    
    const allowedTypes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/msword'];
    if (!allowedTypes.includes(file.type)) {
      return 'Please upload PDF or Word documents only';
    }
    
    if (file.size > API_CONFIG.maxFileSize) {
      return 'File too large (max 10MB)';
    }
    
    return null;
  }, [API_CONFIG.maxFileSize]);

  // Simple file handler
  const handleFileChange = useCallback((e) => {
    const file = e.target.files[0];
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

  // Simple input handler
  const handleInputChange = useCallback((e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  }, []);

  // Simple reset
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
    
    const fileInput = document.getElementById('resumeFile');
    if (fileInput) fileInput.value = '';
  }, []);

  // Push history when results load so browser back button works
  useEffect(() => {
    if (results) {
      window.history.pushState({ resultsPage: true }, '');
      const handlePop = () => handleReset();
      window.addEventListener('popstate', handlePop);
      return () => window.removeEventListener('popstate', handlePop);
    }
  }, [results, handleReset]);

  // Simple submit handler
  const handleSubmit = useCallback(async (e) => {
    e.preventDefault();
    
    if (!agreedToTerms) {
      setError('Please accept the Terms & Conditions');
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

    try {
      const formDataToSend = new FormData();
      formDataToSend.append('resume', selectedFile);
      formDataToSend.append('gender', formData.gender);
      formDataToSend.append('roastLevel', formData.roastLevel);
      formDataToSend.append('roastType', formData.roastType);
      formDataToSend.append('language', formData.language);
      formDataToSend.append('consentGiven', 'true');

      setLoadingStep('analyzing');

      const response = await fetch(`${API_CONFIG.baseURL}/api/resume/analyze`, {
        method: 'POST',
        body: formDataToSend
      });

      setLoadingStep('processing');

      if (!response.ok) {
        throw new Error(`Error ${response.status}: Please try again`);
      }

      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.error?.message || 'Analysis failed');
      }

      const processedData = result.data || result;
      
      const finalResults = {
        ...processedData,
        originalFileName: selectedFile.name,
        score: Number(processedData.score) || 0,
        roastFeedback: processedData.roastFeedback || '',
        improvements: processedData.improvements || [],
        strengths: processedData.strengths || [],
        weaknesses: processedData.weaknesses || []
      };

      setLoadingStep('complete');
      setTimeout(() => {
        setResults(finalResults);
        setIsLoading(false);
        setLoadingStep('');
      }, 1000);

    } catch (error) {
      console.error('Submit error:', error);
      setError(error.message || 'An error occurred. Please try again');
      setIsLoading(false);
      setLoadingStep('');
    }
  }, [selectedFile, formData, agreedToTerms, validateFile, API_CONFIG.baseURL]);

  // Admin route check
  if (window.location.pathname.startsWith('/admin')) {
    return (
      <ErrorBoundary>
        <AdminPanel />
      </ErrorBoundary>
    );
  }

  if (results) {
    return (
      <ErrorBoundary>
        <div className="app">
          <Navbar onNavClick={handleReset} />
          <main>
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
        uploading: 'Uploading your resume...',
        analyzing: 'AI is analyzing your resume...',
        processing: 'Generating feedback...',
        complete: 'Analysis complete!'
      };
      return messages[loadingStep] || 'Processing...';
    };

    const getProgressPercentage = () => {
      const percentages = { uploading: 25, analyzing: 50, processing: 75, complete: 100 };
      return percentages[loadingStep] || 0;
    };

    return (
      <ErrorBoundary>
        <div className="app">
          <Navbar />
          <main className="loading-container">
            <div className="loading-wrapper">

              {/* Header */}
              <div className="loading-header">
                <div className="loading-badge">Analyzing</div>
                <h2 className="loading-title">{getLoadingMessage()}</h2>
                <p className="loading-filename">📄 {selectedFile?.name}</p>
              </div>

              {/* Progress bar */}
              <div className="loading-progress-wrap">
                <div className="loading-progress-track">
                  <div
                    className="loading-progress-fill"
                    style={{ width: `${getProgressPercentage()}%` }}
                  />
                </div>
                <span className="loading-pct">{getProgressPercentage()}%</span>
              </div>

              {/* Step pills */}
              <div className="loading-steps-row">
                {['uploading','analyzing','processing','complete'].map((step, i) => {
                  const pct = getProgressPercentage();
                  const thresholds = { uploading: 25, analyzing: 50, processing: 75, complete: 100 };
                  const done = pct >= thresholds[step];
                  const active = loadingStep === step;
                  return (
                    <div key={step} className={`loading-step-pill ${active ? 'active' : ''} ${done ? 'done' : ''}`}>
                      <span className="pill-dot">{done && !active ? '✓' : i + 1}</span>
                      <span className="pill-label">{step.charAt(0).toUpperCase() + step.slice(1)}</span>
                    </div>
                  );
                })}
              </div>

              {/* Terminal */}
              <div className="loading-terminal">
                <div className="terminal-bar">
                  <span className="t-dot red"></span>
                  <span className="t-dot yellow"></span>
                  <span className="t-dot green"></span>
                  <span className="terminal-title">cv-slayer — analyzing</span>
                </div>
                <div className="terminal-body">
                  {terminalLines.map((line, i) => (
                    <div key={i} className="terminal-line">
                      <span className="terminal-prompt">$</span> {line}
                    </div>
                  ))}
                  <div className="terminal-cursor">█</div>
                </div>
              </div>

              {/* Rotating roast thought */}
              <div className="loading-thought">
                <span className="thought-label">AI is thinking:</span>
                <span className="thought-text" key={roastMsgIndex}>
                  "{roastMessages[roastMsgIndex]}"
                </span>
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
      <div className="app">
        <Navbar />
        
        {/* Hero Section */}
        <section id="home" className="hero">
          <div className="hero-background">
            <div className="hero-pattern"></div>
          </div>
          <div className="container">
            <div className="hero-content">
              <div className="hero-text">
                <h1 className="hero-title">
                  <span className="title-main">CV Slayer</span>
                  <span className="title-sub">Resume Roaster</span>
                </h1>
                <p className="hero-subtitle">
                  Your resume probably isn't as strong as you think. Get honest, brutally useful feedback — with a touch of humor if you want it.
                </p>
                <div className="hero-features">
                  <div className="feature-tag">AI-Powered</div>
                  <div className="feature-tag">Multiple Styles</div>
                  <div className="feature-tag">Hindi / Hinglish</div>
                </div>
                <a href="#upload" className="cta-button">
                  <span>Roast My Resume</span>
                  <div className="cta-icon">→</div>
                </a>
              </div>
              <div className="hero-visual">
                <div className="floating-elements">
                  <div className="hero-score-preview">
                    <div className="hero-score-number">64</div>
                    <div className="hero-score-label">Resume Score</div>
                    <div className="hero-score-bars">
                      <div className="hero-bar"><div className="hero-bar-fill" style={{width:'72%'}}></div></div>
                      <div className="hero-bar"><div className="hero-bar-fill" style={{width:'45%'}}></div></div>
                      <div className="hero-bar"><div className="hero-bar-fill" style={{width:'88%'}}></div></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Features Section */}
        <section id="features" className="features">
          <div className="container">
            <div className="section-header">
              <h2>What you actually get</h2>
              <p>No generic tips. Real feedback that helps you land interviews.</p>
            </div>
            <div className="features-grid">
              <div className="feature-card">
                <div className="feature-icon">🔍</div>
                <h3>Deep Analysis</h3>
                <p>Content, structure, ATS compatibility — checked line by line</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">🎯</div>
                <h3>Your style, your call</h3>
                <p>Gentle nudge or brutal roast — pick the feedback that actually motivates you</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">🌐</div>
                <h3>English, Hindi, Hinglish</h3>
                <p>Read feedback in the language you think in</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">📝</div>
                <h3>Specific suggestions</h3>
                <p>Not "improve your summary" — actual rewrite examples you can use</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">⚡</div>
                <h3>Fast turnaround</h3>
                <p>Upload, wait about 30 seconds, get your results</p>
              </div>
              <div className="feature-card">
                <div className="feature-icon">🗑️</div>
                <h3>No data stored</h3>
                <p>Your resume is deleted right after analysis. No accounts needed.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Upload Section */}
        <section id="upload" className="upload-section">
          <div className="container">
            <div className="section-header">
              <h2>Upload your resume</h2>
              <p>PDF or Word doc. Takes about 30 seconds.</p>
            </div>
            <div className="upload-wrapper">
              {error && (
                <div className="error-alert" role="alert">
                  <div className="error-content">
                    <span className="error-icon">⚠️</span>
                    <span className="error-text">{error}</span>
                    <button 
                      className="error-close"
                      onClick={() => setError('')}
                    >
                      ×
                    </button>
                  </div>
                </div>
              )}
              
              <form onSubmit={handleSubmit} className="upload-form">
                <div className="file-upload-section">
                  <label htmlFor="resumeFile" className="file-upload-label">
                    <div className="file-upload-area">
                      <div className="file-icon">📄</div>
                      <div className="file-text">
                        <span className="file-primary">
                          {selectedFile ? selectedFile.name : "Choose your resume"}
                        </span>
                        <span className="file-secondary">
                          PDF, DOC, DOCX up to 10MB
                        </span>
                      </div>
                      <div className="file-button">Browse</div>
                    </div>
                  </label>
                  <input 
                    type="file" 
                    id="resumeFile" 
                    accept=".pdf,.docx,.doc"
                    onChange={handleFileChange}
                    disabled={isLoading}
                    required
                  />
                </div>

                <div className="form-options">
                  <div className="option-group">
                    <label>Gender</label>
                    <div className="select-wrapper">
                      <select 
                        name="gender" 
                        value={formData.gender} 
                        onChange={handleInputChange}
                        disabled={isLoading}
                      >
                        <option value="male">Male</option>
                        <option value="female">Female</option>
                        <option value="other">Other/Neutral</option>
                      </select>
                    </div>
                  </div>

                  <div className="option-group">
                    <label>Roast Level</label>
                    <div className="select-wrapper">
                      <select 
                        name="roastLevel" 
                        value={formData.roastLevel} 
                        onChange={handleInputChange}
                        disabled={isLoading}
                      >
                        <option value="pyar">😊 Gentle</option>
                        <option value="ache">🤔 Balanced</option>
                        <option value="dhang">😈 Savage</option>
                      </select>
                    </div>
                  </div>

                  <div className="option-group">
                    <label>Style</label>
                    <div className="select-wrapper">
                      <select 
                        name="roastType" 
                        value={formData.roastType} 
                        onChange={handleInputChange}
                        disabled={isLoading}
                      >
                        <option value="funny">😄 Funny</option>
                        <option value="serious">🎯 Professional</option>
                        <option value="sarcastic">😏 Sarcastic</option>
                        <option value="motivational">💪 Motivational</option>
                      </select>
                    </div>
                  </div>

                  <div className="option-group">
                    <label>Language</label>
                    <div className="select-wrapper">
                      <select 
                        name="language" 
                        value={formData.language} 
                        onChange={handleInputChange}
                        disabled={isLoading}
                      >
                        <option value="english">🇺🇸 English</option>
                        <option value="hindi">🇮🇳 Hindi</option>
                        <option value="hinglish">🌍 Hinglish</option>
                      </select>
                    </div>
                  </div>
                </div>

                <div className="terms-section">
                  <label className="terms-checkbox">
                    <input 
                      type="checkbox" 
                      checked={agreedToTerms}
                      onChange={(e) => setAgreedToTerms(e.target.checked)}
                      disabled={isLoading}
                      required
                    />
                    <span className="checkmark"></span>
                    <span className="terms-text">
                      I agree to the{' '}
                      <button 
                        type="button" 
                        className="terms-link"
                        onClick={() => setShowTermsModal(true)}
                      >
                        Terms of Service & Privacy Policy
                      </button>
                    </span>
                  </label>
                </div>

                <button 
                  type="submit" 
                  className="submit-button"
                  disabled={!selectedFile || !agreedToTerms || isLoading}
                >
                  <span>{isLoading ? 'Analyzing...' : 'Roast My Resume'}</span>
                </button>
              </form>
            </div>
          </div>
        </section>

        {/* Terms Modal */}
        {showTermsModal && (
          <div className="modal-overlay" onClick={() => setShowTermsModal(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>Terms of Service & Privacy Policy</h3>
                <button 
                  className="modal-close"
                  onClick={() => setShowTermsModal(false)}
                >
                  ×
                </button>
              </div>
              
              <div className="modal-body">
                <div className="terms-content">
                  <section>
                    <h4>🔐 Privacy & Data</h4>
                    <p>Your resume is processed temporarily for analysis. Files are deleted after processing.</p>
                  </section>

                  <section>
                    <h4>🤖 AI Analysis</h4>
                    <p>We use AI to analyze your resume and provide feedback.</p>
                  </section>
                </div>
              </div>
              
              <div className="modal-footer">
                <button 
                  className="btn-secondary"
                  onClick={() => setShowTermsModal(false)}
                >
                  Close
                </button>
                <button 
                  className="btn-primary"
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
        <section className="how-it-works">
          <div className="container">
            <div className="section-header">
              <h2>How it works</h2>
              <p>Four steps, no signup, no credit card.</p>
            </div>
            <div className="steps-grid">
              <div className="step-card">
                <div className="step-number">1</div>
                <h3>Upload</h3>
                <p>Drop your PDF or Word doc</p>
              </div>
              <div className="step-card">
                <div className="step-number">2</div>
                <h3>Customize</h3>
                <p>Pick your roast level and language</p>
              </div>
              <div className="step-card">
                <div className="step-number">3</div>
                <h3>Wait ~30s</h3>
                <p>AI reads every section of your resume</p>
              </div>
              <div className="step-card">
                <div className="step-number">4</div>
                <h3>Read & fix</h3>
                <p>Get a score, roast, and exact improvements</p>
              </div>
            </div>
          </div>
        </section>

        {/* Sample Results */}
        <section id="examples" className="sample-results">
          <div className="container">
            <div className="section-header">
              <h2>What the feedback looks like</h2>
              <p>Real examples from different roast styles.</p>
            </div>
            <div className="samples-grid">
              <div className="sample-card funny">
                <div className="sample-header">
                  <span className="sample-type">Funny · Gentle</span>
                  <span className="sample-level">Score: 72</span>
                </div>
                <blockquote>
                  "You wrote 'Excel expert' on your resume but I have a feeling you still Google 'how to freeze a row.' Your objective section is three lines of corporate jargon that says absolutely nothing. Let's fix that."
                </blockquote>
              </div>

              <div className="sample-card savage">
                <div className="sample-header">
                  <span className="sample-type">Sarcastic · Savage</span>
                  <span className="sample-level">Score: 41</span>
                </div>
                <blockquote>
                  "Ah yes, 'responsible for driving synergies across cross-functional teams.' What does that mean? Nobody knows, including you. This reads like a LinkedIn post from 2017. Your projects section is empty. That's the most honest thing on this page."
                </blockquote>
              </div>
            </div>
          </div>
        </section>

        {/* Footer */}
        <footer id="contact" className="footer">
          <div className="container">
            <div className="footer-content">
              <div className="footer-section">
                <h3>CV Slayer</h3>
                <p>Making resumes better, one roast at a time.</p>
              </div>
              <div className="footer-section">
                <h4>Contact</h4>
                <p>Ghanshyam Singh</p>
                <p><a href='https://ghanshyamsingh-dev.vercel.app/' target="_blank" rel="noopener noreferrer">Portfolio</a></p>
              </div>
            </div>
            <div className="footer-bottom">
              <p>&copy; 2026 Ghanshyam Singh. All rights reserved.</p>
            </div>
          </div>
        </footer>
      </div>
    </ErrorBoundary>
  );
}

export default App;