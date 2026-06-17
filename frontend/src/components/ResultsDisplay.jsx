import React, { useState, useCallback, useMemo } from 'react';
import './ResultsDisplay.css';

const ResultsDisplay = ({ results, onReset }) => {
  const [activeTab, setActiveTab] = useState('roast');
  const [showResetConfirm, setShowResetConfirm] = useState(false);

  // Simple decode function
  function decodeHtmlEntities(text) {
    const txt = document.createElement('textarea');
    txt.innerHTML = text;
    return txt.value;
  }

  // Simple score calculation
  const sanitizedScore = useMemo(() => {
    if (!results || !results.score) return 0;
    const numScore = Number(results.score);
    return isNaN(numScore) ? 0 : Math.max(0, Math.min(100, Math.round(numScore)));
  }, [results]);

  // Simple file name
  const sanitizedFileName = useMemo(() => {
    if (!results || !results.originalFileName) return 'Unknown File';
    const fileName = results.originalFileName;
    if (typeof fileName !== 'string') return 'Unknown File';
    return fileName.length > 50 ? 
      fileName.substring(0, 47) + '...' : 
      fileName;
  }, [results]);

  // Simple improvements validation
  const validImprovements = useMemo(() => {
    if (!results || !Array.isArray(results.improvements)) return [];
    
    return results.improvements
      .filter(imp => imp && typeof imp === 'object')
      .map(improvement => ({
        priority: ['high', 'medium', 'low'].includes(improvement.priority) 
          ? improvement.priority 
          : 'medium',
        title: typeof improvement.title === 'string' 
          ? improvement.title.substring(0, 100) 
          : 'Improvement',
        description: typeof improvement.description === 'string' 
          ? improvement.description.substring(0, 300) 
          : '',
        example: typeof improvement.example === 'string' 
          ? improvement.example.substring(0, 200) 
          : ''
      }))
      .slice(0, 10);
  }, [results]);

  // Simple strengths/weaknesses
  const validStrengths = useMemo(() => {
    if (!results || !Array.isArray(results.strengths)) return [];
    return results.strengths
      .filter(item => typeof item === 'string' && item.trim().length > 0)
      .map(item => item.substring(0, 150))
      .slice(0, 8);
  }, [results]);

  const validWeaknesses = useMemo(() => {
    if (!results || !Array.isArray(results.weaknesses)) return [];
    return results.weaknesses
      .filter(item => typeof item === 'string' && item.trim().length > 0)
      .map(item => item.substring(0, 150))
      .slice(0, 8);
  }, [results]);

  // Simple score utilities
  const getScoreColor = useCallback((score) => {
    const validScore = Number(score) || 0;
    if (validScore >= 80) return '#2ecc71';
    if (validScore >= 60) return '#f39c12';
    return '#e74c3c';
  }, []);

  const getScoreEmoji = useCallback((score) => {
    const validScore = Number(score) || 0;
    if (validScore >= 80) return '🎯';
    if (validScore >= 60) return '👍';
    return '💪';
  }, []);

  const getScoreDescription = useCallback((score) => {
    const validScore = Number(score) || 0;
    if (validScore >= 80) return "Outstanding resume! You're ready to impress employers.";
    if (validScore >= 60) return "Good foundation with room for strategic improvements.";
    return "Let's transform your resume into a powerful tool.";
  }, []);

  // Simple tab change
  const handleTabChange = useCallback((tabName) => {
    const validTabs = ['roast', 'improvements', 'analysis'];
    if (validTabs.includes(tabName)) {
      setActiveTab(tabName);
    }
  }, []);

  // Simple print
  const handlePrint = useCallback(() => {
    window.print();
  }, []);

  // Simple copy
  const copyToClipboard = useCallback(async (text) => {
    try {
      const sanitizedText = typeof text === 'string' ? text.substring(0, 1000) : '';
      
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(sanitizedText);
        alert('Copied to clipboard!');
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
        alert('Copied to clipboard!');
      }
    } catch (error) {
      alert('Copy failed. Please select and copy manually.');
    }
  }, []);

  // Simple reset handlers
  const handleResetRequest = useCallback(() => {
    setShowResetConfirm(true);
  }, []);

  const handleResetConfirm = useCallback(() => {
    setShowResetConfirm(false);
    onReset();
  }, [onReset]);

  const handleResetCancel = useCallback(() => {
    setShowResetConfirm(false);
  }, []);

  // Simple share
  const handleShare = useCallback(async () => {
    try {
      const shareData = {
        title: 'CV Slayer Results',
        text: `My resume scored ${sanitizedScore}/100 on CV Slayer! Get professional feedback on your resume too.`,
        url: window.location.origin
      };

      if (navigator.share) {
        await navigator.share(shareData);
      } else {
        await copyToClipboard(shareData.text + ' ' + shareData.url);
      }
    } catch (error) {
      await copyToClipboard(`My resume scored ${sanitizedScore}/100 on CV Slayer! ${window.location.origin}`);
    }
  }, [sanitizedScore, copyToClipboard]);

  // Simple text sanitization
  const sanitizeText = useCallback((text) => {
    if (typeof text !== 'string') return [];
    return text
      .substring(0, 2000)
      .split('\n')
      .filter(line => line.trim().length > 0)
      .slice(0, 50);
  }, []);

  if (!results) {
    return (
      <div className="results-page">
        <div className="results-error">
          <span className="error-icon">📄</span>
          <h3>No Results Available</h3>
          <p>The analysis results could not be loaded. Please try again.</p>
          <button onClick={onReset} className="action-button primary">Try Again</button>
        </div>
      </div>
    );
  }

  const { roastFeedback = '' } = results;

  return (
    <div className="results-page">
      <div className="results-container">

        {/* Confirmation Dialog */}
        {showResetConfirm && (
          <div className="confirmation-overlay">
            <div className="confirmation-dialog">
              <div className="dialog-header">
                <h3>Start a new analysis?</h3>
              </div>
              <div className="dialog-content">
                <p>This will clear your current results.</p>
              </div>
              <div className="dialog-actions">
                <button className="dialog-button secondary" onClick={handleResetCancel}>Cancel</button>
                <button className="dialog-button primary" onClick={handleResetConfirm}>Yes, start new</button>
              </div>
            </div>
          </div>
        )}

        {/* Back button */}
        <button className="results-back" onClick={onReset}>
          ← Back to home
        </button>

        {/* Header */}
        <div className="results-header">
          <div className="header-info">
            <h1 className="results-title">Analysis Complete</h1>
            <p className="file-name"><strong>{sanitizedFileName}</strong></p>
          </div>
          <div className="header-actions">
            <button className="action-button secondary small" onClick={handleResetRequest}>
              + New Analysis
            </button>
          </div>
        </div>

        {/* Score */}
        <div className="score-section">
          <div className="score-container">
            <div className="score-circle">
              <span className="score-number" style={{ color: getScoreColor(sanitizedScore) }}>
                {sanitizedScore}
              </span>
              <span className="score-label">/ 100</span>
            </div>
            <div className="score-details">
              <h2 className="score-title">{getScoreEmoji(sanitizedScore)} Overall Resume Score</h2>
              <p className="score-description">{getScoreDescription(sanitizedScore)}</p>
              <div className="score-breakdown">
                <div className="score-bar">
                  <div className="score-fill" style={{ width: `${sanitizedScore}%`, backgroundColor: getScoreColor(sanitizedScore) }} />
                </div>
                <div className="score-labels">
                  <span>0</span><span>50</span><span>100</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="results-tabs">
          <button className={`tab-button ${activeTab === 'roast' ? 'active' : ''}`} onClick={() => handleTabChange('roast')}>
            <span className="tab-icon">🔥</span>
            <span className="tab-text">Feedback</span>
          </button>
          <button className={`tab-button ${activeTab === 'improvements' ? 'active' : ''}`} onClick={() => handleTabChange('improvements')}>
            <span className="tab-icon">💡</span>
            <span className="tab-text">Improvements</span>
            <span className="tab-count">{validImprovements.length}</span>
          </button>
          <button className={`tab-button ${activeTab === 'analysis' ? 'active' : ''}`} onClick={() => handleTabChange('analysis')}>
            <span className="tab-icon">📊</span>
            <span className="tab-text">Analysis</span>
          </button>
        </div>

        {/* Tab Content */}
        <div className="tab-content">
          {activeTab === 'roast' && (
            <div className="content-section">
              <div className="section-header">
                <h3><span className="section-icon">🔥</span> The Roast</h3>
                <p>Honest, unfiltered feedback on your resume</p>
              </div>
              <div className="feedback-text">
                {sanitizeText(roastFeedback).length > 0 ? (
                  <div className="feedback-content">
                    {sanitizeText(decodeHtmlEntities(roastFeedback)).map((paragraph, i) => (
                      <p key={i} className="feedback-paragraph">{paragraph}</p>
                    ))}
                  </div>
                ) : (
                  <div className="no-content">
                    <span className="no-content-icon">📝</span>
                    <p>No feedback available.</p>
                  </div>
                )}
              </div>
              <div className="section-actions">
                <button className="action-button secondary small" onClick={() => copyToClipboard(roastFeedback)}>
                  📋 Copy feedback
                </button>
              </div>
            </div>
          )}

          {activeTab === 'improvements' && (
            <div className="content-section">
              <div className="section-header">
                <h3><span className="section-icon">💡</span> What to fix</h3>
                <p>Specific, actionable improvements ranked by impact</p>
              </div>
              <div className="improvements-list">
                {validImprovements.length > 0 ? validImprovements.map((imp, i) => (
                  <div key={i} className={`improvement-item priority-${imp.priority}`}>
                    <div className="improvement-header">
                      <div className="improvement-priority">
                        <span className="priority-indicator">
                          {imp.priority === 'high' ? '🔴' : imp.priority === 'medium' ? '🟡' : '🟢'}
                        </span>
                        <span className="priority-text">{imp.priority} priority</span>
                      </div>
                    </div>
                    <div className="improvement-content">
                      <h4>{decodeHtmlEntities(imp.title)}</h4>
                      <p className="improvement-description">{decodeHtmlEntities(imp.description)}</p>
                      {imp.example && (
                        <div className="improvement-example">
                          <strong>Example:</strong> {decodeHtmlEntities(imp.example)}
                        </div>
                      )}
                    </div>
                  </div>
                )) : (
                  <div className="no-content">
                    <span className="no-content-icon">✨</span>
                    <p>No improvements identified — your resume looks solid!</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeTab === 'analysis' && (
            <div className="content-section">
              <div className="section-header">
                <h3><span className="section-icon">📊</span> Strengths & Weaknesses</h3>
                <p>A full breakdown of what's working and what isn't</p>
              </div>
              <div className="analysis-grid">
                <div className="strengths-section">
                  <div className="subsection-header">
                    <h4><span className="subsection-icon">✅</span> Strengths <span className="item-count">{validStrengths.length}</span></h4>
                  </div>
                  {validStrengths.length > 0 ? (
                    <ul className="analysis-list strengths-list">
                      {validStrengths.map((s, i) => (
                        <li key={i} className="analysis-item">
                          <span className="item-bullet">+</span>
                          <span className="item-text">{decodeHtmlEntities(s)}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="no-content small"><p>None identified.</p></div>
                  )}
                </div>
                <div className="weaknesses-section">
                  <div className="subsection-header">
                    <h4><span className="subsection-icon">⚠️</span> Areas to fix <span className="item-count">{validWeaknesses.length}</span></h4>
                  </div>
                  {validWeaknesses.length > 0 ? (
                    <ul className="analysis-list weaknesses-list">
                      {validWeaknesses.map((w, i) => (
                        <li key={i} className="analysis-item">
                          <span className="item-bullet">—</span>
                          <span className="item-text">{decodeHtmlEntities(w)}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="no-content small"><p>None identified.</p></div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Bottom actions */}
        <div className="results-actions">
          <button className="action-button primary" onClick={handlePrint}>
            <span className="button-text">Print / Save PDF</span>
          </button>
          <button className="action-button secondary" onClick={handleShare}>
            <span className="button-text">Share Results</span>
          </button>
          <button className="action-button secondary" onClick={handleResetRequest}>
            <span className="button-text">Analyze Another Resume</span>
          </button>
        </div>

      </div>
    </div>
  );
};

export default React.memo(ResultsDisplay);