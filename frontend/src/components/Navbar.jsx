import React, { useState, useEffect, useCallback, useMemo } from 'react';
import './Navbar.css';

const Navbar = ({ onNavClick }) => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [activeSection, setActiveSection] = useState('home');
  const [error, setError] = useState('');

  const handleScroll = useCallback(() => {
    const scrollY = window.scrollY;
    setIsScrolled(scrollY > 50);

    const sections = ['home', 'features', 'upload', 'examples', 'contact'];
    let currentSection = 'home';

    for (const sectionId of sections) {
      const element = document.getElementById(sectionId);
      if (element) {
        const rect = element.getBoundingClientRect();
        if (rect.top <= 100 && rect.bottom >= 100) {
          currentSection = sectionId;
          break;
        }
      }
    }
    setActiveSection(currentSection);
  }, []);

  useEffect(() => {
    let ticking = false;
    let lastScrollTime = 0;
    
    const throttledScroll = () => {
      const now = Date.now();
      // Rate limit: max 60fps
      if (now - lastScrollTime < 16) return;
      
      if (!ticking) {
        requestAnimationFrame(() => {
          handleScroll();
          ticking = false;
          lastScrollTime = now;
        });
        ticking = true;
      }
    };

    window.addEventListener('scroll', throttledScroll, { 
      passive: true,
      capture: false 
    });
    
    // Initial call to set correct state
    handleScroll();
    
    return () => {
      window.removeEventListener('scroll', throttledScroll);
    };
  }, [handleScroll]);

  const toggleMenu = useCallback(() => {
    setIsMenuOpen(prev => {
      const newState = !prev;
      document.body.style.overflow = newState ? 'hidden' : 'unset';
      if (newState) {
        document.body.setAttribute('aria-hidden', 'true');
      } else {
        document.body.removeAttribute('aria-hidden');
      }
      return newState;
    });
  }, []);

  const scrollToSection = useCallback(async (sectionId) => {
    // On the results page, any nav click just goes back to home
    if (onNavClick) {
      onNavClick();
      return;
    }

    const validSections = ['home', 'features', 'upload', 'examples', 'contact'];
    if (!validSections.includes(sectionId)) {
      setError('Section not found.');
      return;
    }

    setError('');
    setIsLoading(true);

    const element = document.getElementById(sectionId);
    if (!element) {
      setError('Navigation failed. Please try again.');
      setTimeout(() => setError(''), 3000);
      setIsLoading(false);
      return;
    }

    setIsMenuOpen(false);
    document.body.style.overflow = 'unset';
    document.body.removeAttribute('aria-hidden');

    const navbar = document.querySelector('.navbar');
    const navbarHeight = navbar ? navbar.offsetHeight : 80;
    const elementPosition = Math.max(0, element.offsetTop - navbarHeight);

    window.scrollTo({ top: elementPosition, behavior: 'smooth' });
    setActiveSection(sectionId);
    setIsLoading(false);
  }, [onNavClick]);

  // Handle keyboard navigation
  const handleKeyDown = useCallback((event, sectionId) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      scrollToSection(sectionId);
    }
  }, [scrollToSection]);

  useEffect(() => {
    const handleEscape = (event) => {
      if (event.key === 'Escape' && isMenuOpen) {
        setIsMenuOpen(false);
        document.body.style.overflow = 'unset';
        document.body.removeAttribute('aria-hidden');
      }
    };

    if (isMenuOpen) {
      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }
  }, [isMenuOpen]);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (isMenuOpen && event.target && !event.target.closest('.navbar-container')) {
        setIsMenuOpen(false);
        document.body.style.overflow = 'unset';
        document.body.removeAttribute('aria-hidden');
      }
    };

    if (isMenuOpen) {
      document.addEventListener('click', handleClickOutside, { passive: true });
      return () => document.removeEventListener('click', handleClickOutside);
    }
  }, [isMenuOpen]);

  useEffect(() => {
    return () => {
      document.body.style.overflow = 'unset';
      document.body.removeAttribute('aria-hidden');
    };
  }, []);

  const navigationItems = useMemo(() => [
    { id: 'home', label: 'Home', ariaLabel: 'Navigate to home section' },
    { id: 'features', label: 'Features', ariaLabel: 'Navigate to features section' },
    { id: 'upload', label: 'Upload Resume', ariaLabel: 'Navigate to resume upload section', isSpecial: true },
    { id: 'examples', label: 'Examples', ariaLabel: 'Navigate to examples section' },
    { id: 'contact', label: 'Contact', ariaLabel: 'Navigate to contact section' }
  ], []);

  // Handle logo click with loading state
  const handleLogoClick = useCallback(async () => {
    await scrollToSection('home');
  }, [scrollToSection]);

  return (
    <>
      {error && (
        <div className="navbar-error" role="alert" aria-live="polite">
          <span>{error}</span>
          <button
            onClick={() => setError('')} 
            className="error-close"
            aria-label="Close error message"
            type="button"
          >
            ×
          </button>
        </div>
      )}

      <nav 
        className={`navbar ${isScrolled ? 'navbar-scrolled' : ''} ${isMenuOpen ? 'navbar-menu-open' : ''}`}
        role="navigation"
        aria-label="Main navigation"
      >
        <div className="navbar-container">
          <div
            className={`navbar-logo ${isLoading ? 'loading' : ''}`}
            onClick={handleLogoClick}
            onKeyDown={(e) => handleKeyDown(e, 'home')}
            role="button"
            tabIndex={0}
            aria-label="CV Slayer logo - navigate to home"
          >
            <span className="logo-text">
              CV Slayer
              {isLoading && (
                <span 
                  className="loading-spinner" 
                  aria-hidden="true"
                  aria-label="Loading"
                ></span>
              )}
            </span>
          </div>

          <ul
            className={`navbar-menu ${isMenuOpen ? 'navbar-menu-active' : ''}`}
            role="menubar"
            id="navbar-menu"
          >
            {navigationItems.map((item) => (
              <li key={item.id} className="navbar-item" role="none">
                <button 
                  onClick={() => scrollToSection(item.id)}
                  onKeyDown={(e) => handleKeyDown(e, item.id)}
                  className={`navbar-link ${item.isSpecial ? 'cta-nav' : ''} ${activeSection === item.id ? 'active' : ''} ${isLoading ? 'disabled' : ''}`}
                  role="menuitem"
                  tabIndex={isMenuOpen || (typeof window !== 'undefined' && window.innerWidth > 768) ? 0 : -1}
                  aria-label={item.ariaLabel}
                  aria-current={activeSection === item.id ? 'page' : undefined}
                  disabled={isLoading}
                  type="button"
                >
                  {item.label}
                  {isLoading && activeSection === item.id && (
                    <span 
                      className="button-spinner" 
                      aria-hidden="true"
                      aria-label="Loading"
                    ></span>
                  )}
                </button>
              </li>
            ))}
          </ul>

          <button
            className={`navbar-toggle ${isMenuOpen ? 'active' : ''}`}
            onClick={toggleMenu}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                toggleMenu();
              }
            }}
            aria-label={isMenuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            aria-expanded={isMenuOpen}
            aria-controls="navbar-menu"
            type="button"
          >
            <span className="navbar-toggle-line" aria-hidden="true"></span>
            <span className="navbar-toggle-line" aria-hidden="true"></span>
            <span className="navbar-toggle-line" aria-hidden="true"></span>
            <span className="sr-only">
              {isMenuOpen ? 'Close menu' : 'Open menu'}
            </span>
          </button>
        </div>

        {isMenuOpen && (
          <div
            className="navbar-overlay"
            onClick={() => {
              setIsMenuOpen(false);
              document.body.style.overflow = 'unset';
              document.body.removeAttribute('aria-hidden');
            }}
            aria-hidden="true"
            role="presentation"
          />
        )}
      </nav>
    </>
  );
};

export default React.memo(Navbar);