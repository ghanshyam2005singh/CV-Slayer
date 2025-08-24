import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "CV Slayer - AI Resume Roaster | Get Brutally Honest Feedback",
  description: "CV Slayer - Get your resume roasted by AI with brutally honest feedback. Improve your resume with AI-powered analysis and actionable suggestions.",
  keywords: "resume roaster, AI resume analysis, CV feedback, resume improvement, job search, career advice",
  authors: [{ name: "Iron Industry" }],
  robots: "index, follow",
  
  // Open Graph
  openGraph: {
    type: "website",
    url: "https://cv-slayer.vercel.app/",
    title: "CV Slayer - AI Resume Roaster",
    description: "Get your resume roasted by AI with brutally honest feedback and actionable improvement suggestions.",
    images: [
      {
        url: "/og-image.jpg",
        width: 1200,
        height: 630,
        alt: "CV Slayer - AI Resume Roaster",
      },
    ],
    siteName: "CV Slayer",
  },
  
  // Twitter
  twitter: {
    card: "summary_large_image",
    site: "@cvslayer", // Add your Twitter handle
    title: "CV Slayer - AI Resume Roaster",
    description: "Get your resume roasted by AI with brutally honest feedback.",
    images: ["/og-image.jpg"],
  },
  
  // Additional metadata
  manifest: "/manifest.json",
  icons: {
    icon: "/favicon.ico",
    apple: "/apple-touch-icon.png",
  },
  
  // Security and other headers
  other: {
    "theme-color": "#667eea",
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#667eea",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        {/* Preconnect to external domains for performance */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        
        {/* Security Headers - These should be set in next.config.js for better performance */}
        <meta httpEquiv="X-Content-Type-Options" content="nosniff" />
        <meta httpEquiv="X-Frame-Options" content="DENY" />
        <meta httpEquiv="X-XSS-Protection" content="1; mode=block" />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        <noscript>
          <div style={{
            textAlign: 'center',
            padding: '50px',
            fontFamily: 'Arial, sans-serif'
          }}>
            <h1>JavaScript Required</h1>
            <p>CV Slayer requires JavaScript to function properly. Please enable JavaScript in your browser and refresh the page.</p>
          </div>
        </noscript>
        {children}
      </body>
    </html>
  );
}