import { NextRequest, NextResponse } from 'next/server';
import { analyzeResumeHandler } from '@/lib/services/geminiService'; // adjust import as needed

export async function POST(req: NextRequest) {
  return analyzeResumeHandler(req);
}