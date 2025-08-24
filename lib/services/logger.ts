import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import crypto from 'crypto';

interface LogEntry {
  level: string;
  message: string;
  meta: any;
  timestamp: number;
}

interface LogStats {
  total: number;
  timeRange: string;
  errors: number;
  warnings: number;
  info: number;
  debug: number;
  errorRate: string;
  lastError?: LogEntry;
  hourlyVolume: Array<{ hour: string; count: number }>;
}

class Logger {
  private logsDir: string;
  private maxFileSize: number;
  private maxBackups: number;
  private logLevels: string[];
  private enableConsoleOutput: boolean;
  private writeQueue: LogEntry[];
  private isWriting: boolean;
  private flushInterval: number;
  private flushTimer?: NodeJS.Timeout;

  constructor() {
    // Create logs directory if it doesn't exist
    this.logsDir = path.join(process.cwd(), 'logs');
    this.initializeLogDirectory();
    
    // Enhanced configuration
    this.maxFileSize = 10 * 1024 * 1024; // 10MB
    this.maxBackups = 5;
    this.logLevels = ['error', 'warn', 'info', 'debug'];
    this.enableConsoleOutput = process.env.NODE_ENV !== 'production';
    
    // Performance optimization
    this.writeQueue = [];
    this.isWriting = false;
    this.flushInterval = 1000; // 1 second
    
    // Start flush timer
    this.startFlushTimer();
  }

  private initializeLogDirectory(): void {
    try {
      if (!fsSync.existsSync(this.logsDir)) {
        fsSync.mkdirSync(this.logsDir, { recursive: true });
      }
    } catch (error) {
      // Silent fail
    }
  }

  private formatMessage(level: string, message: string, meta: any = {}): string {
    const timestamp = new Date().toISOString();
    
    const logEntry = {
      timestamp,
      level: level.toUpperCase(),
      message: this.sanitizeMessage(message),
      environment: process.env.NODE_ENV || 'development',
      service: 'cv-slayer-backend',
      pid: process.pid,
      ...(Object.keys(meta).length > 0 && { meta: this.sanitizeMeta(meta) })
    };

    return JSON.stringify(logEntry);
  }

  private sanitizeMessage(message: string): string {
    if (typeof message !== 'string') {
      message = String(message);
    }
    
    // Enhanced sensitive data patterns
    return message
      .replace(/password[=:]\s*\S+/gi, 'password=[REDACTED]')
      .replace(/token[=:]\s*\S+/gi, 'token=[REDACTED]')
      .replace(/key[=:]\s*\S+/gi, 'key=[REDACTED]')
      .replace(/secret[=:]\s*\S+/gi, 'secret=[REDACTED]')
      .replace(/authorization[=:]\s*\S+/gi, 'authorization=[REDACTED]')
      .replace(/bearer\s+\S+/gi, 'bearer [REDACTED]')
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL]')
      .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[PHONE]')
      .replace(/\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g, '[CARD]')
      .substring(0, 1000); // Increased limit
  }

  private sanitizeMeta(meta: any): any {
    const sanitized = { ...meta };
    
    // Recursively sanitize nested objects
    for (const [key, value] of Object.entries(sanitized)) {
      if (typeof value === 'string') {
        sanitized[key] = this.sanitizeMessage(value);
      } else if (typeof value === 'object' && value !== null) {
        sanitized[key] = this.sanitizeMeta(value);
      } else if (Array.isArray(value)) {
        sanitized[key] = value.map(item => 
          typeof item === 'string' ? this.sanitizeMessage(item) : item
        );
      }
    }
    
    return sanitized;
  }

  private async writeToFile(level: string, message: string, meta: any = {}): Promise<void> {
    const logEntry: LogEntry = {
      level,
      message,
      meta,
      timestamp: Date.now()
    };
    
    // Add to write queue for batch processing
    this.writeQueue.push(logEntry);
    
    // Console output in development
    if (this.enableConsoleOutput) {
      this.logToConsole(level, message, meta);
    }
  }

  private logToConsole(level: string, message: string, meta: any): void {
    const colors = {
      error: '\x1b[31m', // Red
      warn: '\x1b[33m',  // Yellow
      info: '\x1b[36m',  // Cyan
      debug: '\x1b[90m'  // Gray
    };
    
    const reset = '\x1b[0m';
    const color = colors[level as keyof typeof colors] || colors.info;
    const timestamp = new Date().toISOString();
    
    console.log(`${color}[${timestamp}] ${level.toUpperCase()}: ${message}${reset}`);
    
    if (Object.keys(meta).length > 0) {
      console.log(`${color}Meta:${reset}`, meta);
    }
  }

  private startFlushTimer(): void {
    this.flushTimer = setInterval(async () => {
      await this.flushLogs();
    }, this.flushInterval);
  }

  private async flushLogs(): Promise<void> {
    if (this.isWriting || this.writeQueue.length === 0) {
      return;
    }
    
    this.isWriting = true;
    const logsToWrite = [...this.writeQueue];
    this.writeQueue = [];
    
    try {
      // Group logs by level
      const logsByLevel = logsToWrite.reduce((acc, log) => {
        if (!acc[log.level]) acc[log.level] = [];
        acc[log.level].push(log);
        return acc;
      }, {} as Record<string, LogEntry[]>);
      
      // Write to files
      for (const [level, logs] of Object.entries(logsByLevel)) {
        const logFile = path.join(this.logsDir, `${level}.log`);
        const logContent = logs
          .map(log => this.formatMessage(log.level, log.message, log.meta))
          .join('\n') + '\n';
        
        await this.rotateLogIfNeeded(logFile);
        await fs.appendFile(logFile, logContent);
      }
    } catch (error) {
      // Silent fail - put logs back in queue
      this.writeQueue.unshift(...logsToWrite);
    } finally {
      this.isWriting = false;
    }
  }

  private async rotateLogIfNeeded(logFile: string): Promise<void> {
    try {
      const stats = await fs.stat(logFile);
      
      if (stats.size > this.maxFileSize) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = `${logFile}.${timestamp}`;
        
        // Move current log to backup
        await fs.rename(logFile, backupFile);
        
        // Cleanup old backups
        await this.cleanupOldBackups(path.dirname(logFile), path.basename(logFile));
      }
    } catch (error) {
      // File doesn't exist or other error - continue
    }
  }

  private async cleanupOldBackups(dir: string, baseName: string): Promise<void> {
    try {
      const files = await fs.readdir(dir);
      const backupFiles = files
        .filter(file => file.startsWith(`${baseName}.`))
        .sort()
        .reverse();
      
      // Remove excess backups
      const filesToDelete = backupFiles.slice(this.maxBackups);
      for (const file of filesToDelete) {
        try {
          await fs.unlink(path.join(dir, file));
        } catch (error) {
          // Continue on deletion errors
        }
      }
    } catch (error) {
      // Continue on cleanup errors
    }
  }

  // Enhanced logging methods
  info(message: string, meta: any = {}): void {
    this.writeToFile('info', message, meta);
  }

  error(message: string, meta: any = {}): void {
    this.writeToFile('error', message, meta);
  }

  warn(message: string, meta: any = {}): void {
    this.writeToFile('warn', message, meta);
  }

  debug(message: string, meta: any = {}): void {
    if (process.env.NODE_ENV !== 'production') {
      this.writeToFile('debug', message, meta);
    }
  }

  // Request logging helper
  logRequest(req: any, res: any, processingTime: number): void {
    const logData = {
      method: req.method,
      url: req.originalUrl || req.url,
      statusCode: res.statusCode,
      processingTime,
      userAgent: req.get?.('User-Agent'),
      ip: req.ip || req.connection?.remoteAddress,
      contentLength: res.get?.('Content-Length'),
      timestamp: new Date().toISOString()
    };
    
    if (res.statusCode >= 400) {
      this.error('HTTP Request Error', logData);
    } else {
      this.info('HTTP Request', logData);
    }
  }

  // Performance logging
  logPerformance(operation: string, duration: number, metadata: any = {}): void {
    this.info('Performance Metric', {
      operation,
      duration,
      ...metadata
    });
  }

  // Error logging with stack trace
  logError(error: Error, context: any = {}): void {
    const errorData = {
      message: error.message,
      stack: error.stack,
      name: error.name,
      code: (error as any).code,
      ...context
    };
    
    this.error('Application Error', errorData);
  }

  async getRecentLogs(options: {
    level?: string;
    limit?: number;
    startDate?: string;
    endDate?: string;
  } = {}): Promise<LogEntry[]> {
    const {
      level = 'all',
      limit = 100,
      startDate,
      endDate
    } = options;

    try {
      const logs: LogEntry[] = [];
      let levels = level === 'all' ? this.logLevels : [level];
      
      for (const logLevel of levels) {
        const logFile = path.join(this.logsDir, `${logLevel}.log`);
        
        try {
          const content = await fs.readFile(logFile, 'utf8');
          const lines = content.trim().split('\n').filter(line => line);
          
          for (const line of lines) {
            try {
              const logEntry = JSON.parse(line);
              
              // Filter by date range if provided
              if (startDate || endDate) {
                const logDate = new Date(logEntry.timestamp);
                if (startDate && logDate < new Date(startDate)) continue;
                if (endDate && logDate > new Date(endDate)) continue;
              }
              
              logs.push(logEntry);
            } catch (e) {
              // Skip invalid JSON lines
            }
          }
        } catch (error) {
          // File doesn't exist - continue
        }
      }
      
      // Sort by timestamp and limit
      return logs
        .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
        .slice(0, Math.min(limit, 1000));
        
    } catch (error) {
      return [];
    }
  }

  async getLogStats(timeRange: string = '24h'): Promise<LogStats> {
    try {
      const now = new Date();
      const startDate = new Date();
      
      // Calculate start date based on time range
      switch (timeRange) {
        case '1h':
          startDate.setHours(now.getHours() - 1);
          break;
        case '24h':
          startDate.setDate(now.getDate() - 1);
          break;
        case '7d':
          startDate.setDate(now.getDate() - 7);
          break;
        case '30d':
          startDate.setDate(now.getDate() - 30);
          break;
        default:
          startDate.setDate(now.getDate() - 1);
      }
      
      const logs = await this.getRecentLogs({
        level: 'all',
        limit: 10000,
        startDate: startDate.toISOString()
      });
      
      const stats: LogStats = {
        total: logs.length,
        timeRange,
        errors: logs.filter(log => log.level === 'ERROR').length,
        warnings: logs.filter(log => log.level === 'WARN').length,
        info: logs.filter(log => log.level === 'INFO').length,
        debug: logs.filter(log => log.level === 'DEBUG').length,
        
        // Error rate
        errorRate: logs.length > 0 ? 
          ((logs.filter(log => log.level === 'ERROR').length / logs.length) * 100).toFixed(2) : '0',
        
        // Most recent error
        lastError: logs.find(log => log.level === 'ERROR'),
        
        // Log volume by hour (for recent logs)
        hourlyVolume: this.calculateHourlyVolume(logs)
      };
      
      return stats;
      
    } catch (error) {
      return {
        total: 0,
        timeRange,
        errors: 0,
        warnings: 0,
        info: 0,
        debug: 0,
        errorRate: '0',
        hourlyVolume: []
      };
    }
  }

  private calculateHourlyVolume(logs: LogEntry[]): Array<{ hour: string; count: number }> {
    const hourlyData: Record<string, number> = {};
    
    logs.forEach(log => {
      const hour = new Date(log.timestamp).toISOString().substr(0, 13); // YYYY-MM-DDTHH
      hourlyData[hour] = (hourlyData[hour] || 0) + 1;
    });
    
    return Object.entries(hourlyData)
      .map(([hour, count]) => ({ hour, count }))
      .sort((a, b) => a.hour.localeCompare(b.hour))
      .slice(-24); // Last 24 hours
  }

  // Graceful shutdown - flush remaining logs
  async shutdown(): Promise<void> {
    this.info('Logger shutting down');
    await this.flushLogs();
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
    }
  }
}

// Create singleton instance
const logger = new Logger();

// Graceful shutdown handler
process.on('SIGINT', async () => {
  await logger.shutdown();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await logger.shutdown();
  process.exit(0);
});

export default logger;
export { Logger };