import { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';

// Use process.cwd() to resolve the logs directory relative to the project root
const LOG_DIR = path.join(process.cwd(), 'logs');

// Ensure the log directory exists
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

const logger = (req: Request, res: Response, next: NextFunction) => {
    const logEntry = `${new Date().toISOString()} ${req.ip} - ${res.statusCode} ${req.method} ${req.originalUrl}\n`;

    // Write to access.log
    fs.appendFile(path.join(LOG_DIR, 'access.log'), logEntry, (err) => {
        if (err) console.error('Error writing to access log:', err);
    });

    // Write to error.log if status code is >= 400
    res.on('finish', () => {
        if (res.statusCode >= 400) {
            const errorEntry = `${new Date().toISOString()} ${req.ip} - ${res.statusCode} ${req.method} ${req.originalUrl} ${res.statusMessage}\n`;
            fs.appendFile(path.join(LOG_DIR, 'error.log'), errorEntry, (err) => {
                if (err) console.error('Error writing to error log:', err);
            });
        }
    });

    next();
};

export default logger;
