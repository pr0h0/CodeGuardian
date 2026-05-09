export type LogLevel = "debug" | "info" | "warn" | "error";

export class Logger {
  constructor(private readonly verbose = false) {}

  debug(message: string): void {
    if (this.verbose) console.error(`[${new Date().toISOString()}] [debug] ${message}`);
  }

  info(message: string): void {
    console.error(`[${new Date().toISOString()}] [info] ${message}`);
  }

  warn(message: string): void {
    console.error(`[${new Date().toISOString()}] [warn] ${message}`);
  }

  error(message: string): void {
    console.error(`[${new Date().toISOString()}] [error] ${message}`);
  }
}
