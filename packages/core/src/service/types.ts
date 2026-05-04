/**
 * lyrie service — shared types for launchd/systemd daemon management
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export interface ServiceConfig {
  /** Service label / unit name. e.g. "ai.lyrie.daemon" */
  label: string;
  /** Absolute path to the program (bun, node, …) */
  program: string;
  /** Arguments passed after program. e.g. ["run", "/path/to/daemon.ts"] */
  args: string[];
  /** Extra environment variables to inject */
  env?: Record<string, string>;
  /** Stdout/stderr log file path. Default: ~/.lyrie/logs/daemon.log */
  logPath?: string;
  /** Start the service on login/boot. Default: true */
  runAtLoad?: boolean;
  /** Restart automatically on exit. Default: true */
  keepAlive?: boolean;
}

export interface ServiceStatus {
  installed: boolean;
  running: boolean;
  pid?: number;
  uptime?: number; // seconds
  label: string;
}

/** Platform-agnostic service manager interface */
export interface IServiceManager {
  install(config: ServiceConfig): Promise<void>;
  uninstall(): Promise<void>;
  start(): Promise<void>;
  stop(): Promise<void>;
  restart(): Promise<void>;
  status(): Promise<ServiceStatus>;
  logs(lines?: number): Promise<string>;
}
