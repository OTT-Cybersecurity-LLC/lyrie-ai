/**
 * lyrie service — platform-agnostic service manager
 * © OTT Cybersecurity LLC — https://lyrie.ai
 */

export { LaunchdService } from "./launchd";
export { SystemdService } from "./systemd";
export type { IServiceManager, ServiceConfig, ServiceStatus } from "./types";

import { LaunchdService } from "./launchd";
import { SystemdService } from "./systemd";
import type { IServiceManager } from "./types";

/**
 * Returns the appropriate service manager for the current platform.
 * macOS → LaunchdService
 * Linux (and everything else) → SystemdService
 */
export function getServiceManager(): IServiceManager {
  if (process.platform === "darwin") {
    return new LaunchdService();
  }
  return new SystemdService();
}
