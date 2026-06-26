/*
 * Wazuh Case Management Plugin
 * Frontend-specific types
 */

import { CoreStart, AppMountParameters } from 'opensearch-dashboards/public';

/**
 * Services available throughout the app, provided via React context.
 */
export interface AppServices {
  /** OSD core HTTP client for API calls */
  http: CoreStart['http'];
  /** OSD notifications service for toasts */
  notifications: CoreStart['notifications'];
  /** OSD application service for navigation */
  application: CoreStart['application'];
  /** OSD chrome service for breadcrumbs etc. */
  chrome: CoreStart['chrome'];
  /** Base path (for asset URLs) */
  basePath: string;
  /** Username of the currently logged-in Wazuh user */
  currentUser: string;
}

/**
 * Props passed to the root application component.
 */
export interface AppProps {
  services: AppServices;
  params: AppMountParameters;
}

/**
 * Plugin setup dependencies (currently none required).
 */
export interface WazuhCaseManagementPluginSetup {}

/**
 * Plugin start dependencies (currently none required).
 */
export interface WazuhCaseManagementPluginStart {}

/**
 * View mode toggle for the case list page.
 */
export type CaseViewMode = 'table' | 'kanban';

/**
 * Quick filter chip representation.
 */
export interface FilterChip {
  field: string;
  value: string;
  label: string;
  isActive: boolean;
}
