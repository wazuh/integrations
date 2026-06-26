/*
 * Wazuh Case Management Plugin
 * Main App component — React Router setup, navigation tabs, and service context.
 */

import React, { createContext, useContext } from 'react';
import { HashRouter, Route, Switch, useHistory, useLocation } from 'react-router-dom';
import {
  EuiPage,
  EuiPageBody,
  EuiTabs,
  EuiTab,
  EuiSpacer,
} from '@elastic/eui';
import { AppServices, AppProps } from './types';

// ─── Styles ────────────────────────────────────────────────────
import './styles/case_management.scss';

// ─── Pages ─────────────────────────────────────────────────────
import { CaseListPage } from './pages/CaseListPage';
import { CaseDetailPage } from './pages/CaseDetailPage';
import { CreateCasePage } from './pages/CreateCasePage';
import { DashboardPage } from './pages/DashboardPage';
import { SettingsPage } from './pages/SettingsPage';
import { MonitorPage } from './pages/MonitorPage';

// ─── Service Context ──────────────────────────────────────────
const ServicesContext = createContext<AppServices | null>(null);

/**
 * Hook to consume the services context.
 * Must be used within the <CaseManagementApp /> provider tree.
 */
export function useServices(): AppServices {
  const ctx = useContext(ServicesContext);
  if (!ctx) {
    throw new Error('useServices must be used within CaseManagementApp');
  }
  return ctx;
}

// ─── Navigation Tab Definitions ───────────────────────────────
interface NavTab {
  id: string;
  label: string;
  route: string;
  iconType?: string;
  testId: string;
}

const NAV_TABS: NavTab[] = [
  { id: 'cases', label: 'Cases', route: '/', iconType: 'folderOpen', testId: 'nav-tab-cases' },
  { id: 'dashboard', label: 'Dashboard', route: '/dashboard', iconType: 'visBarVertical', testId: 'nav-tab-dashboard' },
  { id: 'monitor', label: 'Auto Monitor', route: '/monitor', iconType: 'clock', testId: 'nav-tab-monitor' },
  { id: 'settings', label: 'Settings', route: '/settings', iconType: 'gear', testId: 'nav-tab-settings' },
];

/**
 * Top-level navigation tabs.
 */
const NavigationTabs: React.FC = () => {
  const history = useHistory();
  const location = useLocation();
  const { currentUser } = useServices();

  const getActiveTab = (): string => {
    const path = location.pathname;
    if (path.startsWith('/dashboard')) return 'dashboard';
    if (path.startsWith('/monitor')) return 'monitor';
    if (path.startsWith('/settings')) return 'settings';
    return 'cases';
  };

  return (
    <div className="caseManagement__navBar" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      <EuiTabs size="l">
        {NAV_TABS.map((tab) => (
          <EuiTab
            key={tab.id}
            id={`nav-tab-${tab.id}`}
            data-test-subj={tab.testId}
            isSelected={getActiveTab() === tab.id}
            onClick={() => history.push(tab.route)}
            prepend={
              tab.iconType ? (
                <span className="caseManagement__navIcon" />
              ) : undefined
            }
          >
            {tab.label}
          </EuiTab>
        ))}
      </EuiTabs>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingRight: 8 }}>
        <span style={{
          width: 28, height: 28, borderRadius: '50%',
          background: 'var(--cm-primary)', color: '#fff',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 12, fontWeight: 700, flexShrink: 0,
        }}>
          {currentUser.charAt(0).toUpperCase()}
        </span>
        <span style={{ fontSize: 12, color: 'var(--cm-text-secondary)', fontWeight: 500 }}>
          {currentUser}
        </span>
      </div>
    </div>
  );
};

/**
 * Inner app content with router and navigation.
 */
const AppContent: React.FC = () => {
  return (
    <EuiPage className="caseManagement__page" paddingSize="l">
      <EuiPageBody>
        <NavigationTabs />
        <EuiSpacer size="l" />
        <Switch>
          <Route exact path="/" component={CaseListPage} />
          <Route exact path="/create" component={CreateCasePage} />
          <Route exact path="/cases/:id" component={CaseDetailPage} />
          <Route exact path="/dashboard" component={DashboardPage} />
          <Route exact path="/monitor" component={MonitorPage} />
          <Route exact path="/settings" component={SettingsPage} />
        </Switch>
      </EuiPageBody>
    </EuiPage>
  );
};

/**
 * Root application component.
 * Provides services context and sets up the hash router.
 */
export const CaseManagementApp: React.FC<AppProps> = ({ services }) => {
  return (
    <ServicesContext.Provider value={services}>
      <HashRouter>
        <AppContent />
      </HashRouter>
    </ServicesContext.Provider>
  );
};
