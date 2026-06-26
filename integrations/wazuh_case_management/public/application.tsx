/*
 * Wazuh Case Management Plugin
 * Application entry — renders the React app and returns the unmount function.
 */

import React from 'react';
import ReactDOM from 'react-dom';
import { CoreStart, AppMountParameters } from 'opensearch-dashboards/public';
import { CaseManagementApp } from './app';
import { AppServices } from './types';

/**
 * Render the Case Management application into the OSD app mount container.
 * Returns an unmount callback for cleanup when the user navigates away.
 */
export function renderApp(core: CoreStart, params: AppMountParameters): () => void {
  // Fetch the current user asynchronously, then render
  core.http
    .get<{ username: string }>('/api/wazuh-case-management/me')
    .then(({ username }) => mount(username))
    .catch(() => mount('unknown'));

  function mount(currentUser: string) {
    const services: AppServices = {
      http: core.http,
      notifications: core.notifications,
      application: core.application,
      chrome: core.chrome,
      basePath: core.http.basePath.get(),
      currentUser,
    };

    ReactDOM.render(
      <CaseManagementApp services={services} params={params} />,
      params.element
    );
  }

  // Return the unmount function
  return () => {
    ReactDOM.unmountComponentAtNode(params.element);
  };
}
