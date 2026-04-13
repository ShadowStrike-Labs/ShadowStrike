/* ============================================================================
 * ShadowStrike Phantom Dashboard — App Router
 * ============================================================================ */

import { lazy } from 'react';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';
import Layout from '@/components/Layout';

// Lazy-loaded pages for code splitting
const Overview   = lazy(() => import('@/pages/Overview'));
const Threats    = lazy(() => import('@/pages/Threats'));
const Scan       = lazy(() => import('@/pages/Scan'));
const Quarantine = lazy(() => import('@/pages/Quarantine'));
const Alerts     = lazy(() => import('@/pages/Alerts'));
const ThreatIntel= lazy(() => import('@/pages/ThreatIntel'));
const Reports    = lazy(() => import('@/pages/Reports'));
const Settings   = lazy(() => import('@/pages/Settings'));

const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      { index: true,            element: <Overview /> },
      { path: 'threats',        element: <Threats /> },
      { path: 'scan',           element: <Scan /> },
      { path: 'quarantine',     element: <Quarantine /> },
      { path: 'alerts',         element: <Alerts /> },
      { path: 'threat-intel',   element: <ThreatIntel /> },
      { path: 'reports',        element: <Reports /> },
      { path: 'settings',       element: <Settings /> },
    ],
  },
]);

export default function App() {
  return <RouterProvider router={router} />;
}
