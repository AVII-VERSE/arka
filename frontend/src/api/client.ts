import axios from 'axios';
import {
  Agent,
  Alert,
  AlertStatus,
  DashboardSummary,
  DetectionRule,
  Incident,
  IncidentStatus,
  SecurityEvent,
} from '../types';

const API_BASE = '/api/v1';

const client = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const api = {
  getDashboardSummary: async (): Promise<DashboardSummary> => {
    const res = await client.get('/dashboard/summary');
    return res.data;
  },

  getEvents: async (params?: Record<string, any>): Promise<SecurityEvent[]> => {
    const res = await client.get('/events', { params });
    return res.data;
  },

  getAlerts: async (params?: Record<string, any>): Promise<Alert[]> => {
    const res = await client.get('/alerts', { params });
    return res.data;
  },

  updateAlertStatus: async (alertId: string, status: AlertStatus): Promise<Alert> => {
    const res = await client.patch(`/alerts/${alertId}`, { status });
    return res.data;
  },

  getIncidents: async (params?: Record<string, any>): Promise<Incident[]> => {
    const res = await client.get('/incidents', { params });
    return res.data;
  },

  updateIncidentStatus: async (incidentId: string, status: IncidentStatus, note?: string): Promise<Incident> => {
    const res = await client.patch(`/incidents/${incidentId}`, { status, note });
    return res.data;
  },

  getAgents: async (): Promise<Agent[]> => {
    const res = await client.get('/agents');
    return res.data;
  },

  getMe: async (): Promise<any> => {
    const res = await client.get('/auth/me');
    return res.data;
  },
  getRules: async (): Promise<DetectionRule[]> => {
    const res = await client.get('/rules');
    return res.data;
  },
};
