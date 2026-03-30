import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('symbiotech_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle response errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('symbiotech_token');
      localStorage.removeItem('symbiotech_user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth APIs
export const authAPI = {
  login: (credentials) => api.post('/auth/login', credentials),
  register: (data) => api.post('/auth/register', data),
  logout: () => api.post('/auth/logout'),
  getProfile: () => api.get('/auth/profile'),
  updateProfile: (data) => api.put('/auth/profile', data),
};

// Waste APIs
export const wasteAPI = {
  getAll: () => api.get('/waste'),
  getById: (id) => api.get(`/waste/${id}`),
  create: (data) => api.post('/waste', data),
  update: (id, data) => api.put(`/waste/${id}`, data),
  delete: (id) => api.delete(`/waste/${id}`),
  search: (query) => api.get(`/waste/search?q=${query}`),
};

// Resource APIs
export const resourceAPI = {
  getAll: () => api.get('/resources'),
  getById: (id) => api.get(`/resources/${id}`),
  create: (data) => api.post('/resources', data),
  update: (id, data) => api.put(`/resources/${id}`, data),
  delete: (id) => api.delete(`/resources/${id}`),
  search: (query) => api.get(`/resources/search?q=${query}`),
};

// Match APIs
export const matchAPI = {
  getAll: () => api.get('/matches'),
  getById: (id) => api.get(`/matches/${id}`),
  accept: (id) => api.post(`/matches/${id}/accept`),
  reject: (id) => api.post(`/matches/${id}/reject`),
  getRecommendations: () => api.get('/matches/recommendations'),
};

// Impact APIs
export const impactAPI = {
  getMetrics: () => api.get('/impact/metrics'),
  getReport: (period) => api.get(`/impact/report?period=${period}`),
  calculate: (data) => api.post('/impact/calculate', data),
  getSustainabilityScore: () => api.get('/impact/sustainability-score'),
};

// Industry APIs
export const industryAPI = {
  getAll: () => api.get('/industries'),
  getById: (id) => api.get(`/industries/${id}`),
  getNetwork: () => api.get('/industries/network'),
  update: (id, data) => api.put(`/industries/${id}`, data),
};

export default api;