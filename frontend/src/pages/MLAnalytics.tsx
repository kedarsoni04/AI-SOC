/**
 * ML Analytics Page
 */
import { useState, useEffect } from 'react';
import { Brain, CheckCircle, XCircle, RefreshCw } from 'lucide-react';
import { PageHeader } from '../components/layout/PageHeader';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { get, post } from '../services/api';
import type { MLModelMetrics } from '../types';

interface MLPerformanceResponse {
  anomaly_detector: MLModelMetrics & { sklearn_available?: boolean };
  threat_classifier: MLModelMetrics;
}

const COLORS = ['#00d4ff', '#7c3aed', '#10b981', '#f59e0b', '#ef4444', '#3b82f6', '#ec4899', '#84cc16'];

export function MLAnalyticsPage() {
  const [data, setData] = useState<MLPerformanceResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isTraining, setIsTraining] = useState(false);

  const load = async () => {
    setIsLoading(true);
    try {
      const result = await get<MLPerformanceResponse>('/ml/performance');
      setData(result);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const train = async () => {
    setIsTraining(true);
    try {
      await post('/ml/train');
      setTimeout(() => { load(); setIsTraining(false); }, 5000);
    } catch {
      setIsTraining(false);
    }
  };

  const classifier = data?.threat_classifier;
  const anomaly = data?.anomaly_detector;

  const metricsData = classifier ? [
    { name: 'Accuracy', value: (classifier.accuracy || 0) * 100 },
    { name: 'Precision', value: (classifier.precision || 0) * 100 },
    { name: 'Recall', value: (classifier.recall || 0) * 100 },
    { name: 'F1-Score', value: (classifier.f1_score || 0) * 100 },
  ] : [];

  return (
    <div className="flex flex-col h-full">
      <PageHeader
        title="ML Analytics"
        subtitle="Machine Learning model performance and metrics"
        actions={
          <button onClick={train} className="btn-primary btn-sm" disabled={isTraining}>
            <RefreshCw className={`w-3.5 h-3.5 ${isTraining ? 'animate-spin' : ''}`} />
            {isTraining ? 'Training...' : 'Retrain Models'}
          </button>
        }
      />
      <div className="flex-1 overflow-auto p-6 space-y-6">
        {isLoading ? (
          <div className="text-center py-12 text-soc-text-muted">Loading ML metrics...</div>
        ) : (
          <>
            {/* Models status */}
            <div className="grid grid-cols-2 gap-4">
              <div className="card">
                <div className="flex items-center gap-3 mb-4">
                  <Brain className="w-5 h-5 text-soc-primary" />
                  <div>
                    <h3 className="text-sm font-medium text-soc-text">Anomaly Detector</h3>
                    <p className="text-xs text-soc-text-muted">Isolation Forest</p>
                  </div>
                  {anomaly?.is_trained ? (
                    <CheckCircle className="w-4 h-4 text-green-400 ml-auto" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-400 ml-auto" />
                  )}
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-soc-text-muted">Status</span>
                    <span className={anomaly?.is_trained ? 'text-green-400' : 'text-red-400'}>
                      {anomaly?.is_trained ? 'Trained' : 'Not Trained'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-soc-text-muted">Training Samples</span>
                    <span className="text-soc-text font-mono">{anomaly?.training_samples?.toLocaleString() || 0}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-soc-text-muted">Contamination Rate</span>
                    <span className="text-soc-text font-mono">5%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-soc-text-muted">scikit-learn</span>
                    <span className={anomaly?.sklearn_available ? 'text-green-400' : 'text-red-400'}>
                      {anomaly?.sklearn_available ? 'Available' : 'Not Available'}
                    </span>
                  </div>
                  <div>
                    <p className="text-soc-text-muted mb-1">Features ({anomaly?.feature_names?.length || 0})</p>
                    <div className="flex flex-wrap gap-1">
                      {anomaly?.feature_names?.map(f => (
                        <span key={f} className="text-xs px-1.5 py-0.5 bg-soc-border rounded text-soc-text-dim">{f}</span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              <div className="card">
                <div className="flex items-center gap-3 mb-4">
                  <Brain className="w-5 h-5 text-soc-secondary" />
                  <div>
                    <h3 className="text-sm font-medium text-soc-text">Threat Classifier</h3>
                    <p className="text-xs text-soc-text-muted">{classifier?.model_type || 'Random Forest / XGBoost'}</p>
                  </div>
                  {classifier?.is_trained ? (
                    <CheckCircle className="w-4 h-4 text-green-400 ml-auto" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-400 ml-auto" />
                  )}
                </div>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-soc-text-muted">Training Samples</span>
                    <span className="text-soc-text font-mono">{classifier?.training_samples?.toLocaleString() || 0}</span>
                  </div>
                  {classifier?.trained_at && (
                    <div className="flex justify-between">
                      <span className="text-soc-text-muted">Trained At</span>
                      <span className="text-soc-text">{new Date(classifier.trained_at).toLocaleDateString()}</span>
                    </div>
                  )}
                  <div>
                    <p className="text-soc-text-muted mb-1">Classes</p>
                    <div className="flex flex-wrap gap-1">
                      {classifier?.class_labels?.map(c => (
                        <span key={c} className="text-xs px-1.5 py-0.5 bg-soc-secondary/20 border border-soc-secondary/30 rounded text-purple-300">{c}</span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Metrics chart */}
            {metricsData.length > 0 && (
              <div className="card">
                <h3 className="text-sm font-medium text-soc-text mb-4">Classifier Performance Metrics</h3>
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={metricsData}>
                    <XAxis dataKey="name" tick={{ fontSize: 12, fill: '#94a3b8' }} />
                    <YAxis tick={{ fontSize: 11, fill: '#64748b' }} domain={[0, 100]} tickFormatter={v => `${v}%`} />
                    <Tooltip
                      contentStyle={{ background: '#1a2235', border: '1px solid #1e2d40', borderRadius: '8px' }}
                      formatter={(value: number) => [`${value.toFixed(1)}%`, '']}
                    />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {metricsData.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
                <div className="grid grid-cols-4 gap-4 mt-4">
                  {metricsData.map((m, i) => (
                    <div key={m.name} className="text-center">
                      <p className="text-2xl font-bold font-mono" style={{ color: COLORS[i] }}>
                        {m.value.toFixed(1)}%
                      </p>
                      <p className="text-xs text-soc-text-muted">{m.name}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Confusion matrix */}
            {classifier?.confusion_matrix && (
              <div className="card">
                <h3 className="text-sm font-medium text-soc-text mb-4">Confusion Matrix</h3>
                <div className="overflow-x-auto">
                  <table className="text-xs">
                    <thead>
                      <tr>
                        <th className="p-2 text-soc-text-muted">Actual ↓ / Predicted →</th>
                        {classifier.class_labels?.map(c => (
                          <th key={c} className="p-2 text-soc-primary font-mono">{c}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {classifier.confusion_matrix.map((row, i) => (
                        <tr key={i}>
                          <td className="p-2 text-purple-300 font-mono">{classifier.class_labels?.[i]}</td>
                          {row.map((cell, j) => (
                            <td key={j} className={`p-2 text-center font-mono ${i === j ? 'bg-green-500/20 text-green-400' : cell > 0 ? 'bg-red-500/10 text-red-400' : 'text-soc-text-muted'}`}>
                              {cell}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
