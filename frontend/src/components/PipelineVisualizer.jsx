import { ChevronRight, CheckCircle2 } from 'lucide-react';

const PIPELINE_STEPS = [
  { id: 'ingestion', label: 'Traffic Ingestion' },
  { id: 'feature_extraction', label: 'Feature Extraction' },
  { id: 'detection', label: 'Normalization' },
  { id: 'anomaly_detection', label: 'Anomaly Detection' },
  { id: 'classification', label: 'Classification' },
  { id: 'complete', label: 'Scoring & Alerts' },
];

export default function PipelineVisualizer({ currentStage }) {
  const currentIdx = PIPELINE_STEPS.findIndex((s) => s.id === currentStage);

  return (
    <div className="pipeline">
      {PIPELINE_STEPS.map((step, i) => {
        let status = 'pending';
        if (i < currentIdx) status = 'completed';
        else if (i === currentIdx) status = 'active';

        return (
          <div key={step.id} style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
            <div className={`pipeline-step ${status}`}>
              {status === 'completed' && <CheckCircle2 size={14} />}
              {step.label}
            </div>
            {i < PIPELINE_STEPS.length - 1 && (
              <ChevronRight className="pipeline-arrow" size={16} />
            )}
          </div>
        );
      })}
    </div>
  );
}
