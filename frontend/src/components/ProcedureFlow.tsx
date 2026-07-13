import type { ProcedureStep } from "../types";

interface ProcedureFlowProps {
  steps: ProcedureStep[];
  currentStepId?: string;
}

export function ProcedureFlow({ steps, currentStepId }: ProcedureFlowProps) {
  const visible = steps.slice(0, 12);
  const width = Math.max(660, visible.length * 126);

  return (
    <section className="flow-section" aria-labelledby="flow-title">
      <div className="section-heading">
        <h3 id="flow-title">Procedure flow</h3>
        <span>{visible.length} visible steps</span>
      </div>
      <div className="flow-scroll" tabIndex={0} aria-label="Scrollable procedure flow">
        <svg
          className="procedure-flow"
          viewBox={`0 0 ${width} 116`}
          role="img"
          aria-label="Procedure steps and current execution position"
        >
          {visible.map((step, index) => {
            const x = 28 + index * 126;
            const active = step.id === currentStepId;
            const state = active ? "active" : (step.state ?? "pending");
            return (
              <g key={step.id} className={`flow-node ${state}`}>
                {index < visible.length - 1 && (
                  <line x1={x + 46} y1="48" x2={x + 122} y2="48" />
                )}
                <rect x={x} y="25" width="46" height="46" rx="4" />
                <text x={x + 23} y="53" textAnchor="middle">{index + 1}</text>
                <text className="flow-label" x={x + 23} y="89" textAnchor="middle">
                  {step.label.length > 15 ? `${step.label.slice(0, 13)}...` : step.label}
                </text>
              </g>
            );
          })}
          {visible.length === 0 && (
            <text x="24" y="60" className="flow-empty">No execution steps available</text>
          )}
        </svg>
      </div>
    </section>
  );
}
