import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ProcedureFlow } from "./ProcedureFlow";

describe("ProcedureFlow", () => {
  it("renders an accessible flow and marks the active step", () => {
    const { container } = render(
      <ProcedureFlow
        currentStepId="1"
        steps={[
          { id: "0", line: 1, label: "Initialize", state: "complete" },
          { id: "1", line: 2, label: "Acquire telemetry", state: "active" },
        ]}
      />,
    );
    expect(screen.getByRole("img", { name: /procedure steps/i })).toBeInTheDocument();
    expect(container.querySelectorAll(".flow-node.active")).toHaveLength(1);
  });
});
