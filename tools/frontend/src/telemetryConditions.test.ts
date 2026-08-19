import { describe, expect, it } from "vitest";
import {
  BUNDLED_TELEMETRY_CATALOG_DIGEST,
  TELEMETRY_CONDITION_ITEMS,
  createTelemetryConditionPlan,
} from "./telemetryConditions";

describe("v0.7 telemetry condition builder", () => {
  it("emits the frozen typed condition contract for bundled engineering telemetry", () => {
    const plan = createTelemetryConditionPlan({
      planId: "schedule-condition-1",
      itemId: "TM.POWER.BUS_VOLTAGE",
      operator: "GE",
      rawValue: "30.5",
    });

    expect(plan).toEqual({
      schema_version: "spell.v07.condition-plan/1",
      condition_plan_id: "schedule-condition-1",
      root: {
        type: "PREDICATE",
        node_id: "telemetry-predicate",
        operator: "GE",
        left: {
          kind: "TELEMETRY",
          item_id: "TM.POWER.BUS_VOLTAGE",
          catalog_digest: BUNDLED_TELEMETRY_CATALOG_DIGEST,
          scalar_type: "FINITE_DOUBLE",
          value_field: "ENGINEERING",
        },
        right: {
          kind: "LITERAL",
          value: { type: "FINITE_DOUBLE", value: 30.5 },
        },
      },
    });
    expect(BUNDLED_TELEMETRY_CATALOG_DIGEST).toBe(
      "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94",
    );
    expect(TELEMETRY_CONDITION_ITEMS.map((item) => item.itemId)).toEqual([
      "TM.POWER.BUS_VOLTAGE",
      "TM.POWER.SAFE_MODE",
      "TM.THERMAL.MODE",
    ]);
  });

  it("preserves boolean and string literal types and rejects unbounded input", () => {
    expect(createTelemetryConditionPlan({
      planId: "schedule-condition-safe",
      itemId: "TM.POWER.SAFE_MODE",
      operator: "EQ",
      rawValue: "false",
    }).root.right.value).toEqual({ type: "BOOLEAN", value: false });
    expect(createTelemetryConditionPlan({
      planId: "schedule-condition-mode",
      itemId: "TM.THERMAL.MODE",
      operator: "NE",
      rawValue: "WARM",
    }).root.right.value).toEqual({ type: "STRING", value: "WARM" });

    expect(() => createTelemetryConditionPlan({
      planId: "schedule-condition-safe",
      itemId: "TM.POWER.SAFE_MODE",
      operator: "GT",
      rawValue: "true",
    })).toThrow("comparison operator");
    expect(() => createTelemetryConditionPlan({
      planId: "schedule-condition-mode",
      itemId: "TM.THERMAL.MODE",
      operator: "EQ",
      rawValue: "UNKNOWN",
    })).toThrow("declared telemetry value");
    expect(() => createTelemetryConditionPlan({
      planId: "schedule-condition-voltage",
      itemId: "TM.POWER.BUS_VOLTAGE",
      operator: "GE",
      rawValue: "101",
    })).toThrow("at most 100");
  });
});
