import type {
  TelemetryComparisonOperator,
  TelemetryConditionPlan,
  TelemetryConditionScalarType,
} from "./types";

export const BUNDLED_TELEMETRY_CATALOG_DIGEST =
  "5cc5323c10c18e3b5e4d0b9eec0a12f0e896274821e488f85160dc6fde718d94";

export const TELEMETRY_COMPARISON_LABELS: Readonly<Record<TelemetryComparisonOperator, string>> = {
  EQ: "=",
  NE: "!=",
  LT: "<",
  LE: "<=",
  GT: ">",
  GE: ">=",
};

export interface TelemetryConditionItem {
  itemId: string;
  label: string;
  scalarType: TelemetryConditionScalarType;
  unit: string;
  operators: readonly TelemetryComparisonOperator[];
  defaultValue: string;
  minimum?: number;
  maximum?: number;
  step?: number;
  valueOptions?: readonly { value: string; label: string }[];
}

export const TELEMETRY_CONDITION_ITEMS = [
  {
    itemId: "TM.POWER.BUS_VOLTAGE",
    label: "Bus voltage",
    scalarType: "FINITE_DOUBLE",
    unit: "V",
    operators: ["EQ", "NE", "LT", "LE", "GT", "GE"],
    defaultValue: "28",
    minimum: 0,
    maximum: 100,
    step: 0.001,
  },
  {
    itemId: "TM.POWER.SAFE_MODE",
    label: "Safe mode",
    scalarType: "BOOLEAN",
    unit: "",
    operators: ["EQ", "NE"],
    defaultValue: "true",
    valueOptions: [
      { value: "true", label: "True" },
      { value: "false", label: "False" },
    ],
  },
  {
    itemId: "TM.THERMAL.MODE",
    label: "Thermal mode",
    scalarType: "STRING",
    unit: "",
    operators: ["EQ", "NE"],
    defaultValue: "NOMINAL",
    valueOptions: [
      { value: "NOMINAL", label: "Nominal" },
      { value: "WARM", label: "Warm" },
      { value: "SAFE", label: "Safe" },
    ],
  },
] as const satisfies readonly TelemetryConditionItem[];

export function telemetryConditionItem(itemId: string): TelemetryConditionItem | undefined {
  return TELEMETRY_CONDITION_ITEMS.find((item) => item.itemId === itemId);
}

function literalValue(item: TelemetryConditionItem, rawValue: string): boolean | number | string {
  const trimmed = rawValue.trim();
  if (item.scalarType === "BOOLEAN") {
    if (trimmed !== "true" && trimmed !== "false") {
      throw new Error("Boolean telemetry conditions require true or false.");
    }
    return trimmed === "true";
  }
  if (item.scalarType === "FINITE_DOUBLE") {
    if (!trimmed) throw new Error("Telemetry threshold is required.");
    const value = Number(trimmed);
    if (!Number.isFinite(value)) throw new Error("Telemetry threshold must be finite.");
    if (item.minimum !== undefined && value < item.minimum) {
      throw new Error(`Telemetry threshold must be at least ${item.minimum}.`);
    }
    if (item.maximum !== undefined && value > item.maximum) {
      throw new Error(`Telemetry threshold must be at most ${item.maximum}.`);
    }
    return value;
  }
  if (item.scalarType === "STRING") {
    if (!item.valueOptions?.some((option) => option.value === trimmed)) {
      throw new Error("Select a declared telemetry value.");
    }
    return trimmed;
  }
  throw new Error("The selected telemetry scalar type is not available in this builder.");
}

export function createTelemetryConditionPlan(input: {
  planId: string;
  itemId: string;
  operator: TelemetryComparisonOperator;
  rawValue: string;
}): TelemetryConditionPlan {
  const item = telemetryConditionItem(input.itemId);
  if (!item) throw new Error("Select a bundled telemetry item.");
  if (!item.operators.includes(input.operator)) {
    throw new Error("The comparison operator is not valid for the selected telemetry item.");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(input.planId)) {
    throw new Error("Telemetry condition identity is invalid.");
  }
  return {
    schema_version: "spell.v07.condition-plan/1",
    condition_plan_id: input.planId,
    root: {
      type: "PREDICATE",
      node_id: "telemetry-predicate",
      operator: input.operator,
      left: {
        kind: "TELEMETRY",
        item_id: item.itemId,
        catalog_digest: BUNDLED_TELEMETRY_CATALOG_DIGEST,
        scalar_type: item.scalarType,
        value_field: "ENGINEERING",
      },
      right: {
        kind: "LITERAL",
        value: {
          type: item.scalarType,
          value: literalValue(item, input.rawValue),
        },
      },
    },
  };
}
