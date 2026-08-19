import { Copy, Plus, Search, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import type {
  DictionaryDbDocument,
  DictionaryDbEntry,
  DictionaryDocument,
  DictionaryImpDocument,
  DictionaryImpRecord,
  DictionaryTypedValue,
  PinnedCatalogItem,
} from "./types";

const DB_MEDIA_TYPE = "application/vnd.openbexi.spell.dictionary-db+json";
const IMP_MEDIA_TYPE = "application/vnd.openbexi.spell.dictionary-imp+json";
const VALUE_TYPES: DictionaryTypedValue["type"][] = [
  "NULL", "BOOLEAN", "INT64", "UINT64", "DECIMAL", "FINITE_DOUBLE", "STRING", "BYTES",
  "UTC_DATETIME", "REL_DURATION", "LIST", "MAP",
];

interface StructuredEditorProps {
  content: string;
  canEdit: boolean;
  onChange: (value: string) => void;
  onMediaTypeChange?: (mediaType: string) => void;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value !== "object" || value === null) return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, canonicalize(item)]),
  );
}

async function sha256(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(canonicalize(value)));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function defaultTypedValue(): DictionaryTypedValue {
  return { schema_version: "spell.data.value/1", type: "STRING", value: "" };
}

function defaultWireValue(type: DictionaryTypedValue["type"]): unknown {
  if (type === "NULL") return null;
  if (type === "BOOLEAN") return false;
  if (type === "LIST" || type === "MAP") return [];
  return "";
}

async function serializeDocument(document: DictionaryDocument): Promise<string> {
  const unsigned = { ...document } as Record<string, unknown>;
  delete unsigned.content_digest;
  return `${JSON.stringify({ ...unsigned, content_digest: await sha256(unsigned) }, null, 2)}\n`;
}

function isTypedValue(value: unknown): value is DictionaryTypedValue {
  if (typeof value !== "object" || value === null) return false;
  const item = value as Record<string, unknown>;
  return item.schema_version === "spell.data.value/1"
    && typeof item.type === "string"
    && VALUE_TYPES.includes(item.type as DictionaryTypedValue["type"])
    && Object.keys(item).sort().join(",") === "schema_version,type,value";
}

function parseDictionary(content: string): DictionaryDocument | null {
  try {
    const value = JSON.parse(content) as Record<string, unknown>;
    if (value.schema_version === "spell.dictionary.db/1" && value.format === "DB" && Array.isArray(value.entries)) {
      if (!value.entries.every((entry) => typeof entry === "object" && entry !== null && isTypedValue((entry as Record<string, unknown>).value))) return null;
      return value as unknown as DictionaryDbDocument;
    }
    if (value.schema_version === "spell.dictionary.imp/1" && value.format === "IMP" && Array.isArray(value.records)) {
      return value as unknown as DictionaryImpDocument;
    }
    return null;
  } catch {
    return null;
  }
}

export async function createEmptyDictionary(dictionaryId: string, format: "DB" | "IMP" = "DB"): Promise<{ content: string; mediaType: string }> {
  const base = {
    base_revision: 0,
    content_digest: "",
    dictionary_id: dictionaryId,
  };
  const document: DictionaryDocument = format === "DB"
    ? { ...base, entries: [], format: "DB", schema_version: "spell.dictionary.db/1" }
    : { ...base, records: [], format: "IMP", schema_version: "spell.dictionary.imp/1" };
  return {
    content: await serializeDocument(document),
    mediaType: format === "DB" ? DB_MEDIA_TYPE : IMP_MEDIA_TYPE,
  };
}

function valueText(value: DictionaryTypedValue): string {
  return typeof value.value === "string" ? value.value : JSON.stringify(value.value);
}

function parseWireValue(type: DictionaryTypedValue["type"], value: string): unknown {
  if (type === "STRING" || type === "BYTES" || type === "UTC_DATETIME" || type === "INT64"
    || type === "UINT64" || type === "DECIMAL" || type === "REL_DURATION") return value;
  if (type === "NULL") return null;
  if (type === "BOOLEAN") return value.toLowerCase() === "true";
  if (type === "FINITE_DOUBLE") return Number(value);
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return value;
  }
}

export function DictionaryEditor({ content, canEdit, onChange, onMediaTypeChange }: StructuredEditorProps) {
  const document = useMemo(() => parseDictionary(content), [content]);
  if (!document) {
    return <div className="dev-structured-error" role="status">Invalid strict DB/IMP document. Use Source to repair schema fields or digests.</div>;
  }

  async function emit(next: DictionaryDocument) {
    onMediaTypeChange?.(next.format === "DB" ? DB_MEDIA_TYPE : IMP_MEDIA_TYPE);
    onChange(await serializeDocument(next));
  }

  async function updateDbEntry(index: number, patch: Partial<DictionaryDbEntry>) {
    if (document?.format !== "DB") return;
    const entries = await Promise.all(document.entries.map(async (entry, entryIndex) => {
      if (entryIndex !== index) return entry;
      const next = { ...entry, ...patch };
      return { ...next, value_digest: await sha256(next.value) };
    }));
    await emit({ ...document, entries });
  }

  async function updateImpRecord(index: number, patch: Partial<DictionaryImpRecord>) {
    if (document?.format !== "IMP") return;
    const records = await Promise.all(document.records.map(async (record, recordIndex) => {
      if (recordIndex !== index) return record;
      const next = { ...record, ...patch };
      if (next.operation === "DELETE") {
        return { operation: "DELETE", entry_id: next.entry_id, expected_entry_revision: Math.max(1, next.expected_entry_revision) } as DictionaryImpRecord;
      }
      const value = next.value ?? defaultTypedValue();
      return { ...next, qualified_name: next.qualified_name ?? "NEW_ENTRY", value, value_digest: await sha256(value) };
    }));
    await emit({ ...document, records });
  }

  return (
    <div className="dev-structured-editor">
      <div className="dev-structured-heading">
        <div><h3>{document.format} dictionary</h3><small>{document.schema_version}</small></div>
        <label>Dictionary ID<input value={document.dictionary_id} disabled={!canEdit} onChange={(event) => void emit({ ...document, dictionary_id: event.target.value })} /></label>
        <label>Base revision<input type="number" min={0} value={document.base_revision} disabled={!canEdit} onChange={(event) => void emit({ ...document, base_revision: Number(event.target.value) })} /></label>
      </div>
      <div className="dev-table-scroll">
        <table>
          <thead><tr><th>Operation</th><th>Entry ID</th><th>Qualified name</th><th>Type</th><th>Value</th><th>Revision</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {document.format === "DB" ? document.entries.map((entry, index) => (
              <tr key={`${entry.entry_id}-${index}`}>
                <td>SNAPSHOT</td>
                <td><input aria-label={`Dictionary entry ID ${index + 1}`} value={entry.entry_id} disabled={!canEdit} onChange={(event) => void updateDbEntry(index, { entry_id: event.target.value })} /></td>
                <td><input aria-label={`Dictionary qualified name ${index + 1}`} value={entry.qualified_name} disabled={!canEdit} onChange={(event) => void updateDbEntry(index, { qualified_name: event.target.value })} /></td>
                <td><select aria-label={`Dictionary type ${index + 1}`} value={entry.value.type} disabled={!canEdit} onChange={(event) => void updateDbEntry(index, { value: { ...entry.value, type: event.target.value as DictionaryTypedValue["type"], value: defaultWireValue(event.target.value as DictionaryTypedValue["type"]) } })}>{VALUE_TYPES.map((type) => <option key={type}>{type}</option>)}</select></td>
                <td><input aria-label={`Dictionary value ${index + 1}`} value={valueText(entry.value)} disabled={!canEdit} onChange={(event) => void updateDbEntry(index, { value: { ...entry.value, value: parseWireValue(entry.value.type, event.target.value) } })} /></td>
                <td>base</td>
                <td><button type="button" title="Delete dictionary entry" aria-label={`Delete dictionary entry ${entry.entry_id}`} disabled={!canEdit} onClick={() => void emit({ ...document, entries: document.entries.filter((_, itemIndex) => itemIndex !== index) })}><Trash2 aria-hidden="true" size={14} /></button></td>
              </tr>
            )) : document.records.map((record, index) => (
              <tr key={`${record.entry_id}-${index}`}>
                <td><select aria-label={`Import operation ${index + 1}`} value={record.operation} disabled={!canEdit} onChange={(event) => void updateImpRecord(index, { operation: event.target.value as DictionaryImpRecord["operation"] })}><option>UPSERT</option><option>DELETE</option></select></td>
                <td><input aria-label={`Import entry ID ${index + 1}`} value={record.entry_id} disabled={!canEdit} onChange={(event) => void updateImpRecord(index, { entry_id: event.target.value })} /></td>
                <td><input aria-label={`Import qualified name ${index + 1}`} value={record.qualified_name ?? ""} disabled={!canEdit || record.operation === "DELETE"} onChange={(event) => void updateImpRecord(index, { qualified_name: event.target.value })} /></td>
                <td><select aria-label={`Import type ${index + 1}`} value={record.value?.type ?? "STRING"} disabled={!canEdit || record.operation === "DELETE"} onChange={(event) => void updateImpRecord(index, { value: { schema_version: "spell.data.value/1", type: event.target.value as DictionaryTypedValue["type"], value: defaultWireValue(event.target.value as DictionaryTypedValue["type"]) } })}>{VALUE_TYPES.map((type) => <option key={type}>{type}</option>)}</select></td>
                <td><input aria-label={`Import value ${index + 1}`} value={record.value ? valueText(record.value) : ""} disabled={!canEdit || record.operation === "DELETE"} onChange={(event) => { const value = record.value ?? defaultTypedValue(); void updateImpRecord(index, { value: { ...value, value: parseWireValue(value.type, event.target.value) } }); }} /></td>
                <td><input aria-label={`Expected entry revision ${index + 1}`} type="number" min={record.operation === "DELETE" ? 1 : 0} value={record.expected_entry_revision} disabled={!canEdit} onChange={(event) => void updateImpRecord(index, { expected_entry_revision: Number(event.target.value) })} /></td>
                <td><button type="button" title="Delete import record" aria-label={`Delete import record ${record.entry_id}`} disabled={!canEdit} onClick={() => void emit({ ...document, records: document.records.filter((_, itemIndex) => itemIndex !== index) })}><Trash2 aria-hidden="true" size={14} /></button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button type="button" className="dev-secondary-command" disabled={!canEdit} onClick={() => {
        if (document.format === "DB") {
          const value = defaultTypedValue();
          void sha256(value).then((valueDigest) => emit({ ...document, entries: [...document.entries, { entry_id: crypto.randomUUID(), qualified_name: "NEW_ENTRY", value, value_digest: valueDigest }] }));
        } else {
          const value = defaultTypedValue();
          void sha256(value).then((valueDigest) => emit({ ...document, records: [...document.records, { operation: "UPSERT", entry_id: crypto.randomUUID(), expected_entry_revision: 0, qualified_name: "NEW_ENTRY", value, value_digest: valueDigest }] }));
        }
      }}><Plus aria-hidden="true" size={14} /> Add {document.format === "DB" ? "entry" : "record"}</button>
    </div>
  );
}

interface CatalogBrowserProps {
  entries: PinnedCatalogItem[];
  canInsert: boolean;
  onInsert: (value: string) => void;
}

const CATALOG_KINDS = ["TM", "TC", "RESOURCE", "SCDB", "GDB", "PROC", "MMD"] as const;
type CatalogKindFilter = "ALL" | PinnedCatalogItem["catalog_kind"];
type CatalogFieldFilter = "ALL" | "QUALIFIED_NAME" | "ENTRY_ID" | "CATALOG_ID" | "CATALOG_REVISION" | "VALUE_TYPE" | "DESCRIPTION";
const MAX_CATALOG_QUERY_LENGTH = 256;
const MAX_CATALOG_RESULTS = 500;

function catalogData(entry: PinnedCatalogItem): Record<string, unknown> | null {
  return typeof entry.data === "object" && entry.data !== null && !Array.isArray(entry.data)
    ? entry.data
    : null;
}

function catalogFieldValue(entry: PinnedCatalogItem, field: CatalogFieldFilter): string {
  const data = catalogData(entry);
  if (!data) return "";
  const values: Record<Exclude<CatalogFieldFilter, "ALL">, string> = {
    QUALIFIED_NAME: entry.qualified_name,
    ENTRY_ID: entry.entry_id,
    CATALOG_ID: entry.catalog_id,
    CATALOG_REVISION: String(entry.catalog_revision),
    VALUE_TYPE: String(data.value_type ?? data.type ?? ""),
    DESCRIPTION: String(data.description ?? ""),
  };
  return field === "ALL" ? Object.values(values).join(" ") : values[field];
}

export function catalogReferenceSnippet(entry: Pick<PinnedCatalogItem, "qualified_name">): string {
  return JSON.stringify(entry.qualified_name);
}

export function CatalogBrowser({ entries, canInsert, onInsert }: CatalogBrowserProps) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState<CatalogKindFilter>("ALL");
  const [field, setField] = useState<CatalogFieldFilter>("ALL");
  const literal = query.toLowerCase();
  const matching = entries.filter((entry) => catalogData(entry) !== null
    && (kind === "ALL" || entry.catalog_kind === kind)
    && catalogFieldValue(entry, field).toLowerCase().includes(literal));
  const filtered = matching.slice(0, MAX_CATALOG_RESULTS);
  return (
    <div className="dev-structured-editor dev-catalog-browser">
      <div className="dev-structured-heading"><div><h3>Pinned catalog</h3><small>read-only local snapshot</small></div><span>{filtered.length} / {matching.length}</span></div>
      <div className="dev-catalog-filters">
        <label><Search aria-hidden="true" size={14} /><span className="sr-only">Filter catalog</span><input aria-label="Filter catalog" maxLength={MAX_CATALOG_QUERY_LENGTH} value={query} onChange={(event) => setQuery(event.target.value)} /></label>
        <label className="dev-catalog-select"><span>Field</span><select aria-label="Catalog filter field" value={field} onChange={(event) => setField(event.target.value as CatalogFieldFilter)}>
          <option value="ALL">All fields</option><option value="QUALIFIED_NAME">Qualified name</option><option value="ENTRY_ID">Entry ID</option><option value="CATALOG_ID">Catalog ID</option><option value="CATALOG_REVISION">Revision</option><option value="VALUE_TYPE">Value type</option><option value="DESCRIPTION">Description</option>
        </select></label>
        <label className="dev-catalog-select"><span>Kind</span><select aria-label="Catalog kind" value={kind} onChange={(event) => setKind(event.target.value as CatalogKindFilter)}>
          <option value="ALL">All kinds</option>{CATALOG_KINDS.map((item) => <option key={item} value={item}>{item}</option>)}
        </select></label>
      </div>
      <div className="dev-table-scroll"><table><thead><tr><th>Kind</th><th>Qualified name</th><th>Type</th><th>Description</th><th>Pin</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
        {filtered.map((entry) => {
          const data = catalogData(entry);
          if (!data) return null;
          return <tr key={`${entry.catalog_id}-${entry.entry_id}`}><td>{entry.catalog_kind}</td><td><code>{entry.qualified_name}</code></td><td>{String(data.value_type ?? data.type ?? "-")}</td><td>{String(data.description ?? "")}</td><td><code title={entry.content_digest}>{entry.catalog_id}@{entry.catalog_revision}</code></td><td><button type="button" title="Insert catalog reference" aria-label={`Insert ${entry.qualified_name}`} disabled={!canInsert} onClick={() => onInsert(catalogReferenceSnippet(entry))}><Copy aria-hidden="true" size={14} /></button></td></tr>;
        })}
      </tbody></table></div>
      {filtered.length === 0 && <div className="dev-empty">No pinned entries match this filter</div>}
    </div>
  );
}
