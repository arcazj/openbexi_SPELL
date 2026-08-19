import {
  BookOpen,
  Boxes,
  ChevronLeft,
  ChevronRight,
  Database,
  Download,
  FilePlus2,
  Files,
  Folder,
  FolderPlus,
  KeyRound,
  Layers3,
  RefreshCw,
  RotateCw,
  Save,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  DATA_PAGE_SIZE,
  MAX_DATA_FILE_BYTES,
  canMutateData,
  currentDataRole,
  dataApi,
} from "../dataApi";
import type {
  DataCatalogSummary,
  DataContainerDetail,
  DataContainerSummary,
  DataContainerVariable,
  DataDictionarySummary,
  SharedDataEntry,
  SharedNamespaceDetail,
  SharedNamespaceSummary,
  TypedDataValue,
  VirtualFileEncoding,
  VirtualFileNode,
  VirtualFileRoot,
} from "../types";

type DataTab = "catalogs" | "dictionaries" | "containers" | "shared" | "files";
type Phase = "loading" | "ready" | "empty" | "error";

const tabs: Array<{ id: DataTab; label: string; icon: typeof Database }> = [
  { id: "catalogs", label: "Catalogs", icon: Layers3 },
  { id: "dictionaries", label: "Dictionaries", icon: BookOpen },
  { id: "containers", label: "Containers", icon: Boxes },
  { id: "shared", label: "Shared", icon: KeyRound },
  { id: "files", label: "Files", icon: Files },
];

const typedString = (value = ""): TypedDataValue => ({
  schema_version: "spell.data.value/1",
  type: "STRING",
  value,
});

function mutationKey(): string {
  return `console-${crypto.randomUUID()}`;
}

function message(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function compactDigest(value: string | null | undefined): string {
  return value ? `${value.slice(0, 10)}...${value.slice(-8)}` : "-";
}

function parseObjectArray(source: string): Array<{
  entry_id: string;
  qualified_name: string;
  content: Record<string, unknown>;
}> {
  const parsed = JSON.parse(source) as unknown;
  if (!Array.isArray(parsed)) throw new Error("Entries must be a JSON array");
  return parsed as Array<{
    entry_id: string;
    qualified_name: string;
    content: Record<string, unknown>;
  }>;
}

function parseTypedValue(source: string): TypedDataValue {
  const parsed = JSON.parse(source) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Typed value must be a JSON object");
  }
  const value = parsed as Record<string, unknown>;
  if (value.schema_version !== "spell.data.value/1" || typeof value.type !== "string") {
    throw new Error("Typed value envelope is invalid");
  }
  return value as TypedDataValue;
}

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function PhaseMessage({ phase, error, noun }: { phase: Phase; error: string | null; noun: string }) {
  if (phase === "loading") return <p className="data-empty">Loading {noun}...</p>;
  if (phase === "error") return <p className="data-error" role="alert">{error ?? `${noun} unavailable`}</p>;
  if (phase === "empty") return <p className="data-empty">No {noun} in this owner scope.</p>;
  return null;
}

function MutationKeyField({ value, onChange, disabled }: {
  value: string;
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  return (
    <label className="data-wide-field">
      Idempotency key
      <span className="data-key-input">
        <input value={value} onChange={(event) => onChange(event.target.value)} disabled={disabled} />
        <button
          type="button"
          aria-label="Generate idempotency key"
          title="Generate idempotency key"
          onClick={() => onChange(mutationKey())}
          disabled={disabled}
        >
          <RotateCw aria-hidden="true" size={14} />
        </button>
      </span>
    </label>
  );
}

function ResultNotice({ value }: { value: string | null }) {
  return value ? <p className="data-result" role="status">{value}</p> : null;
}

function Pager({ nextCursor, onNext, disabled }: {
  nextCursor: string | null;
  onNext: () => void;
  disabled: boolean;
}) {
  return (
    <div className="data-pager">
      <span>{nextCursor ? "More records available" : "End of result set"}</span>
      <button
        type="button"
        className="data-icon-button"
        aria-label="Load next page"
        title="Load next page"
        onClick={onNext}
        disabled={disabled || !nextCursor}
      >
        <ChevronRight aria-hidden="true" size={15} />
      </button>
    </div>
  );
}

function CatalogPanel({ ownerId, writable }: { ownerId: string; writable: boolean }) {
  const [items, setItems] = useState<DataCatalogSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState<DataCatalogSummary | null>(null);
  const [detail, setDetail] = useState<Record<string, unknown> | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);
  const [catalogId, setCatalogId] = useState("user-catalog");
  const [aclRevision, setAclRevision] = useState("1");
  const [expectedRevision, setExpectedRevision] = useState("0");
  const [kind, setKind] = useState<DataCatalogSummary["kind"]>("USER_DICTIONARY");
  const [schemaVersion, setSchemaVersion] = useState("1");
  const [entries, setEntries] = useState('[{"entry_id":"entry-1","qualified_name":"local.entry","content":{}}]');
  const [idempotency, setIdempotency] = useState(mutationKey);

  const load = useCallback(async (cursor?: string, append = false) => {
    setPhase("loading");
    setError(null);
    try {
      const page = await dataApi.catalogs(ownerId, DATA_PAGE_SIZE, cursor);
      setItems((current) => append ? [...current, ...page.catalogs] : page.catalogs);
      setNextCursor(page.next_cursor);
      setPhase(page.catalogs.length === 0 && !append ? "empty" : "ready");
    } catch (caught) {
      setError(message(caught, "Catalogs unavailable"));
      setPhase("error");
    }
  }, [ownerId]);

  useEffect(() => { void load(); }, [load]);

  const inspect = async (item: DataCatalogSummary) => {
    setSelected(item);
    setDetail(null);
    setCatalogId(item.catalog_id);
    setAclRevision(item.acl_revision);
    setExpectedRevision(item.revision);
    setKind(item.kind);
    setSchemaVersion(item.schema_version);
    try {
      const revision = await dataApi.catalogRevision(ownerId, item);
      setDetail(revision.content);
    } catch (caught) {
      setError(message(caught, "Catalog revision unavailable"));
    }
  };

  const publish = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setResult(null);
    setError(null);
    try {
      const response = await dataApi.publishCatalog({
        owner_id: ownerId,
        catalog_id: catalogId,
        acl_revision: aclRevision,
        expected_revision: expectedRevision,
        idempotency_key: idempotency,
        kind,
        schema_version: schemaVersion,
        entries: parseObjectArray(entries),
      });
      setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
      setExpectedRevision(response.new_revision);
      setIdempotency(mutationKey());
      await load();
    } catch (caught) {
      setError(message(caught, "Catalog publication failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="data-domain-layout">
      <section className="data-list-pane" aria-labelledby="catalog-list-title">
        <header><h2 id="catalog-list-title">Catalogs</h2><span>{items.length} loaded</span></header>
        <PhaseMessage phase={phase} error={error} noun="catalogs" />
        {items.length > 0 && (
          <div className="data-table-scroll">
            <table><thead><tr><th>ID</th><th>Kind</th><th>Revision</th></tr></thead>
              <tbody>{items.map((item) => (
                <tr key={item.catalog_id} className={selected?.catalog_id === item.catalog_id ? "selected" : undefined}>
                  <td><button type="button" onClick={() => void inspect(item)}>{item.catalog_id}</button></td>
                  <td>{item.kind}</td><td><code>{item.revision}</code></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
        <Pager nextCursor={nextCursor} onNext={() => void load(nextCursor ?? undefined, true)} disabled={phase === "loading"} />
      </section>
      <section className="data-detail-pane" aria-labelledby="catalog-detail-title">
        <header><h2 id="catalog-detail-title">Revision</h2><span>{selected?.catalog_id ?? "No selection"}</span></header>
        {selected ? (
          <><dl className="data-meta">
            <div><dt>Revision</dt><dd><code>{selected.revision}</code></dd></div>
            <div><dt>ACL revision</dt><dd><code>{selected.acl_revision}</code></dd></div>
            <div><dt>Schema</dt><dd>{selected.schema_version}</dd></div>
            <div><dt>Digest</dt><dd title={selected.content_digest}><code>{compactDigest(selected.content_digest)}</code></dd></div>
          </dl><pre className="data-json">{detail ? JSON.stringify(detail, null, 2) : "Loading revision..."}</pre></>
        ) : <p className="data-empty">Select a catalog revision.</p>}
      </section>
      <form className="data-action-pane" aria-labelledby="catalog-action-title" onSubmit={publish}>
        <header><h2 id="catalog-action-title">Publish revision</h2><span>{writable ? "Mutation enabled" : "Read only"}</span></header>
        <fieldset disabled={!writable || busy}>
          <div className="data-form-grid">
            <label>Catalog ID<input value={catalogId} onChange={(event) => setCatalogId(event.target.value)} required /></label>
            <label>Kind<select value={kind} onChange={(event) => setKind(event.target.value as DataCatalogSummary["kind"])}>
              <option>SCDB</option><option>GDB</option><option>PROC</option><option>MMD</option><option>USER_DICTIONARY</option>
            </select></label>
            <label>Expected revision<input value={expectedRevision} onChange={(event) => setExpectedRevision(event.target.value)} pattern="0|[1-9][0-9]*" required /></label>
            <label>ACL revision<input value={aclRevision} onChange={(event) => setAclRevision(event.target.value)} pattern="[1-9][0-9]*" required /></label>
            <label>Schema version<input value={schemaVersion} onChange={(event) => setSchemaVersion(event.target.value)} required /></label>
            <MutationKeyField value={idempotency} onChange={setIdempotency} disabled={!writable || busy} />
          </div>
          <label className="data-json-field">Entries JSON<textarea value={entries} onChange={(event) => setEntries(event.target.value)} rows={7} required /></label>
          <button className="data-primary" type="submit"><Save aria-hidden="true" size={14} />Publish</button>
        </fieldset>
        <ResultNotice value={result} />
      </form>
    </div>
  );
}

function DictionaryPanel({ ownerId, writable }: { ownerId: string; writable: boolean }) {
  const [items, setItems] = useState<DataDictionarySummary[]>([]);
  const [selected, setSelected] = useState<DataDictionarySummary | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [dictionaryId, setDictionaryId] = useState("user-dictionary");
  const [aclRevision, setAclRevision] = useState("1");
  const [expectedRevision, setExpectedRevision] = useState("0");
  const [file, setFile] = useState<File | null>(null);
  const [idempotency, setIdempotency] = useState(mutationKey);

  const load = useCallback(async (cursor?: string, append = false) => {
    setPhase("loading"); setError(null);
    try {
      const page = await dataApi.dictionaries(ownerId, DATA_PAGE_SIZE, cursor);
      setItems((current) => append ? [...current, ...page.dictionaries] : page.dictionaries);
      setNextCursor(page.next_cursor);
      setPhase(page.dictionaries.length === 0 && !append ? "empty" : "ready");
    } catch (caught) {
      setError(message(caught, "Dictionaries unavailable")); setPhase("error");
    }
  }, [ownerId]);
  useEffect(() => { void load(); }, [load]);

  const choose = (item: DataDictionarySummary) => {
    setSelected(item); setDictionaryId(item.dictionary_id); setAclRevision(item.acl_revision); setExpectedRevision(item.revision);
  };

  const importDocument = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!file) { setError("Select a dictionary document"); return; }
    setBusy(true); setError(null); setResult(null);
    try {
      const response = await dataApi.importDictionary({
        owner_id: ownerId, dictionary_id: dictionaryId, acl_revision: aclRevision,
        expected_revision: expectedRevision, idempotency_key: idempotency, document: file,
        media_type: "application/vnd.openbexi.spell.dictionary-db+json",
      });
      setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
      setExpectedRevision(response.new_revision); setIdempotency(mutationKey()); await load();
    } catch (caught) { setError(message(caught, "Dictionary import failed")); }
    finally { setBusy(false); }
  };

  const exportDocument = async () => {
    if (!selected) return;
    setBusy(true); setError(null);
    try {
      const response = await dataApi.exportDictionary({ owner_id: ownerId, dictionary_id: selected.dictionary_id, acl_revision: selected.acl_revision, revision: selected.revision });
      saveBlob(response.blob, `${selected.dictionary_id}-r${selected.revision}.spell-db.json`);
      setResult(`Exported revision ${response.revision}`);
    } catch (caught) { setError(message(caught, "Dictionary export failed")); }
    finally { setBusy(false); }
  };

  return (
    <div className="data-domain-layout">
      <section className="data-list-pane" aria-labelledby="dictionary-list-title">
        <header><h2 id="dictionary-list-title">Dictionaries</h2><span>{items.length} loaded</span></header>
        <PhaseMessage phase={phase} error={error} noun="dictionaries" />
        {items.length > 0 && <div className="data-table-scroll"><table><thead><tr><th>ID</th><th>Revision</th><th>Digest</th></tr></thead><tbody>
          {items.map((item) => <tr key={item.dictionary_id} className={selected?.dictionary_id === item.dictionary_id ? "selected" : undefined}>
            <td><button type="button" onClick={() => choose(item)}>{item.dictionary_id}</button></td><td><code>{item.revision}</code></td><td title={item.content_digest}><code>{compactDigest(item.content_digest)}</code></td>
          </tr>)}
        </tbody></table></div>}
        <Pager nextCursor={nextCursor} onNext={() => void load(nextCursor ?? undefined, true)} disabled={phase === "loading"} />
      </section>
      <section className="data-detail-pane" aria-labelledby="dictionary-detail-title">
        <header><h2 id="dictionary-detail-title">Selected dictionary</h2><span>{selected?.dictionary_id ?? "No selection"}</span></header>
        {selected ? <><dl className="data-meta">
          <div><dt>Revision</dt><dd><code>{selected.revision}</code></dd></div><div><dt>ACL revision</dt><dd><code>{selected.acl_revision}</code></dd></div>
          <div className="wide"><dt>Content digest</dt><dd title={selected.content_digest}><code>{selected.content_digest}</code></dd></div>
        </dl><button type="button" className="data-secondary" onClick={() => void exportDocument()} disabled={busy}><Download aria-hidden="true" size={14} />Export DB</button></> : <p className="data-empty">Select a dictionary.</p>}
      </section>
      <form className="data-action-pane" aria-labelledby="dictionary-action-title" onSubmit={importDocument}>
        <header><h2 id="dictionary-action-title">Import DB</h2><span>16 MiB maximum</span></header>
        <fieldset disabled={!writable || busy}>
          <div className="data-form-grid">
            <label>Dictionary ID<input value={dictionaryId} onChange={(event) => setDictionaryId(event.target.value)} required /></label>
            <label>Expected revision<input value={expectedRevision} onChange={(event) => setExpectedRevision(event.target.value)} pattern="0|[1-9][0-9]*" required /></label>
            <label>ACL revision<input value={aclRevision} onChange={(event) => setAclRevision(event.target.value)} pattern="[1-9][0-9]*" required /></label>
            <MutationKeyField value={idempotency} onChange={setIdempotency} disabled={!writable || busy} />
          </div>
          <label className="data-file-field">DB document<input type="file" accept="application/json,.json" onChange={(event) => setFile(event.target.files?.[0] ?? null)} required /></label>
          <button className="data-primary" type="submit"><Upload aria-hidden="true" size={14} />Import</button>
        </fieldset>
        {error && <p className="data-error" role="alert">{error}</p>}<ResultNotice value={result} />
      </form>
    </div>
  );
}

function ContainerPanel({ ownerId, writable }: { ownerId: string; writable: boolean }) {
  const [items, setItems] = useState<DataContainerSummary[]>([]);
  const [selected, setSelected] = useState<DataContainerSummary | null>(null);
  const [detail, setDetail] = useState<DataContainerDetail | null>(null);
  const [variables, setVariables] = useState<DataContainerVariable[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<"create" | "variable">("variable");
  const [containerId, setContainerId] = useState("data-container");
  const [aclRevision, setAclRevision] = useState("1");
  const [schemaRevision, setSchemaRevision] = useState("1");
  const [expectedRevision, setExpectedRevision] = useState("0");
  const [variableId, setVariableId] = useState("variable-1");
  const [variableRevision, setVariableRevision] = useState("0");
  const [variableName, setVariableName] = useState("value");
  const [declaredType, setDeclaredType] = useState<DataContainerVariable["declared_type"]>("STRING");
  const [typedValue, setTypedValue] = useState(JSON.stringify(typedString(), null, 2));
  const [idempotency, setIdempotency] = useState(mutationKey);

  const load = useCallback(async (cursor?: string, append = false) => {
    setPhase("loading"); setError(null);
    try {
      const page = await dataApi.containers(ownerId, DATA_PAGE_SIZE, cursor);
      setItems((current) => append ? [...current, ...page.containers] : page.containers);
      setNextCursor(page.next_cursor);
      setPhase(page.containers.length === 0 && !append ? "empty" : "ready");
    } catch (caught) { setError(message(caught, "Containers unavailable")); setPhase("error"); }
  }, [ownerId]);
  useEffect(() => { void load(); }, [load]);

  const inspect = async (item: DataContainerSummary) => {
    setSelected(item); setDetail(null); setVariables([]); setError(null);
    setContainerId(item.container_id); setAclRevision(item.acl_revision); setExpectedRevision(item.revision);
    try {
      const [container, page] = await Promise.all([
        dataApi.container(ownerId, item.container_id, item.acl_revision),
        dataApi.containerVariables(ownerId, item.container_id, item.acl_revision),
      ]);
      setDetail(container); setVariables(page.variables); setExpectedRevision(page.revision);
    } catch (caught) { setError(message(caught, "Container detail unavailable")); }
  };

  const chooseVariable = (item: DataContainerVariable) => {
    setVariableId(item.variable_id); setVariableRevision(item.revision); setVariableName(item.name);
    setDeclaredType(item.declared_type); setTypedValue(JSON.stringify(item.value, null, 2)); setMode("variable");
  };

  const mutate = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError(null); setResult(null);
    try {
      if (mode === "create") {
        const response = await dataApi.createContainer({ owner_id: ownerId, container_id: containerId, acl_revision: aclRevision, schema_revision: schemaRevision, idempotency_key: idempotency });
        setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
      } else {
        const response = await dataApi.setContainerVariable({
          owner_id: ownerId, container_id: containerId, variable_id: variableId, acl_revision: aclRevision,
          expected_revision: expectedRevision, expected_variable_revision: variableRevision,
          idempotency_key: idempotency, name: variableName, declared_type: declaredType,
          value: parseTypedValue(typedValue),
        });
        setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
        setExpectedRevision(response.new_revision);
      }
      setIdempotency(mutationKey()); await load();
      const refreshed = selected && items.find((item) => item.container_id === selected.container_id);
      if (refreshed) await inspect(refreshed);
    } catch (caught) { setError(message(caught, "Container mutation failed")); }
    finally { setBusy(false); }
  };

  const deleteVariable = async () => {
    if (!selected || !variableId) return;
    setBusy(true); setError(null); setResult(null);
    try {
      const response = await dataApi.deleteContainerVariable({
        owner_id: ownerId, container_id: selected.container_id, variable_id: variableId,
        acl_revision: selected.acl_revision, expected_revision: expectedRevision,
        expected_variable_revision: variableRevision, idempotency_key: idempotency,
      });
      setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
      setExpectedRevision(response.new_revision); setIdempotency(mutationKey()); await inspect(selected); await load();
    } catch (caught) { setError(message(caught, "Variable deletion failed")); }
    finally { setBusy(false); }
  };

  const mutable = writable && selected?.kind !== "ARGS" && detail?.mutable !== false;
  return (
    <div className="data-domain-layout">
      <section className="data-list-pane" aria-labelledby="container-list-title">
        <header><h2 id="container-list-title">Containers</h2><span>{items.length} loaded</span></header>
        <PhaseMessage phase={phase} error={error} noun="containers" />
        {items.length > 0 && <div className="data-table-scroll"><table><thead><tr><th>ID</th><th>Kind</th><th>Revision</th></tr></thead><tbody>
          {items.map((item) => <tr key={item.container_id} className={selected?.container_id === item.container_id ? "selected" : undefined}>
            <td><button type="button" onClick={() => void inspect(item)}>{item.container_id}</button></td><td>{item.kind}</td><td><code>{item.revision}</code></td>
          </tr>)}
        </tbody></table></div>}
        <Pager nextCursor={nextCursor} onNext={() => void load(nextCursor ?? undefined, true)} disabled={phase === "loading"} />
      </section>
      <section className="data-detail-pane" aria-labelledby="container-detail-title">
        <header><h2 id="container-detail-title">Variables</h2><span>{selected?.container_id ?? "No selection"}</span></header>
        {selected ? <><dl className="data-meta">
          <div><dt>Revision</dt><dd><code>{expectedRevision}</code></dd></div><div><dt>ACL revision</dt><dd><code>{selected.acl_revision}</code></dd></div>
          <div><dt>Kind</dt><dd>{selected.kind}</dd></div><div><dt>Mutable</dt><dd>{detail?.mutable === false ? "NO" : "YES"}</dd></div>
        </dl><div className="data-table-scroll"><table><thead><tr><th>Name</th><th>Type</th><th>Revision</th></tr></thead><tbody>
          {variables.length ? variables.map((item) => <tr key={item.variable_id}><td><button type="button" onClick={() => chooseVariable(item)}>{item.name}</button></td><td>{item.declared_type}</td><td><code>{item.revision}</code></td></tr>) : <tr><td colSpan={3} className="data-empty-cell">No variables</td></tr>}
        </tbody></table></div></> : <p className="data-empty">Select a container.</p>}
      </section>
      <form className="data-action-pane" aria-labelledby="container-action-title" onSubmit={mutate}>
        <header><h2 id="container-action-title">Container mutation</h2><span>{selected?.kind === "ARGS" ? "ARGS immutable" : writable ? "CAS required" : "Read only"}</span></header>
        <div className="data-segmented" role="group" aria-label="Container mutation type">
          <button type="button" aria-pressed={mode === "variable"} onClick={() => setMode("variable")}>Variable</button>
          <button type="button" aria-pressed={mode === "create"} onClick={() => setMode("create")}>New container</button>
        </div>
        <fieldset disabled={!writable || busy || (mode === "variable" && !mutable)}>
          <div className="data-form-grid">
            <label>Container ID<input value={containerId} onChange={(event) => setContainerId(event.target.value)} required /></label>
            <label>ACL revision<input value={aclRevision} onChange={(event) => setAclRevision(event.target.value)} pattern="[1-9][0-9]*" required /></label>
            {mode === "create" ? <label>Schema revision<input value={schemaRevision} onChange={(event) => setSchemaRevision(event.target.value)} pattern="[1-9][0-9]*" required /></label> : <>
              <label>Container revision<input value={expectedRevision} onChange={(event) => setExpectedRevision(event.target.value)} pattern="[1-9][0-9]*" required /></label>
              <label>Variable ID<input value={variableId} onChange={(event) => setVariableId(event.target.value)} required /></label>
              <label>Variable revision<input value={variableRevision} onChange={(event) => setVariableRevision(event.target.value)} pattern="0|[1-9][0-9]*" required /></label>
              <label>Name<input value={variableName} onChange={(event) => setVariableName(event.target.value)} required /></label>
              <label>Declared type<select value={declaredType} onChange={(event) => setDeclaredType(event.target.value as DataContainerVariable["declared_type"])}>
                <option>BOOLEAN</option><option>LONG</option><option>FLOAT</option><option>STRING</option><option>DATETIME</option><option>RELTIME</option>
              </select></label>
            </>}
            <MutationKeyField value={idempotency} onChange={setIdempotency} disabled={!writable || busy} />
          </div>
          {mode === "variable" && <label className="data-json-field">Typed value JSON<textarea value={typedValue} onChange={(event) => setTypedValue(event.target.value)} rows={7} required /></label>}
          <div className="data-form-actions"><button className="data-primary" type="submit"><Save aria-hidden="true" size={14} />{mode === "create" ? "Create" : "Set variable"}</button>
            {mode === "variable" && <button className="data-danger" type="button" onClick={() => void deleteVariable()} disabled={!selected || variableRevision === "0"}><Trash2 aria-hidden="true" size={14} />Delete variable</button>}
          </div>
        </fieldset>
        {error && <p className="data-error" role="alert">{error}</p>}<ResultNotice value={result} />
      </form>
    </div>
  );
}

function SharedPanel({ ownerId, writable }: { ownerId: string; writable: boolean }) {
  const [items, setItems] = useState<SharedNamespaceSummary[]>([]);
  const [selected, setSelected] = useState<SharedNamespaceSummary | null>(null);
  const [detail, setDetail] = useState<SharedNamespaceDetail | null>(null);
  const [entries, setEntries] = useState<SharedDataEntry[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<"entry" | "namespace">("entry");
  const [namespaceId, setNamespaceId] = useState("project-shared");
  const [scope, setScope] = useState<SharedNamespaceSummary["scope"]>("PROJECT");
  const [aclRevision, setAclRevision] = useState("1");
  const [namespaceRevision, setNamespaceRevision] = useState("1");
  const [entryKey, setEntryKey] = useState("key");
  const [entryRevision, setEntryRevision] = useState("0");
  const [typedValue, setTypedValue] = useState(JSON.stringify(typedString(), null, 2));
  const [maximumAffected, setMaximumAffected] = useState(256);
  const [idempotency, setIdempotency] = useState(mutationKey);

  const load = useCallback(async (cursor?: string, append = false) => {
    setPhase("loading"); setError(null);
    try {
      const page = await dataApi.sharedNamespaces(ownerId, DATA_PAGE_SIZE, cursor);
      setItems((current) => append ? [...current, ...page.namespaces] : page.namespaces);
      setNextCursor(page.next_cursor);
      setPhase(page.namespaces.length === 0 && !append ? "empty" : "ready");
    } catch (caught) { setError(message(caught, "Shared namespaces unavailable")); setPhase("error"); }
  }, [ownerId]);
  useEffect(() => { void load(); }, [load]);

  const inspect = async (item: SharedNamespaceSummary) => {
    setSelected(item); setDetail(null); setEntries([]); setError(null);
    setNamespaceId(item.namespace_id); setScope(item.scope); setAclRevision(item.acl_revision); setNamespaceRevision(item.revision);
    try {
      const [namespace, page] = await Promise.all([
        dataApi.sharedNamespace(ownerId, item.namespace_id, item.acl_revision, item.scope),
        dataApi.sharedEntries(ownerId, item.namespace_id, item.acl_revision, item.scope),
      ]);
      setDetail(namespace); setEntries(page.entries); setNamespaceRevision(page.revision);
    } catch (caught) { setError(message(caught, "Shared namespace unavailable")); }
  };

  const chooseEntry = (item: SharedDataEntry) => {
    setEntryKey(item.key); setEntryRevision(item.revision); setTypedValue(JSON.stringify(item.value, null, 2)); setMode("entry");
  };

  const mutate = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError(null); setResult(null);
    try {
      if (mode === "namespace") {
        const response = await dataApi.createSharedNamespace({ owner_id: ownerId, namespace_id: namespaceId, acl_revision: aclRevision, scope, idempotency_key: idempotency });
        setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
      } else {
        const response = await dataApi.putSharedEntry({
          owner_id: ownerId, namespace_id: namespaceId, key: entryKey, acl_revision: aclRevision, scope,
          expected_namespace_revision: namespaceRevision, expected_entry_revision: entryRevision,
          idempotency_key: idempotency, value: parseTypedValue(typedValue),
        });
        setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
        setNamespaceRevision(response.new_revision); setEntryRevision(response.entry_revision);
      }
      setIdempotency(mutationKey()); await load();
      if (selected) await inspect(selected);
    } catch (caught) { setError(message(caught, "Shared mutation failed")); }
    finally { setBusy(false); }
  };

  const deleteEntry = async () => {
    if (!selected || entryRevision === "0") return;
    setBusy(true); setError(null);
    try {
      const response = await dataApi.deleteSharedEntry({ owner_id: ownerId, namespace_id: selected.namespace_id, key: entryKey, acl_revision: selected.acl_revision, scope: selected.scope, expected_namespace_revision: namespaceRevision, expected_entry_revision: entryRevision, idempotency_key: idempotency });
      setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
      setIdempotency(mutationKey()); await inspect(selected); await load();
    } catch (caught) { setError(message(caught, "Shared entry deletion failed")); }
    finally { setBusy(false); }
  };

  const clearNamespace = async () => {
    if (!selected) return;
    setBusy(true); setError(null);
    try {
      const response = await dataApi.clearSharedNamespace({ owner_id: ownerId, namespace_id: selected.namespace_id, acl_revision: selected.acl_revision, scope: selected.scope, expected_namespace_revision: namespaceRevision, maximum_affected_entries: maximumAffected, idempotency_key: idempotency });
      setResult(`${response.outcome} at revision ${response.new_revision}${response.replayed ? " (replay)" : ""}`);
      setIdempotency(mutationKey()); await inspect(selected); await load();
    } catch (caught) { setError(message(caught, "Shared clear failed")); }
    finally { setBusy(false); }
  };

  const deleteNamespace = async () => {
    if (!selected) return;
    setBusy(true); setError(null);
    try {
      const response = await dataApi.deleteSharedNamespace({ owner_id: ownerId, namespace_id: selected.namespace_id, acl_revision: selected.acl_revision, scope: selected.scope, expected_namespace_revision: namespaceRevision, idempotency_key: idempotency });
      setResult(`${response.outcome}${response.replayed ? " (replay)" : ""}`);
      setSelected(null); setDetail(null); setEntries([]); setIdempotency(mutationKey()); await load();
    } catch (caught) { setError(message(caught, "Namespace deletion failed")); }
    finally { setBusy(false); }
  };

  return (
    <div className="data-domain-layout">
      <section className="data-list-pane" aria-labelledby="shared-list-title">
        <header><h2 id="shared-list-title">Namespaces</h2><span>{items.length} loaded</span></header>
        <PhaseMessage phase={phase} error={error} noun="shared namespaces" />
        {items.length > 0 && <div className="data-table-scroll"><table><thead><tr><th>ID</th><th>Scope</th><th>Revision</th></tr></thead><tbody>
          {items.map((item) => <tr key={item.namespace_id} className={selected?.namespace_id === item.namespace_id ? "selected" : undefined}>
            <td><button type="button" onClick={() => void inspect(item)}>{item.namespace_id}</button></td><td>{item.scope}</td><td><code>{item.revision}</code></td>
          </tr>)}
        </tbody></table></div>}
        <Pager nextCursor={nextCursor} onNext={() => void load(nextCursor ?? undefined, true)} disabled={phase === "loading"} />
      </section>
      <section className="data-detail-pane" aria-labelledby="shared-detail-title">
        <header><h2 id="shared-detail-title">Entries</h2><span>{selected?.namespace_id ?? "No selection"}</span></header>
        {selected ? <><dl className="data-meta">
          <div><dt>Revision</dt><dd><code>{namespaceRevision}</code></dd></div><div><dt>ACL revision</dt><dd><code>{selected.acl_revision}</code></dd></div>
          <div><dt>Scope</dt><dd>{selected.scope}</dd></div><div><dt>Entries</dt><dd>{detail?.entry_count ?? String(entries.length)}</dd></div>
        </dl><div className="data-table-scroll"><table><thead><tr><th>Key</th><th>Type</th><th>Revision</th></tr></thead><tbody>
          {entries.length ? entries.map((item) => <tr key={item.entry_id}><td><button type="button" onClick={() => chooseEntry(item)}>{item.key}</button></td><td>{item.value.type}</td><td><code>{item.revision}</code></td></tr>) : <tr><td colSpan={3} className="data-empty-cell">No entries</td></tr>}
        </tbody></table></div></> : <p className="data-empty">Select a shared namespace.</p>}
      </section>
      <form className="data-action-pane" aria-labelledby="shared-action-title" onSubmit={mutate}>
        <header><h2 id="shared-action-title">Shared mutation</h2><span>{writable ? "CAS required" : "Read only"}</span></header>
        <div className="data-segmented" role="group" aria-label="Shared mutation type"><button type="button" aria-pressed={mode === "entry"} onClick={() => setMode("entry")}>Entry</button><button type="button" aria-pressed={mode === "namespace"} onClick={() => setMode("namespace")}>New namespace</button></div>
        <fieldset disabled={!writable || busy}>
          <div className="data-form-grid">
            <label>Namespace ID<input value={namespaceId} onChange={(event) => setNamespaceId(event.target.value)} required /></label>
            <label>ACL revision<input value={aclRevision} onChange={(event) => setAclRevision(event.target.value)} pattern="[1-9][0-9]*" required /></label>
            {mode === "namespace" ? <label>Scope<input value="PROJECT" readOnly /></label> : <>
              <label>Namespace revision<input value={namespaceRevision} onChange={(event) => setNamespaceRevision(event.target.value)} pattern="[1-9][0-9]*" required /></label>
              <label>Entry key<input value={entryKey} onChange={(event) => setEntryKey(event.target.value)} required /></label>
              <label>Entry revision<input value={entryRevision} onChange={(event) => setEntryRevision(event.target.value)} pattern="0|[1-9][0-9]*" required /></label>
              <label>Clear maximum<input type="number" min={0} max={4096} value={maximumAffected} onChange={(event) => setMaximumAffected(event.target.valueAsNumber)} /></label>
            </>}
            <MutationKeyField value={idempotency} onChange={setIdempotency} disabled={!writable || busy} />
          </div>
          {mode === "entry" && <label className="data-json-field">Typed value JSON<textarea value={typedValue} onChange={(event) => setTypedValue(event.target.value)} rows={7} required /></label>}
          <div className="data-form-actions"><button className="data-primary" type="submit"><Save aria-hidden="true" size={14} />{mode === "namespace" ? "Create" : "Put entry"}</button>
            {mode === "entry" && <><button className="data-danger" type="button" onClick={() => void deleteEntry()} disabled={!selected || entryRevision === "0"}><Trash2 aria-hidden="true" size={14} />Delete entry</button><button className="data-danger" type="button" onClick={() => void clearNamespace()} disabled={!selected}>Clear</button><button className="data-danger" type="button" onClick={() => void deleteNamespace()} disabled={!selected}>Delete namespace</button></>}
          </div>
        </fieldset>
        {error && <p className="data-error" role="alert">{error}</p>}<ResultNotice value={result} />
      </form>
    </div>
  );
}

function FilePanel({ writable }: { writable: boolean }) {
  const [rootId, setRootId] = useState<VirtualFileRoot>("PROJECT_DATA");
  const [path, setPath] = useState("");
  const [items, setItems] = useState<VirtualFileNode[]>([]);
  const [selected, setSelected] = useState<VirtualFileNode | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [rootRevision, setRootRevision] = useState("");
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mode, setMode] = useState<"upload" | "directory">("upload");
  const [targetPath, setTargetPath] = useState("result.txt");
  const [expectedRevision, setExpectedRevision] = useState("0");
  const [encoding, setEncoding] = useState<VirtualFileEncoding>("UTF8_TEXT");
  const [file, setFile] = useState<File | null>(null);
  const [idempotency, setIdempotency] = useState(mutationKey);

  const load = useCallback(async (cursor?: string, append = false) => {
    setPhase("loading"); setError(null);
    try {
      const page = await dataApi.directory(rootId, path, DATA_PAGE_SIZE, cursor);
      setItems((current) => append ? [...current, ...page.items] : page.items);
      setNextCursor(page.next_cursor); setRootRevision(page.revision);
      setPhase(page.items.length === 0 && !append ? "empty" : "ready");
    } catch (caught) { setError(message(caught, "Directory unavailable")); setPhase("error"); }
  }, [path, rootId]);
  useEffect(() => { setSelected(null); void load(); }, [load]);

  const openNode = (item: VirtualFileNode) => {
    if (item.kind === "DIRECTORY") { setPath(item.virtual_path); setSelected(null); return; }
    setSelected(item); setTargetPath(item.virtual_path); setExpectedRevision(item.revision);
  };

  const parentPath = () => setPath(path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "");

  const write = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError(null); setResult(null);
    try {
      if (mode === "directory") {
        const response = await dataApi.createDirectory({ root_id: rootId, virtual_path: targetPath, expected_revision: expectedRevision, idempotency_key: idempotency });
        setResult(`Created directory revision ${response.revision}${response.replayed ? " (replay)" : ""}`);
      } else {
        if (!file) throw new Error("Select a file to upload");
        const response = await dataApi.writeFile({ root_id: rootId, virtual_path: targetPath, expected_revision: expectedRevision, encoding, idempotency_key: idempotency, file });
        setResult(`Wrote revision ${response.revision}${response.replayed ? " (replay)" : ""}`);
        setExpectedRevision(response.revision);
      }
      setIdempotency(mutationKey()); await load();
    } catch (caught) { setError(message(caught, "File mutation failed")); }
    finally { setBusy(false); }
  };

  const download = async () => {
    if (!selected || selected.kind !== "FILE") return;
    setBusy(true); setError(null);
    try {
      const response = await dataApi.readFile(rootId, selected.virtual_path, selected.revision);
      saveBlob(response.blob, selected.name);
      setResult(`Downloaded revision ${response.revision}`);
    } catch (caught) { setError(message(caught, "File download failed")); }
    finally { setBusy(false); }
  };

  const deleteNode = async () => {
    if (!selected) return;
    setBusy(true); setError(null); setResult(null);
    try {
      const response = await dataApi.deleteFileNode({ root_id: rootId, virtual_path: selected.virtual_path, expected_revision: selected.revision, idempotency_key: idempotency });
      setResult(`Deleted revision ${response.deleted_revision}${response.replayed ? " (replay)" : ""}`);
      setSelected(null); setIdempotency(mutationKey()); await load();
    } catch (caught) { setError(message(caught, "File deletion failed")); }
    finally { setBusy(false); }
  };

  return (
    <div className="data-domain-layout">
      <section className="data-list-pane" aria-labelledby="file-list-title">
        <header><h2 id="file-list-title">Virtual files</h2><span>Root revision {rootRevision || "-"}</span></header>
        <div className="data-file-location">
          <select aria-label="Virtual file root" value={rootId} onChange={(event) => { setRootId(event.target.value as VirtualFileRoot); setPath(""); }}><option value="PROJECT_DATA">PROJECT_DATA</option><option value="PROCEDURE_DATA">PROCEDURE_DATA</option></select>
          <button type="button" aria-label="Open parent directory" title="Open parent directory" onClick={parentPath} disabled={!path}><ChevronLeft aria-hidden="true" size={15} /></button>
          <code title={path}>{path || "/"}</code>
        </div>
        <PhaseMessage phase={phase} error={error} noun="nodes" />
        {items.length > 0 && <div className="data-table-scroll"><table><thead><tr><th>Name</th><th>Kind</th><th>Revision</th><th>Bytes</th></tr></thead><tbody>
          {items.map((item) => <tr key={item.virtual_path} className={selected?.virtual_path === item.virtual_path ? "selected" : undefined}>
            <td><button type="button" onClick={() => openNode(item)}>{item.kind === "DIRECTORY" ? <Folder aria-hidden="true" size={13} /> : <FilePlus2 aria-hidden="true" size={13} />}{item.name}</button></td><td>{item.kind}</td><td><code>{item.revision}</code></td><td>{item.size}</td>
          </tr>)}
        </tbody></table></div>}
        <Pager nextCursor={nextCursor} onNext={() => void load(nextCursor ?? undefined, true)} disabled={phase === "loading"} />
      </section>
      <section className="data-detail-pane" aria-labelledby="file-detail-title">
        <header><h2 id="file-detail-title">Node</h2><span>{selected?.name ?? "No selection"}</span></header>
        {selected ? <><dl className="data-meta">
          <div><dt>Revision</dt><dd><code>{selected.revision}</code></dd></div><div><dt>Kind</dt><dd>{selected.kind}</dd></div><div><dt>Bytes</dt><dd>{selected.size}</dd></div>
          <div className="wide"><dt>Path</dt><dd title={selected.virtual_path}><code>{selected.virtual_path}</code></dd></div>
          <div className="wide"><dt>Digest</dt><dd title={selected.content_sha256 ?? ""}><code>{selected.content_sha256 ?? "-"}</code></dd></div>
        </dl><div className="data-form-actions"><button type="button" className="data-secondary" onClick={() => void download()} disabled={selected.kind !== "FILE" || busy}><Download aria-hidden="true" size={14} />Download</button><button type="button" className="data-danger" onClick={() => void deleteNode()} disabled={!writable || busy}><Trash2 aria-hidden="true" size={14} />Delete</button></div></> : <p className="data-empty">Select a file or directory.</p>}
      </section>
      <form className="data-action-pane" aria-labelledby="file-action-title" onSubmit={write}>
        <header><h2 id="file-action-title">File mutation</h2><span>{writable ? "Bounded transfer" : "Read only"}</span></header>
        <div className="data-segmented" role="group" aria-label="File mutation type"><button type="button" aria-pressed={mode === "upload"} onClick={() => setMode("upload")}>Upload</button><button type="button" aria-pressed={mode === "directory"} onClick={() => setMode("directory")}>New directory</button></div>
        <fieldset disabled={!writable || busy}>
          <div className="data-form-grid">
            <label className="data-wide-field">Virtual path<input value={targetPath} onChange={(event) => setTargetPath(event.target.value)} required /></label>
            <label>Expected revision<input value={expectedRevision} onChange={(event) => setExpectedRevision(event.target.value)} pattern="0|[1-9][0-9]*" required /></label>
            {mode === "upload" && <label>Encoding<select value={encoding} onChange={(event) => setEncoding(event.target.value as VirtualFileEncoding)}><option>UTF8_TEXT</option><option>BINARY</option></select></label>}
            <MutationKeyField value={idempotency} onChange={setIdempotency} disabled={!writable || busy} />
          </div>
          {mode === "upload" && <label className="data-file-field">File (maximum {Math.floor(MAX_DATA_FILE_BYTES / 1_048_576)} MiB)<input type="file" onChange={(event) => setFile(event.target.files?.[0] ?? null)} required /></label>}
          <button className="data-primary" type="submit">{mode === "upload" ? <Upload aria-hidden="true" size={14} /> : <FolderPlus aria-hidden="true" size={14} />}{mode === "upload" ? "Upload" : "Create directory"}</button>
        </fieldset>
        {error && <p className="data-error" role="alert">{error}</p>}<ResultNotice value={result} />
      </form>
    </div>
  );
}

export function DataServiceWorkspace() {
  const [activeTab, setActiveTab] = useState<DataTab>("catalogs");
  const [ownerDraft, setOwnerDraft] = useState("local-project");
  const [ownerId, setOwnerId] = useState("local-project");
  const role = useMemo(currentDataRole, []);
  const writable = canMutateData(role);

  const selectTab = (tab: DataTab, focus = false) => {
    setActiveTab(tab);
    if (focus) window.setTimeout(() => document.getElementById(`data-tab-${tab}`)?.focus(), 0);
  };

  const moveTab = (event: React.KeyboardEvent, current: DataTab) => {
    const index = tabs.findIndex((tab) => tab.id === current);
    let next = index;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    else return;
    event.preventDefault();
    const target = tabs[next];
    if (target) selectTab(target.id, true);
  };

  return (
    <main className="data-service-workspace" aria-label="Data services workspace">
      <header className="data-workspace-header">
        <div><span className="data-eyebrow"><Database aria-hidden="true" size={14} />Local data services</span><h1>Data services</h1></div>
        <form onSubmit={(event) => { event.preventDefault(); setOwnerId(ownerDraft.trim()); }}>
          <label>Owner scope<input value={ownerDraft} onChange={(event) => setOwnerDraft(event.target.value)} required /></label>
          <button type="submit" className="data-secondary"><RefreshCw aria-hidden="true" size={14} />Apply</button>
        </form>
        <span className={`data-role ${writable ? "writable" : "readonly"}`}><ShieldCheck aria-hidden="true" size={14} />{role === "unknown" ? "READ ONLY" : role.toUpperCase()}</span>
      </header>
      <div className="data-tabs" role="tablist" aria-label="Data service domains">
        {tabs.map(({ id, label, icon: Icon }) => <button key={id} id={`data-tab-${id}`} type="button" role="tab" aria-selected={activeTab === id} aria-controls={`data-panel-${id}`} tabIndex={activeTab === id ? 0 : -1} onClick={() => selectTab(id)} onKeyDown={(event) => moveTab(event, id)}><Icon aria-hidden="true" size={14} /><span>{label}</span></button>)}
      </div>
      <div id={`data-panel-${activeTab}`} className="data-domain-panel" role="tabpanel" aria-labelledby={`data-tab-${activeTab}`}>
        {activeTab === "catalogs" && <CatalogPanel ownerId={ownerId} writable={writable} />}
        {activeTab === "dictionaries" && <DictionaryPanel ownerId={ownerId} writable={writable} />}
        {activeTab === "containers" && <ContainerPanel ownerId={ownerId} writable={writable} />}
        {activeTab === "shared" && <SharedPanel ownerId={ownerId} writable={writable} />}
        {activeTab === "files" && <FilePanel writable={writable} />}
      </div>
    </main>
  );
}
