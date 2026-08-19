import {
  Braces,
  Columns3,
  ChevronDown,
  ChevronUp,
  FoldVertical,
  ListPlus,
  PanelRight,
  Replace,
  Save,
  Search,
  Trash2,
  WandSparkles,
  UnfoldVertical,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { DevelopmentDiagnostic, PinnedCatalogItem, ProcedureMetadata, ResourceDocument } from "./types";

interface OutlineItem {
  label: string;
  kind: string;
  line: number;
  column?: number;
}

interface CodeEditorProps {
  document: ResourceDocument;
  content: string;
  dirty: boolean;
  canEdit: boolean;
  saving: boolean;
  catalogEntries: PinnedCatalogItem[];
  diagnostics: DevelopmentDiagnostic[];
  insertRequest?: { key: string; value: string } | null;
  navigationTarget?: { key: string; line: number; column: number } | null;
  onChange: (value: string) => void;
  onSave: () => void;
}

// Mirrors ProcedureCatalog._step_calls and _Compiler._reserved_calls.
const SPELL_CALLS = [
  "ARGS", "AddSharedDataScope", "ClearSharedData", "ClearSharedDataScopes", "CloseFile",
  "CreateDictionary", "DataContainer", "DeleteFile", "File", "GetSharedData", "GetSharedDataKeys",
  "GetSharedDataScopes", "GetTM", "Label", "LoadDictionary", "Log", "OpenFile", "Prompt",
  "ReadDirectory", "ReadFile", "SaveDictionary", "SetSharedData", "StartProc", "Telemetry", "UserAction",
  "Var", "Verify", "Wait", "WaitFor", "WriteFile",
] as const;
const LANGUAGE_KEYWORDS = ["def", "if", "elif", "else", "for", "in", "and", "or", "not", "True", "False", "None", "bool", "float", "int", "str", "range"] as const;
const LANGUAGE_TOKENS = [...LANGUAGE_KEYWORDS, ...SPELL_CALLS].join("|");
const TOKEN_PATTERN = new RegExp(`(#[^\\n]*|'[^'\\n]*'|"[^"\\n]*"|\\b(?:${LANGUAGE_TOKENS})\\b|\\b\\d+(?:\\.\\d+)?\\b)`, "g");
const TOKEN_EXACT = new RegExp(`^(?:#[^\\n]*|'[^'\\n]*'|"[^"\\n]*"|(?:${LANGUAGE_TOKENS})|\\d+(?:\\.\\d+)?)$`);

function tokenClass(token: string): string {
  if (token.startsWith("#")) return "syntax-comment";
  if (token.startsWith("'") || token.startsWith('"')) return "syntax-string";
  if (/^\d/.test(token)) return "syntax-number";
  return "syntax-keyword";
}

function highlightedTokens(value: string, keyPrefix: string) {
  return value.split(TOKEN_PATTERN).map((token, tokenIndex) => (
    TOKEN_EXACT.test(token)
      ? <span key={`${keyPrefix}-${tokenIndex}`} className={tokenClass(token)}>{token}</span>
      : <span key={`${keyPrefix}-${tokenIndex}`}>{token}</span>
  ));
}

function highlightedLine(line: string, lineIndex: number, diagnostics: DevelopmentDiagnostic[]) {
  const lineNumber = lineIndex + 1;
  const matches = diagnostics.filter((item) => item.start_line <= lineNumber && item.end_line >= lineNumber);
  const boundaries = new Set<number>([0, line.length]);
  matches.forEach((item) => {
    const start = item.start_line === lineNumber ? Math.max(0, item.start_column - 1) : 0;
    const end = item.end_line === lineNumber ? Math.min(line.length, Math.max(start + 1, item.end_column)) : line.length;
    boundaries.add(Math.min(line.length, start));
    boundaries.add(end);
  });
  const offsets = [...boundaries].sort((left, right) => left - right);
  return (
    <span key={lineIndex} className="syntax-line">
      {offsets.slice(0, -1).map((start, segmentIndex) => {
        const end = offsets[segmentIndex + 1] ?? line.length;
        const active = matches.filter((item) => {
          const itemStart = item.start_line === lineNumber ? Math.max(0, item.start_column - 1) : 0;
          const itemEnd = item.end_line === lineNumber ? Math.min(line.length, Math.max(itemStart + 1, item.end_column)) : line.length;
          return itemStart < end && itemEnd > start;
        });
        const segment = highlightedTokens(line.slice(start, end), `${lineIndex}-${segmentIndex}`);
        if (active.length === 0) return segment;
        const title = active.map((item) => `${item.code} ${item.start_line}:${item.start_column}-${item.end_line}:${item.end_column}: ${item.message}`).join("\n");
        return <mark key={`diagnostic-${start}-${end}`} className="syntax-diagnostic" title={title}>{segment}</mark>;
      })}
    </span>
  );
}

function lineColumn(content: string, offset: number): { line: number; column: number } {
  const before = content.slice(0, Math.max(0, Math.min(offset, content.length))).split("\n");
  return { line: before.length - 1, column: before.at(-1)?.length ?? 0 };
}

export function applyRectangularEdit(content: string, start: number, end: number, replacement: string): string {
  const lines = content.split("\n");
  const first = lineColumn(content, Math.min(start, end));
  const last = lineColumn(content, Math.max(start, end));
  const from = Math.min(first.column, last.column);
  const to = Math.max(first.column, last.column);
  const finalLine = Math.min(last.line, first.line + 255);
  for (let index = first.line; index <= finalLine; index += 1) {
    const line = lines[index] ?? "";
    const padded = line.padEnd(from, " ");
    lines[index] = `${padded.slice(0, from)}${replacement.slice(0, 1024)}${padded.slice(Math.min(to, padded.length))}`;
  }
  return lines.join("\n");
}

export function formatProcedureSource(content: string): string {
  const normalized = content.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
  return normalized.endsWith("\n") ? normalized : `${normalized}\n`;
}

function buildOutline(content: string): OutlineItem[] {
  const result: OutlineItem[] = [];
  content.split("\n").forEach((line, index) => {
    const definition = line.match(/^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)/);
    const label = line.match(/^\s*Label\(\s*["']([A-Za-z][A-Za-z0-9_.-]{0,127})["']/);
    const call = line.match(new RegExp(`^\\s*(${SPELL_CALLS.join("|")})\\s*\\(`));
    const header = line.match(/^\s*#\s*@procedure\s+(.+)/);
    if (definition) result.push({ label: definition[1] ?? "definition", kind: "FUNCTION", line: index + 1 });
    else if (label) result.push({ label: label[1] ?? "label", kind: "LABEL", line: index + 1 });
    else if (call) result.push({ label: call[1] ?? "call", kind: "SPELL_CALL", line: index + 1 });
    else if (header) result.push({ label: header[1] ?? "procedure", kind: "header", line: index + 1 });
  });
  return result.slice(0, 5000);
}

function metadataHeader(metadata: ProcedureMetadata): string {
  return [
    `# @procedure ${metadata.procedure_id}`,
    `# @display-name ${metadata.display_name}`,
    `# @description ${metadata.description}`,
    `# @language-profile ${metadata.language_profile}`,
  ].join("\n");
}

function previewMetadataFromSource(content: string, path: string): ProcedureMetadata | null {
  const field = (name: string) => content.match(new RegExp(`^\\s*#\\s*@${name}\\s+(.+)$`, "m"))?.[1]?.trim() ?? "";
  const procedureId = field("procedure");
  if (!procedureId) return null;
  const fallbackName = path.split("/").at(-1)?.replace(/\.spell\.py$/i, "").replace(/\.[^.]+$/, "") ?? procedureId;
  return {
    procedure_id: procedureId,
    display_name: field("display-name") || fallbackName,
    description: field("description"),
    language_profile: field("language-profile") || "spell-restricted-ast/0.9",
    arguments: {},
    catalog_dependencies: [],
  };
}

export function CodeEditor({
  document,
  content,
  dirty,
  canEdit,
  saving,
  catalogEntries,
  diagnostics,
  insertRequest,
  navigationTarget,
  onChange,
  onSave,
}: CodeEditorProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const highlightRef = useRef<HTMLPreElement>(null);
  const gutterRef = useRef<HTMLPreElement>(null);
  const [find, setFind] = useState("");
  const [replace, setReplace] = useState("");
  const [matchIndex, setMatchIndex] = useState(-1);
  const [columnText, setColumnText] = useState("");
  const [folded, setFolded] = useState(false);
  const [showInspector, setShowInspector] = useState(true);
  const [inspectorTab, setInspectorTab] = useState<"outline" | "metadata" | "references" | "snippets">("outline");
  const [snippetName, setSnippetName] = useState("");
  const [snippetBody, setSnippetBody] = useState("");
  const [customSnippets, setCustomSnippets] = useState<Array<{ label: string; value: string }>>(() => {
    try {
      const value = JSON.parse(localStorage.getItem("spell.v09.custom-snippets") ?? "[]") as unknown;
      return Array.isArray(value) ? value.filter((item): item is { label: string; value: string } => typeof item === "object" && item !== null && typeof (item as { label?: unknown }).label === "string" && typeof (item as { value?: unknown }).value === "string").slice(0, 100) : [];
    } catch {
      return [];
    }
  });
  const [metadata, setMetadata] = useState<ProcedureMetadata | null>(document.metadata);
  const outline = useMemo(() => content === document.content && document.language
    ? document.language.outline.map((item) => ({ label: item.name, kind: item.kind, line: item.line, column: item.column }))
    : buildOutline(content), [content, document.content, document.language]);
  const lines = useMemo(() => content.split("\n"), [content]);

  useEffect(() => {
    setMetadata(content === document.content ? document.metadata : previewMetadataFromSource(content, document.path));
  }, [content, document.content, document.metadata, document.path]);

  useEffect(() => {
    setMatchIndex(-1);
    setFolded(false);
  }, [document.resource_id]);

  function syncScroll() {
    if (!textareaRef.current) return;
    if (highlightRef.current) {
      highlightRef.current.scrollTop = textareaRef.current.scrollTop;
      highlightRef.current.scrollLeft = textareaRef.current.scrollLeft;
    }
    if (gutterRef.current) gutterRef.current.scrollTop = textareaRef.current.scrollTop;
  }

  function navigateTo(line: number, column = 1) {
    const textarea = textareaRef.current;
    if (!textarea) return;
    setFolded(false);
    const lineStart = lines.slice(0, Math.max(0, line - 1)).reduce((total, value) => total + value.length + 1, 0);
    const offset = Math.min(content.length, lineStart + Math.max(0, column - 1));
    requestAnimationFrame(() => {
      textarea.focus();
      textarea.setSelectionRange(offset, offset);
      const lineHeight = 20;
      textarea.scrollTop = Math.max(0, (line - 3) * lineHeight);
      syncScroll();
    });
  }

  useEffect(() => {
    if (navigationTarget) navigateTo(navigationTarget.line, navigationTarget.column);
  }, [navigationTarget?.key]);

  useEffect(() => {
    if (insertRequest?.value) insertText(insertRequest.value);
  }, [insertRequest?.key]);

  function findNext(direction: 1 | -1) {
    const textarea = textareaRef.current;
    if (!textarea || !find) return;
    const lower = content.toLowerCase();
    const needle = find.toLowerCase();
    const origin = matchIndex >= 0 ? matchIndex + (direction > 0 ? needle.length : -1) : textarea.selectionStart;
    let next = direction > 0 ? lower.indexOf(needle, origin) : lower.lastIndexOf(needle, origin);
    if (next < 0) next = direction > 0 ? lower.indexOf(needle) : lower.lastIndexOf(needle);
    if (next >= 0) {
      setMatchIndex(next);
      textarea.focus();
      textarea.setSelectionRange(next, next + needle.length);
    }
  }

  function insertText(value: string) {
    const textarea = textareaRef.current;
    if (!textarea || !canEdit) return;
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const next = `${content.slice(0, start)}${value}${content.slice(end)}`;
    onChange(next);
    requestAnimationFrame(() => {
      textarea.focus();
      textarea.setSelectionRange(start + value.length, start + value.length);
    });
  }

  function replaceCurrent() {
    const textarea = textareaRef.current;
    if (!textarea || !canEdit || !find) return;
    const selected = content.slice(textarea.selectionStart, textarea.selectionEnd);
    if (selected.toLowerCase() !== find.toLowerCase()) {
      findNext(1);
      return;
    }
    const start = textarea.selectionStart;
    const next = `${content.slice(0, start)}${replace}${content.slice(textarea.selectionEnd)}`;
    onChange(next);
    setMatchIndex(start);
    requestAnimationFrame(() => textarea.setSelectionRange(start, start + replace.length));
  }

  function replaceAll() {
    if (!canEdit || !find) return;
    const escaped = find.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    onChange(content.replace(new RegExp(escaped, "gi"), () => replace));
    setMatchIndex(-1);
  }

  function rectangularEdit() {
    const textarea = textareaRef.current;
    if (!textarea || !canEdit || textarea.selectionStart === textarea.selectionEnd) return;
    onChange(applyRectangularEdit(content, textarea.selectionStart, textarea.selectionEnd, columnText));
  }

  function applyMetadata() {
    if (!metadata) return;
    const withoutHeader = content.replace(/^(?:#\s*@(?:procedure|display-name|description|language-profile).*\n){1,4}/, "");
    onChange(`${metadataHeader(metadata)}\n${withoutHeader}`);
  }

  const completionItems = document.language?.completions.map((item) => item.insert_text) ?? [...SPELL_CALLS];
  const snippets = [
    { label: "Insert snippet", value: "" },
    { label: "Guarded log", value: "ready: bool = True\nif ready:\n    Log('Verified')\n" },
    { label: "Operator prompt", value: "Prompt('Continue?', type='YES_NO', default='YES', response_timeout=30)\n" },
    { label: "Bounded wait", value: "Wait(1)\nLog('Wait complete')\n" },
    ...customSnippets,
  ];

  return (
    <div className={`dev-editor ${showInspector ? "with-inspector" : ""}`}>
      <div className="dev-editor-toolbar" role="toolbar" aria-label="Editor commands">
        <span className="dev-file-identity" title={document.path}>
          <Braces aria-hidden="true" size={15} />
          <strong>{document.path.split("/").pop()}</strong>
          {dirty && <i aria-label="Unsaved changes" />}
        </span>
        <div className="dev-find">
          <Search aria-hidden="true" size={14} />
          <label className="sr-only" htmlFor="dev-editor-find">Find in resource</label>
          <input
            id="dev-editor-find"
            value={find}
            placeholder="Find"
            onChange={(event) => { setFind(event.target.value); setMatchIndex(-1); }}
            onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); findNext(event.shiftKey ? -1 : 1); } }}
          />
          <button type="button" title="Previous match" aria-label="Previous match" onClick={() => findNext(-1)} disabled={!find}>
            <ChevronUp aria-hidden="true" size={14} />
          </button>
          <button type="button" title="Next match" aria-label="Next match" onClick={() => findNext(1)} disabled={!find}>
            <ChevronDown aria-hidden="true" size={14} />
          </button>
          <label className="sr-only" htmlFor="dev-editor-replace">Replace in resource</label>
          <input id="dev-editor-replace" value={replace} placeholder="Replace" onChange={(event) => setReplace(event.target.value)} />
          <button type="button" title="Replace current match" aria-label="Replace current match" onClick={replaceCurrent} disabled={!canEdit || !find}><Replace aria-hidden="true" size={14} /></button>
          <button type="button" title="Replace all matches" aria-label="Replace all matches" onClick={replaceAll} disabled={!canEdit || !find}><ListPlus aria-hidden="true" size={14} /></button>
        </div>
        <select
          aria-label="Insert completion"
          defaultValue=""
          disabled={!canEdit}
          onChange={(event) => { if (event.target.value) insertText(event.target.value); event.target.value = ""; }}
        >
          <option value="">Completion</option>
          {completionItems.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
        <select
          aria-label="Insert snippet"
          defaultValue=""
          disabled={!canEdit}
          onChange={(event) => { if (event.target.value) insertText(event.target.value); event.target.value = ""; }}
        >
          {snippets.map((snippet) => <option key={snippet.label} value={snippet.value}>{snippet.label}</option>)}
        </select>
        <button type="button" title={folded ? "Unfold source" : "Fold source to outline"} aria-label={folded ? "Unfold source" : "Fold source to outline"} onClick={() => setFolded((value) => !value)}>
          {folded ? <UnfoldVertical aria-hidden="true" size={15} /> : <FoldVertical aria-hidden="true" size={15} />}
        </button>
        <div className="dev-column-edit">
          <label className="sr-only" htmlFor="dev-column-text">Rectangular edit text</label>
          <input id="dev-column-text" value={columnText} maxLength={1024} placeholder="Column text" onChange={(event) => setColumnText(event.target.value)} onKeyDown={(event) => { if (event.altKey && event.shiftKey && event.key.toLowerCase() === "i") { event.preventDefault(); rectangularEdit(); } }} />
          <button type="button" title="Apply rectangular edit to selected lines (Alt+Shift+I)" aria-label="Apply rectangular edit" onClick={rectangularEdit} disabled={!canEdit}><Columns3 aria-hidden="true" size={15} /></button>
        </div>
        <button type="button" title="Format source deterministically" aria-label="Format source" onClick={() => onChange(formatProcedureSource(content))} disabled={!canEdit}>
          <WandSparkles aria-hidden="true" size={15} />
        </button>
        <button type="button" title="Toggle inspector" aria-label="Toggle inspector" aria-pressed={showInspector} onClick={() => setShowInspector((value) => !value)}>
          <PanelRight aria-hidden="true" size={15} />
        </button>
        <button type="button" className="dev-primary-icon" title="Save resource" aria-label="Save resource" onClick={onSave} disabled={!canEdit || !dirty || saving}>
          <Save aria-hidden="true" size={15} />
        </button>
      </div>
      <div className="dev-code-region">
        {folded ? (
          <div className="dev-folded-source" aria-label="Folded source outline">
            {outline.length === 0 ? <span>No foldable symbols</span> : outline.map((item) => (
              <button key={`${item.line}-${item.label}`} type="button" onClick={() => navigateTo(item.line)}>
                <small>{item.line}</small><strong>{item.label}</strong><span>{item.kind}</span>
              </button>
            ))}
          </div>
        ) : (
          <div className="dev-code-stack">
            <pre ref={gutterRef} className="dev-line-gutter" aria-hidden="true">
              {lines.map((_, index) => `${index + 1}\n`).join("")}
            </pre>
            <div className="dev-code-input">
              <pre ref={highlightRef} className="dev-syntax-layer" aria-hidden="true">
                {lines.map((line, index) => highlightedLine(line, index, diagnostics))}
              </pre>
              <textarea
                ref={textareaRef}
                aria-label="Procedure source editor"
                value={content}
                readOnly={!canEdit}
                spellCheck={false}
                wrap="off"
                onChange={(event) => onChange(event.target.value)}
                onScroll={syncScroll}
                onKeyDown={(event) => {
                  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
                    event.preventDefault();
                    if (dirty && canEdit) onSave();
                  }
                  if (event.key === "Tab" && canEdit) {
                    event.preventDefault();
                    insertText("    ");
                  }
                  if (event.altKey && event.shiftKey && event.key.toLowerCase() === "i" && canEdit) {
                    event.preventDefault();
                    rectangularEdit();
                  }
                }}
              />
            </div>
          </div>
        )}
      </div>
      {showInspector && (
        <aside className="dev-editor-inspector" aria-label="Resource inspector">
          <div className="dev-subtabs" role="tablist" aria-label="Inspector views">
            {(["outline", "metadata", "references", "snippets"] as const).map((tab) => (
              <button key={tab} type="button" role="tab" aria-selected={inspectorTab === tab} onClick={() => setInspectorTab(tab)}>{tab}</button>
            ))}
          </div>
          {inspectorTab === "outline" && (
            <div className="dev-outline-list">
              {outline.length === 0 ? <div className="dev-empty">No symbols</div> : outline.map((item) => (
                <button key={`${item.line}-${item.label}`} type="button" onClick={() => navigateTo(item.line)}>
                  <span>{item.label}</span><small>{item.kind} : {item.line}</small>
                </button>
              ))}
            </div>
          )}
          {inspectorTab === "metadata" && (
            <div className="dev-metadata-form">
              {metadata ? (
                <>
                  <label>Procedure ID<input value={metadata.procedure_id} disabled={!canEdit} onChange={(event) => setMetadata({ ...metadata, procedure_id: event.target.value })} /></label>
                  <label>Display name<input value={metadata.display_name} disabled={!canEdit} onChange={(event) => setMetadata({ ...metadata, display_name: event.target.value })} /></label>
                  <label>Description<textarea value={metadata.description} disabled={!canEdit} onChange={(event) => setMetadata({ ...metadata, description: event.target.value })} /></label>
                  <label>Language profile<input value={metadata.language_profile} readOnly /></label>
                  <button type="button" className="dev-secondary-command" onClick={applyMetadata} disabled={!canEdit}>Apply header</button>
                </>
              ) : <div className="dev-empty">No procedure metadata</div>}
            </div>
          )}
          {inspectorTab === "references" && (
            <div className="dev-reference-list">
              {catalogEntries.length === 0 ? <div className="dev-empty">No pinned catalog entries</div> : catalogEntries.slice(0, 100).map((entry) => (
                <button key={entry.entry_id} type="button" onClick={() => insertText(`'${entry.qualified_name}'`)} disabled={!canEdit}>
                  <span>{entry.qualified_name}</span><small>{entry.catalog_kind} / {String(entry.data.value_type ?? entry.data.type ?? "-")}</small>
                </button>
              ))}
            </div>
          )}
          {inspectorTab === "snippets" && (
            <div className="dev-snippet-manager">
              <label>Name<input value={snippetName} maxLength={80} disabled={!canEdit} onChange={(event) => setSnippetName(event.target.value)} /></label>
              <label>Body<textarea value={snippetBody} maxLength={8192} disabled={!canEdit} onChange={(event) => setSnippetBody(event.target.value)} /></label>
              <button type="button" className="dev-secondary-command" disabled={!canEdit || !snippetName.trim() || !snippetBody} onClick={() => {
                const next = [...customSnippets.filter((item) => item.label !== snippetName.trim()), { label: snippetName.trim(), value: snippetBody }].slice(-100);
                setCustomSnippets(next);
                localStorage.setItem("spell.v09.custom-snippets", JSON.stringify(next));
                setSnippetName("");
                setSnippetBody("");
              }}>Add custom snippet</button>
              {customSnippets.map((snippet) => <div key={snippet.label} className="dev-snippet-row"><button type="button" disabled={!canEdit} onClick={() => insertText(snippet.value)}>{snippet.label}</button><button type="button" aria-label={`Delete snippet ${snippet.label}`} disabled={!canEdit} onClick={() => { const next = customSnippets.filter((item) => item.label !== snippet.label); setCustomSnippets(next); localStorage.setItem("spell.v09.custom-snippets", JSON.stringify(next)); }}><Trash2 aria-hidden="true" size={13} /></button></div>)}
            </div>
          )}
        </aside>
      )}
      <footer className="dev-editor-status">
        <span>{document.kind}</span><span>UTF-8</span><span>LF</span><span>{lines.length} lines</span><span>rev {document.revision}</span>
      </footer>
    </div>
  );
}
