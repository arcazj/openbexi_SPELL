import { AlertCircle, Code2, LogOut, RefreshCcw, ShieldCheck, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import {
  accessTokenExpiresAtMs,
  AUTH_CHANGED_EVENT,
  clearAccessToken,
  getAccessToken,
  scheduleAt,
} from "../api";
import { AccessTokenGate } from "../components/AccessTokenGate";
import {
  authenticateDevelopmentAccessToken,
  createProject,
  currentDevelopmentIdentity,
  listProjects,
} from "./api";
import { DevelopmentWorkspace } from "./DevelopmentWorkspace";
import type { DevelopmentIdentity, ProjectSummary } from "./types";

export function DevelopmentApp() {
  const [accessToken, setCurrentAccessToken] = useState(() => getAccessToken());
  const [identity, setIdentity] = useState<DevelopmentIdentity>(() => currentDevelopmentIdentity());
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(null);
  const [workspaceDirty, setWorkspaceDirty] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const authenticated = Boolean(accessToken);

  const loadProjects = useCallback(async () => {
    setLoading(true);
    try {
      const next = await listProjects();
      setProjects(next);
      setSelectedProjectId((current) => {
        if (current && next.some((project) => project.project_id === current)) return current;
        return next[0]?.project_id ?? null;
      });
      setError(null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Projects could not be loaded.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const updateAuthentication = () => {
      const token = getAccessToken();
      const active = Boolean(token);
      setCurrentAccessToken(token);
      setIdentity(currentDevelopmentIdentity());
      if (!active) {
        setProjects([]);
        setSelectedProjectId(null);
        setWorkspaceDirty(false);
      }
    };
    window.addEventListener(AUTH_CHANGED_EVENT, updateAuthentication);
    return () => window.removeEventListener(AUTH_CHANGED_EVENT, updateAuthentication);
  }, []);

  useEffect(() => {
    if (accessToken) void loadProjects();
  }, [accessToken, loadProjects]);

  useEffect(() => {
    if (!accessToken) return;
    const deadline = accessTokenExpiresAtMs(accessToken);
    if (deadline === null) return;
    return scheduleAt(deadline, clearAccessToken);
  }, [accessToken]);

  async function addProject(name: string, casePolicy: ProjectSummary["case_policy"]): Promise<void> {
    if (workspaceDirty && !window.confirm("Discard unsaved changes and create another project?")) return;
    const project = await createProject({
      name,
      case_policy: casePolicy,
      manifest: {
        schema_version: "spell.project/0.9",
        display_name: name,
        language_profile: "spell-restricted-ast/0.9",
        source_roots: ["src"],
      },
    });
    setProjects((current) => [...current, project]);
    setWorkspaceDirty(false);
    setSelectedProjectId(project.project_id);
  }

  function changeProject(projectId: string | null): void {
    if (projectId === selectedProjectId) return;
    if (workspaceDirty && !window.confirm("Discard unsaved changes and switch projects?")) return;
    setWorkspaceDirty(false);
    setSelectedProjectId(projectId);
  }

  function endSession(): void {
    if (workspaceDirty && !window.confirm("Discard unsaved changes and end this session?")) return;
    clearAccessToken();
  }

  useEffect(() => {
    if (!workspaceDirty) return;
    const preventDraftLoss = (event: BeforeUnloadEvent) => event.preventDefault();
    window.addEventListener("beforeunload", preventDraftLoss);
    return () => window.removeEventListener("beforeunload", preventDraftLoss);
  }, [workspaceDirty]);

  if (!authenticated) {
    return (
      <AccessTokenGate
        title="Development access"
        subtitle="OpenBEXI SPELL authoring environment"
        authenticate={authenticateDevelopmentAccessToken}
      />
    );
  }

  return (
    <div className="dev-app">
      <header className="dev-header">
        <div className="dev-brand" aria-label="OpenBEXI SPELL Development">
          <Code2 aria-hidden="true" size={20} />
          <div><strong>OpenBEXI SPELL</strong><span>Development environment</span></div>
        </div>
        <div className="dev-project-switcher">
          <label htmlFor="dev-project">Project</label>
          <select
            id="dev-project"
            aria-label="Project"
            value={selectedProjectId ?? ""}
            disabled={loading || projects.length === 0}
            onChange={(event) => changeProject(event.target.value || null)}
          >
            {projects.length === 0 && <option value="">No projects</option>}
            {projects.map((project) => (
              <option key={project.project_id} value={project.project_id}>{project.display_name}</option>
            ))}
          </select>
          <button
            type="button"
            className="dev-icon-button"
            title="Refresh projects"
            aria-label="Refresh projects"
            onClick={() => void loadProjects()}
            disabled={loading}
          >
            <RefreshCcw aria-hidden="true" size={16} className={loading ? "spinning" : undefined} />
          </button>
        </div>
        <div className="dev-session">
          <ShieldCheck aria-hidden="true" size={16} />
          <span><strong>{identity.subject}</strong><small>{identity.role}</small></span>
          <button type="button" title="End session" aria-label="End session" onClick={endSession}>
            <LogOut aria-hidden="true" size={16} />
          </button>
        </div>
      </header>
      {error && (
        <div className="dev-error" role="alert">
          <AlertCircle aria-hidden="true" size={16} />
          <span>{error}</span>
          <button type="button" title="Dismiss error" aria-label="Dismiss error" onClick={() => setError(null)}>
            <X aria-hidden="true" size={15} />
          </button>
        </div>
      )}
      <DevelopmentWorkspace
        key={selectedProjectId ?? "no-project"}
        identity={identity}
        selectedProjectId={selectedProjectId}
        onCreateProject={addProject}
        onProjectsChanged={loadProjects}
        onDirtyChange={setWorkspaceDirty}
        onError={setError}
      />
    </div>
  );
}
