import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CodeEditor } from "./CodeEditor";
import { ProjectManifestDialog } from "./ProjectManifestDialog";
import { DevelopmentWorkspace } from "./DevelopmentWorkspace";
import { LEGACY_LANGUAGE_PROFILE, V19_LANGUAGE_PROFILE } from "./profiles";
import type { ProjectSummary, ResourceDocument } from "./types";

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe("v0.19 authoring profile", () => {
  it("offers supported native calls and inserts explicit independent confirmation", () => {
    const onChange = vi.fn();
    const text = "command = BuildTC('CMDNAME')\nSend(command=command, Confirm=True)\nDisplay('done')\n";
    const document = {
      resource_id: "source", project_id: "project", path: "src/command.spell.py", kind: "PROCEDURE",
      content: text, revision: 1, metadata: { language_profile: V19_LANGUAGE_PROFILE },
      language: { diagnostics: [], outline: [], completions: [] },
    } as unknown as ResourceDocument;
    const view = render(<CodeEditor document={document} content={text} dirty={false} canEdit saving={false}
      catalogEntries={[]} diagnostics={[]} onChange={onChange} onSave={vi.fn()} />);
    for (const name of ["BuildTC", "Send", "Display", "GetTM", "Verify", "WaitFor"]) {
      expect(screen.getByRole("option", { name })).toBeInTheDocument();
    }
    expect([...view.container.querySelectorAll(".syntax-keyword")].map((item) => item.textContent)).toEqual(expect.arrayContaining(["BuildTC", "Send", "Display"]));
    const snippet = "command = BuildTC('CMDNAME')\nSend(command=command, Confirm=True)\n";
    fireEvent.change(screen.getByLabelText("Insert snippet"), { target: { value: snippet } });
    expect(onChange).toHaveBeenLastCalledWith(expect.stringContaining(snippet));
    const prompt = "answer = Prompt('Continue?', Type=YES_NO)\n";
    fireEvent.change(screen.getByLabelText("Insert snippet"), { target: { value: prompt } });
    expect(onChange).toHaveBeenLastCalledWith(expect.stringContaining(prompt));
  });

  it("retains the selected profile while editing other manifest properties", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    const project = {
      project_id: "project", display_name: "Observations", owner_subject: "author", case_policy: "CASE_SENSITIVE",
      manifest: { language_profile: V19_LANGUAGE_PROFILE, source_roots: ["src"], owners: ["author"], policy_labels: ["LOCAL_SYNTHETIC_NON_CUI_ONLY"], catalog_dependencies: [] },
    } as unknown as ProjectSummary;
    render(<ProjectManifestDialog project={project} folderPaths={["src"]} canEdit busy={false} onClose={vi.fn()} onSave={onSave} />);
    expect(screen.getByLabelText("Language profile")).toHaveValue(V19_LANGUAGE_PROFILE);
    fireEvent.submit(screen.getByRole("dialog"));
    expect(onSave).toHaveBeenCalledWith(expect.objectContaining({ language_profile: V19_LANGUAGE_PROFILE }));
  });

  it("creates a v19 project by default and permits explicit legacy authoring", async () => {
    const create = vi.fn().mockResolvedValue(undefined);
    render(<DevelopmentWorkspace identity={{ subject: "author", role: "operator" }} selectedProjectId={null}
      onCreateProject={create} onProjectsChanged={vi.fn()} onDirtyChange={vi.fn()} onError={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Create project" }));
    expect(screen.getByLabelText("Language profile")).toHaveValue(V19_LANGUAGE_PROFILE);
    fireEvent.change(screen.getByLabelText("Project name"), { target: { value: "Legacy" } });
    fireEvent.change(screen.getByLabelText("Language profile"), { target: { value: LEGACY_LANGUAGE_PROFILE } });
    fireEvent.submit(screen.getByRole("dialog"));
    expect(create).toHaveBeenCalledWith("Legacy", "CASE_SENSITIVE", LEGACY_LANGUAGE_PROFILE);
  });
});
