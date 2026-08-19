import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { dataApi } from "../dataApi";
import type { DataCatalogSummary } from "../types";
import { DataServiceWorkspace } from "./DataServiceWorkspace";

const catalog: DataCatalogSummary = {
  acl_revision: "1",
  catalog_id: "catalog-1",
  content_digest: "a".repeat(64),
  kind: "USER_DICTIONARY",
  revision: "9007199254740995",
  schema_version: "1",
};

function token(role: "viewer" | "operator" | "admin"): string {
  return `e30.${btoa(JSON.stringify({ role, sub: `${role}-subject` }))}.signature`;
}

function mockCatalogs() {
  return vi.spyOn(dataApi, "catalogs").mockResolvedValue({
    catalogs: [catalog],
    next_cursor: null,
    owner_revision: "9007199254740997",
  });
}

beforeEach(() => {
  window.sessionStorage.setItem("openbexi.spell.access-token", token("viewer"));
});

afterEach(() => {
  cleanup();
  window.sessionStorage.clear();
  vi.restoreAllMocks();
});

describe("DataServiceWorkspace", () => {
  it("renders every data domain and keeps viewer mutations disabled", async () => {
    mockCatalogs();
    vi.spyOn(dataApi, "dictionaries").mockResolvedValue({ dictionaries: [], next_cursor: null, owner_revision: "1" });
    render(<DataServiceWorkspace />);

    const workspace = screen.getByRole("main", { name: "Data services workspace" });
    expect(within(workspace).getByRole("heading", { name: "Data services" })).toBeInTheDocument();
    expect(within(workspace).getByText("VIEWER")).toBeInTheDocument();
    expect(await within(workspace).findByRole("button", { name: "catalog-1" })).toBeEnabled();
    expect(within(workspace).getByText("9007199254740995")).toBeInTheDocument();
    expect(within(workspace).getByRole("button", { name: "Publish" })).toBeDisabled();

    const catalogTab = within(workspace).getByRole("tab", { name: "Catalogs" });
    catalogTab.focus();
    fireEvent.keyDown(catalogTab, { key: "ArrowRight" });
    const dictionaryTab = within(workspace).getByRole("tab", { name: "Dictionaries" });
    await waitFor(() => expect(dictionaryTab).toHaveAttribute("aria-selected", "true"));
    expect(dictionaryTab).toHaveFocus();
    expect(await within(workspace).findByText("No dictionaries in this owner scope.")).toBeInTheDocument();

    for (const label of ["Catalogs", "Dictionaries", "Containers", "Shared", "Files"]) {
      expect(within(workspace).getByRole("tab", { name: label })).toBeInTheDocument();
    }
  });

  it("publishes with opaque decimal revisions and an explicit idempotency key", async () => {
    window.sessionStorage.setItem("openbexi.spell.access-token", token("operator"));
    const catalogs = mockCatalogs();
    const publish = vi.spyOn(dataApi, "publishCatalog").mockResolvedValue({
      ...catalog,
      revision: "1",
      new_revision: "1",
      prior_revision: "0",
      operation_id: "operation-1",
      outcome: "PUBLISHED",
      replayed: false,
    });
    const user = userEvent.setup();
    render(<DataServiceWorkspace />);

    expect(await screen.findByRole("button", { name: "catalog-1" })).toBeEnabled();
    expect(screen.getByText("OPERATOR")).toBeInTheDocument();
    await user.clear(screen.getByLabelText("Catalog ID"));
    await user.type(screen.getByLabelText("Catalog ID"), "new-catalog");
    await user.click(screen.getByRole("button", { name: "Publish" }));

    await waitFor(() => expect(publish).toHaveBeenCalledTimes(1));
    expect(publish).toHaveBeenCalledWith(expect.objectContaining({
      acl_revision: "1",
      catalog_id: "new-catalog",
      expected_revision: "0",
      idempotency_key: expect.stringMatching(/^console-/),
      owner_id: "local-project",
    }));
    expect(screen.getByRole("status")).toHaveTextContent("PUBLISHED at revision 1");
    expect(catalogs).toHaveBeenCalledTimes(2);
  });

  it("loads an exact catalog revision without converting its identifier", async () => {
    mockCatalogs();
    const revision = vi.spyOn(dataApi, "catalogRevision").mockResolvedValue({
      ...catalog,
      closure_digest: "b".repeat(64),
      content: { entries: [{ entry_id: "entry-1" }] },
    });
    render(<DataServiceWorkspace />);

    await userEvent.click(await screen.findByRole("button", { name: "catalog-1" }));
    expect(revision).toHaveBeenCalledWith("local-project", expect.objectContaining({
      revision: "9007199254740995",
    }));
    expect(await screen.findByText(/"entry_id": "entry-1"/)).toBeInTheDocument();
  });

  it("surfaces a bounded API error and preserves retryable owner scope", async () => {
    vi.spyOn(dataApi, "catalogs").mockRejectedValue(new Error("catalog boundary offline"));
    render(<DataServiceWorkspace />);
    expect(await screen.findByRole("alert")).toHaveTextContent("catalog boundary offline");
    expect(screen.getByLabelText("Owner scope")).toHaveValue("local-project");
  });
});
