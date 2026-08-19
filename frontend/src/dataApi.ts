import { ApiError, clearAccessToken, currentControlProof, getAccessToken } from "./api";
import type {
  DataCatalogPage,
  DataCatalogPublishInput,
  DataCatalogRevision,
  DataCatalogSummary,
  DataContainerDetail,
  DataContainerPage,
  DataContainerVariable,
  DataContainerVariablePage,
  DataDictionaryPage,
  DataMutationResult,
  DataRevision,
  DataRole,
  SharedDataEntry,
  SharedDataEntryPage,
  SharedNamespaceDetail,
  SharedNamespacePage,
  TypedDataValue,
  VirtualDirectoryPage,
  VirtualFileContent,
  VirtualFileEncoding,
  VirtualFileRoot,
} from "./types";

const DATA_API_ROOT = "/api/v1/data";
export const MAX_DATA_FILE_BYTES = 16_777_216;
export const DATA_PAGE_SIZE = 100;

type MutationHeaders = {
  idempotencyKey: string;
  contentType?: string;
  contentSha256?: string;
};

function decodeJwtPayload(): Record<string, unknown> | null {
  const token = getAccessToken();
  if (!token) return null;
  try {
    const segment = token.split(".")[1];
    if (!segment) return null;
    const normalized = segment.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const parsed = JSON.parse(atob(padded)) as unknown;
    return typeof parsed === "object" && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function currentDataRole(): DataRole {
  const role = decodeJwtPayload()?.role;
  return role === "viewer" || role === "operator" || role === "admin" ? role : "unknown";
}

export function canMutateData(role = currentDataRole()): boolean {
  return role === "operator" || role === "admin";
}

function headers(extra?: HeadersInit): Headers {
  const result = new Headers(extra);
  const token = getAccessToken();
  if (token) result.set("Authorization", `Bearer ${token}`);
  return result;
}

function mutationHeaders(options: MutationHeaders): Headers {
  const proof = currentControlProof();
  const result = headers({
    "Content-Type": options.contentType ?? "application/json",
    "Idempotency-Key": options.idempotencyKey,
    "X-Spell-Client-Instance-Key-Id": proof.client_instance_key_id,
    "X-Spell-Session-Id": proof.session_id,
  });
  if (options.contentSha256) result.set("Content-SHA256", options.contentSha256);
  return result;
}

async function responseError(response: Response): Promise<ApiError> {
  const body = (await response.json().catch(() => null)) as unknown;
  if (response.status === 401) clearAccessToken();
  const record = typeof body === "object" && body !== null
    ? body as Record<string, unknown>
    : null;
  const nested = record && typeof record.detail === "object" && record.detail !== null
    ? record.detail as Record<string, unknown>
    : null;
  const code = String(record?.code ?? nested?.code ?? "");
  const detailValue = nested?.message ?? nested?.detail ?? (nested ? null : record?.detail);
  const detail = String(detailValue ?? response.statusText ?? "Request rejected");
  return new ApiError(code ? `${code}: ${detail}` : detail, response.status, body);
}

async function jsonRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${DATA_API_ROOT}${path}`, {
    ...init,
    headers: headers(init?.headers),
  });
  if (!response.ok) throw await responseError(response);
  return await response.json() as T;
}

function pageParameters(ownerId: string, pageSize: number, cursor?: string): URLSearchParams {
  const query = new URLSearchParams({ owner_id: ownerId, page_size: String(pageSize) });
  if (cursor) query.set("cursor", cursor);
  return query;
}

function resourceParameters(ownerId: string, aclRevision: DataRevision): URLSearchParams {
  return new URLSearchParams({ owner_id: ownerId, acl_revision: aclRevision });
}

function sharedResourceParameters(
  ownerId: string,
  aclRevision: DataRevision,
  scope: SharedNamespaceDetail["scope"],
): URLSearchParams {
  const query = resourceParameters(ownerId, aclRevision);
  query.set("scope", scope);
  return query;
}

async function sha256Hex(payload: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", payload);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export const dataApi = {
  async catalogs(ownerId: string, pageSize = DATA_PAGE_SIZE, cursor?: string): Promise<DataCatalogPage> {
    return jsonRequest(`/catalogs?${pageParameters(ownerId, pageSize, cursor).toString()}`);
  },

  async catalogRevision(
    ownerId: string,
    catalog: Pick<DataCatalogSummary, "catalog_id" | "acl_revision" | "revision">,
  ): Promise<DataCatalogRevision> {
    const query = resourceParameters(ownerId, catalog.acl_revision);
    return jsonRequest(
      `/catalogs/${encodeURIComponent(catalog.catalog_id)}/revisions/${encodeURIComponent(catalog.revision)}?${query.toString()}`,
    );
  },

  async publishCatalog(input: DataCatalogPublishInput): Promise<DataMutationResult & DataCatalogSummary> {
    const query = resourceParameters(input.owner_id, input.acl_revision);
    return jsonRequest(
      `/catalogs/${encodeURIComponent(input.catalog_id)}/revisions?${query.toString()}`,
      {
        method: "POST",
        headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
        body: JSON.stringify({
          expected_revision: input.expected_revision,
          kind: input.kind,
          schema_version: input.schema_version,
          entries: input.entries,
          dependencies: input.dependencies ?? [],
        }),
      },
    );
  },

  async dictionaries(ownerId: string, pageSize = DATA_PAGE_SIZE, cursor?: string): Promise<DataDictionaryPage> {
    return jsonRequest(`/dictionaries?${pageParameters(ownerId, pageSize, cursor).toString()}`);
  },

  async importDictionary(input: {
    owner_id: string;
    dictionary_id: string;
    acl_revision: DataRevision;
    expected_revision: DataRevision;
    idempotency_key: string;
    document: Blob;
    media_type: "application/vnd.openbexi.spell.dictionary-db+json" | "application/vnd.openbexi.spell.dictionary-imp+json";
  }): Promise<DataMutationResult & { dictionary_id: string; revision: DataRevision; content_digest: string }> {
    if (input.document.size > MAX_DATA_FILE_BYTES) throw new Error("Dictionary import exceeds 16 MiB");
    const content = await input.document.arrayBuffer();
    const digest = await sha256Hex(content);
    const query = resourceParameters(input.owner_id, input.acl_revision);
    query.set("expected_revision", input.expected_revision);
    return jsonRequest(
      `/dictionaries/${encodeURIComponent(input.dictionary_id)}/imports?${query.toString()}`,
      {
        method: "POST",
        headers: mutationHeaders({
          idempotencyKey: input.idempotency_key,
          contentType: input.media_type,
          contentSha256: digest,
        }),
        body: input.document,
      },
    );
  },

  async exportDictionary(input: {
    owner_id: string;
    dictionary_id: string;
    acl_revision: DataRevision;
    revision: DataRevision;
  }): Promise<VirtualFileContent> {
    const query = resourceParameters(input.owner_id, input.acl_revision);
    query.set("format", "DB");
    const response = await fetch(
      `${DATA_API_ROOT}/dictionaries/${encodeURIComponent(input.dictionary_id)}/revisions/${encodeURIComponent(input.revision)}/exports?${query.toString()}`,
      { headers: headers() },
    );
    if (!response.ok) throw await responseError(response);
    return {
      blob: await response.blob(),
      content_sha256: response.headers.get("Content-SHA256") ?? "",
      encoding: "UTF8_TEXT",
      revision: response.headers.get("X-Spell-Revision") ?? input.revision,
    };
  },

  async containers(ownerId: string, pageSize = DATA_PAGE_SIZE, cursor?: string): Promise<DataContainerPage> {
    return jsonRequest(`/containers?${pageParameters(ownerId, pageSize, cursor).toString()}`);
  },

  async createContainer(input: {
    owner_id: string;
    container_id: string;
    acl_revision: DataRevision;
    schema_revision: DataRevision;
    idempotency_key: string;
  }): Promise<DataMutationResult & DataContainerDetail> {
    const query = resourceParameters(input.owner_id, input.acl_revision);
    query.set("container_id", input.container_id);
    return jsonRequest(`/containers?${query.toString()}`, {
      method: "POST",
      headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
      body: JSON.stringify({ expected_revision: "0", schema_revision: input.schema_revision }),
    });
  },

  async container(
    ownerId: string,
    containerId: string,
    aclRevision: DataRevision,
  ): Promise<DataContainerDetail> {
    return jsonRequest(
      `/containers/${encodeURIComponent(containerId)}?${resourceParameters(ownerId, aclRevision).toString()}`,
    );
  },

  async containerVariables(
    ownerId: string,
    containerId: string,
    aclRevision: DataRevision,
    pageSize = DATA_PAGE_SIZE,
    cursor?: string,
  ): Promise<DataContainerVariablePage> {
    const query = resourceParameters(ownerId, aclRevision);
    query.set("page_size", String(pageSize));
    if (cursor) query.set("cursor", cursor);
    return jsonRequest(`/containers/${encodeURIComponent(containerId)}/variables?${query.toString()}`);
  },

  async setContainerVariable(input: {
    owner_id: string;
    container_id: string;
    variable_id: string;
    acl_revision: DataRevision;
    expected_revision: DataRevision;
    expected_variable_revision: DataRevision;
    idempotency_key: string;
    name: string;
    declared_type: DataContainerVariable["declared_type"];
    value: TypedDataValue;
  }): Promise<DataMutationResult & { container_id: string; variable_id: string; revision: DataRevision }> {
    const query = resourceParameters(input.owner_id, input.acl_revision);
    return jsonRequest(
      `/containers/${encodeURIComponent(input.container_id)}/variables/${encodeURIComponent(input.variable_id)}?${query.toString()}`,
      {
        method: "PUT",
        headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
        body: JSON.stringify({
          expected_revision: input.expected_revision,
          expected_variable_revision: input.expected_variable_revision,
          name: input.name,
          declared_type: input.declared_type,
          value: input.value,
        }),
      },
    );
  },

  async deleteContainerVariable(input: {
    owner_id: string;
    container_id: string;
    variable_id: string;
    acl_revision: DataRevision;
    expected_revision: DataRevision;
    expected_variable_revision: DataRevision;
    idempotency_key: string;
  }): Promise<DataMutationResult & { container_id: string; variable_id: string; revision: DataRevision }> {
    const query = resourceParameters(input.owner_id, input.acl_revision);
    return jsonRequest(
      `/containers/${encodeURIComponent(input.container_id)}/variables/${encodeURIComponent(input.variable_id)}?${query.toString()}`,
      {
        method: "DELETE",
        headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
        body: JSON.stringify({
          expected_revision: input.expected_revision,
          expected_variable_revision: input.expected_variable_revision,
        }),
      },
    );
  },

  async sharedNamespaces(ownerId: string, pageSize = DATA_PAGE_SIZE, cursor?: string): Promise<SharedNamespacePage> {
    return jsonRequest(`/shared/namespaces?${pageParameters(ownerId, pageSize, cursor).toString()}`);
  },

  async createSharedNamespace(input: {
    owner_id: string;
    namespace_id: string;
    acl_revision: DataRevision;
    scope: SharedNamespaceDetail["scope"];
    idempotency_key: string;
  }): Promise<DataMutationResult & SharedNamespaceDetail> {
    const query = resourceParameters(input.owner_id, input.acl_revision);
    query.set("namespace_id", input.namespace_id);
    return jsonRequest(`/shared/namespaces?${query.toString()}`, {
      method: "POST",
      headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
      body: JSON.stringify({ expected_revision: "0", scope: input.scope }),
    });
  },

  async sharedNamespace(
    ownerId: string,
    namespaceId: string,
    aclRevision: DataRevision,
    scope: SharedNamespaceDetail["scope"],
  ): Promise<SharedNamespaceDetail> {
    return jsonRequest(
      `/shared/namespaces/${encodeURIComponent(namespaceId)}?${sharedResourceParameters(ownerId, aclRevision, scope).toString()}`,
    );
  },

  async sharedEntries(
    ownerId: string,
    namespaceId: string,
    aclRevision: DataRevision,
    scope: SharedNamespaceDetail["scope"],
    pageSize = DATA_PAGE_SIZE,
    cursor?: string,
  ): Promise<SharedDataEntryPage> {
    const query = sharedResourceParameters(ownerId, aclRevision, scope);
    query.set("page_size", String(pageSize));
    if (cursor) query.set("cursor", cursor);
    return jsonRequest(`/shared/namespaces/${encodeURIComponent(namespaceId)}/entries?${query.toString()}`);
  },

  async sharedEntry(
    ownerId: string,
    namespaceId: string,
    key: string,
    aclRevision: DataRevision,
    scope: SharedNamespaceDetail["scope"],
  ): Promise<SharedDataEntry & { namespace_id: string; namespace_revision: DataRevision }> {
    return jsonRequest(
      `/shared/namespaces/${encodeURIComponent(namespaceId)}/entries/${encodeURIComponent(key)}?${sharedResourceParameters(ownerId, aclRevision, scope).toString()}`,
    );
  },

  async putSharedEntry(input: {
    owner_id: string;
    namespace_id: string;
    key: string;
    acl_revision: DataRevision;
    scope: SharedNamespaceDetail["scope"];
    expected_namespace_revision: DataRevision;
    expected_entry_revision: DataRevision;
    idempotency_key: string;
    value: TypedDataValue;
  }): Promise<DataMutationResult & { namespace_id: string; entry_id: string; entry_revision: DataRevision; revision: DataRevision }> {
    const query = sharedResourceParameters(input.owner_id, input.acl_revision, input.scope);
    return jsonRequest(
      `/shared/namespaces/${encodeURIComponent(input.namespace_id)}/entries/${encodeURIComponent(input.key)}?${query.toString()}`,
      {
        method: "PUT",
        headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
        body: JSON.stringify({
          expected_namespace_revision: input.expected_namespace_revision,
          expected_entry_revision: input.expected_entry_revision,
          value: input.value,
        }),
      },
    );
  },

  async deleteSharedEntry(input: {
    owner_id: string;
    namespace_id: string;
    key: string;
    acl_revision: DataRevision;
    scope: SharedNamespaceDetail["scope"];
    expected_namespace_revision: DataRevision;
    expected_entry_revision: DataRevision;
    idempotency_key: string;
  }): Promise<DataMutationResult> {
    const query = sharedResourceParameters(input.owner_id, input.acl_revision, input.scope);
    return jsonRequest(
      `/shared/namespaces/${encodeURIComponent(input.namespace_id)}/entries/${encodeURIComponent(input.key)}?${query.toString()}`,
      {
        method: "DELETE",
        headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
        body: JSON.stringify({
          expected_namespace_revision: input.expected_namespace_revision,
          expected_entry_revision: input.expected_entry_revision,
        }),
      },
    );
  },

  async clearSharedNamespace(input: {
    owner_id: string;
    namespace_id: string;
    acl_revision: DataRevision;
    scope: SharedNamespaceDetail["scope"];
    expected_namespace_revision: DataRevision;
    maximum_affected_entries: number;
    idempotency_key: string;
  }): Promise<DataMutationResult & { affected_entries: number; revision: DataRevision }> {
    const query = sharedResourceParameters(input.owner_id, input.acl_revision, input.scope);
    return jsonRequest(`/shared/namespaces/${encodeURIComponent(input.namespace_id)}/clear?${query.toString()}`, {
      method: "POST",
      headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
      body: JSON.stringify({
        expected_namespace_revision: input.expected_namespace_revision,
        maximum_affected_entries: input.maximum_affected_entries,
      }),
    });
  },

  async deleteSharedNamespace(input: {
    owner_id: string;
    namespace_id: string;
    acl_revision: DataRevision;
    scope: SharedNamespaceDetail["scope"];
    expected_namespace_revision: DataRevision;
    idempotency_key: string;
  }): Promise<DataMutationResult> {
    const query = sharedResourceParameters(input.owner_id, input.acl_revision, input.scope);
    return jsonRequest(`/shared/namespaces/${encodeURIComponent(input.namespace_id)}?${query.toString()}`, {
      method: "DELETE",
      headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
      body: JSON.stringify({ expected_namespace_revision: input.expected_namespace_revision }),
    });
  },

  async directory(
    rootId: VirtualFileRoot,
    virtualPath = "",
    limit = DATA_PAGE_SIZE,
    cursor?: string,
  ): Promise<VirtualDirectoryPage> {
    const query = new URLSearchParams({ virtual_path: virtualPath, limit: String(limit) });
    if (cursor) query.set("cursor", cursor);
    return jsonRequest(`/files/${rootId}/directory?${query.toString()}`);
  },

  async createDirectory(input: {
    root_id: VirtualFileRoot;
    virtual_path: string;
    expected_revision: DataRevision;
    idempotency_key: string;
  }): Promise<{ revision: DataRevision; root_revision: DataRevision; replayed: boolean }> {
    return jsonRequest(`/files/${input.root_id}/directories`, {
      method: "POST",
      headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
      body: JSON.stringify({
        virtual_path: input.virtual_path,
        expected_revision: input.expected_revision,
      }),
    });
  },

  async readFile(
    rootId: VirtualFileRoot,
    virtualPath: string,
    revision?: DataRevision,
  ): Promise<VirtualFileContent> {
    const query = new URLSearchParams({ virtual_path: virtualPath });
    if (revision) query.set("revision", revision);
    const response = await fetch(`${DATA_API_ROOT}/files/${rootId}/content?${query.toString()}`, {
      headers: headers(),
    });
    if (!response.ok) throw await responseError(response);
    return {
      blob: await response.blob(),
      content_sha256: response.headers.get("Content-SHA256") ?? "",
      encoding: (response.headers.get("X-Spell-Encoding") ?? "BINARY") as VirtualFileEncoding,
      revision: response.headers.get("X-Spell-Revision") ?? revision ?? "",
    };
  },

  async writeFile(input: {
    root_id: VirtualFileRoot;
    virtual_path: string;
    expected_revision: DataRevision;
    encoding: VirtualFileEncoding;
    idempotency_key: string;
    file: Blob;
  }): Promise<{
    content_sha256: string;
    encoding: VirtualFileEncoding;
    replayed: boolean;
    revision: DataRevision;
    root_revision: DataRevision;
    size: number;
    virtual_path: string;
  }> {
    if (input.file.size > MAX_DATA_FILE_BYTES) throw new Error("File exceeds 16 MiB");
    const digest = await sha256Hex(await input.file.arrayBuffer());
    const query = new URLSearchParams({
      virtual_path: input.virtual_path,
      expected_revision: input.expected_revision,
      encoding: input.encoding,
    });
    return jsonRequest(`/files/${input.root_id}/content?${query.toString()}`, {
      method: "PUT",
      headers: mutationHeaders({
        idempotencyKey: input.idempotency_key,
        contentType: "application/octet-stream",
        contentSha256: digest,
      }),
      body: input.file,
    });
  },

  async deleteFileNode(input: {
    root_id: VirtualFileRoot;
    virtual_path: string;
    expected_revision: DataRevision;
    idempotency_key: string;
  }): Promise<{ deleted_revision: DataRevision; replayed: boolean; root_revision: DataRevision }> {
    return jsonRequest(`/files/${input.root_id}/nodes`, {
      method: "DELETE",
      headers: mutationHeaders({ idempotencyKey: input.idempotency_key }),
      body: JSON.stringify({
        virtual_path: input.virtual_path,
        expected_revision: input.expected_revision,
      }),
    });
  },
};
