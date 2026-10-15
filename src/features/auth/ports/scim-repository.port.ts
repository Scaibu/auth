export interface ScimUserRecord {
  readonly id: string;
  readonly externalId?: string;
  readonly userName: string;
  readonly name?: {
    readonly formatted?: string;
    readonly familyName?: string;
    readonly givenName?: string;
  };
  readonly displayName?: string;
  readonly emails: ReadonlyArray<{
    readonly value: string;
    readonly primary?: boolean;
    readonly type?: string;
  }>;
  readonly active: boolean;
  readonly meta: {
    readonly resourceType: 'User';
    readonly created: string;
    readonly lastModified: string;
    readonly location: string;
  };
}

export interface ScimGroupRecord {
  readonly id: string;
  readonly externalId?: string;
  readonly displayName: string;
  readonly members: ReadonlyArray<{
    readonly value: string;
    readonly display?: string;
  }>;
  readonly meta: {
    readonly resourceType: 'Group';
    readonly created: string;
    readonly lastModified: string;
    readonly location: string;
  };
}

export interface ScimListResponse<T> {
  readonly schemas: ReadonlyArray<string>;
  readonly totalResults: number;
  readonly startIndex: number;
  readonly itemsPerPage: number;
  readonly Resources: ReadonlyArray<T>;
}

export interface ScimPatchOperation {
  readonly op: 'add' | 'remove' | 'replace' | 'Add' | 'Remove' | 'Replace';
  readonly path?: string;
  readonly value: unknown;
}

export interface ScimPatchRequest {
  readonly schemas: ReadonlyArray<string>;
  readonly Operations: ReadonlyArray<ScimPatchOperation>;
}

export interface CreateScimUserInput {
  readonly externalId?: string;
  readonly userName: string;
  readonly name?: {
    readonly formatted?: string;
    readonly familyName?: string;
    readonly givenName?: string;
  };
  readonly emails: ReadonlyArray<{
    readonly value: string;
    readonly primary?: boolean;
    readonly type?: string;
  }>;
  readonly active?: boolean;
}

export interface CreateScimGroupInput {
  readonly externalId?: string;
  readonly displayName: string;
  readonly members?: ReadonlyArray<{
    readonly value: string;
    readonly display?: string;
  }>;
}

export interface ScimTokenRecord {
  readonly id: string;
  readonly org_id: string;
  readonly token_hash: string;
  readonly description: string;
  readonly status: 'ACTIVE' | 'REVOKED';
  readonly created_at_ms: number;
  readonly expires_at_ms: number | null;
  readonly last_used_at_ms: number | null;
}

export interface ScimRepositoryPort {
  saveScimToken(record: ScimTokenRecord): Promise<void>;
  findScimTokenByHash(tokenHash: string): Promise<ScimTokenRecord | null>;
  revokeScimToken(tokenId: string, orgId: string): Promise<void>;
  
  saveExternalMapping(orgId: string, resourceType: 'user' | 'group', internalId: string, externalId: string): Promise<void>;
  findExternalMapping(orgId: string, resourceType: 'user' | 'group', externalId: string): Promise<string | null>;
  
  saveScimGroup(orgId: string, group: { id: string; displayName: string; externalId?: string }): Promise<void>;
  findScimGroupById(orgId: string, groupId: string): Promise<ScimGroupRecord | null>;
  listScimGroups(orgId: string, filter?: string, startIndex?: number, count?: number): Promise<{ groups: ReadonlyArray<ScimGroupRecord>; total: number }>;
  deleteScimGroup(orgId: string, groupId: string): Promise<void>;
  
  addScimGroupMember(groupId: string, userId: string): Promise<void>;
  removeScimGroupMember(groupId: string, userId: string): Promise<void>;
  listScimGroupMembers(groupId: string): Promise<ReadonlyArray<{ value: string; display?: string }>>;
}
