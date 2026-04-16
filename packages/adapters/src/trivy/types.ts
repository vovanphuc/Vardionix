export interface TrivyJsonOutput {
  SchemaVersion: number;
  ArtifactName: string;
  ArtifactType: string;
  Results: TrivyResult[];
}

export interface TrivyResult {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
}

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgID?: string;
  PkgName: string;
  PkgPath?: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Status?: string;
  SeveritySource?: string;
  PrimaryURL?: string;
  DataSource?: {
    ID: string;
    Name: string;
    URL: string;
  };
  Title?: string;
  Description?: string;
  Severity: string;
  CweIDs?: string[];
  CVSS?: Record<string, {
    V2Vector?: string;
    V3Vector?: string;
    V2Score?: number;
    V3Score?: number;
  }>;
  References?: string[];
  PublishedDate?: string;
  LastModifiedDate?: string;
}
