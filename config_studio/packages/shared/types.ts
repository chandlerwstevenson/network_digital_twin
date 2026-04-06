// Shared types between Next.js frontend and API layer

export type Vendor =
  | "cisco_ios"
  | "cisco_iosxe"
  | "junos"
  | "cisco_nxos"
  | "arista_eos"
  | "palo_alto"
  | "unknown";

export type Severity = "critical" | "warning" | "info";

export type FindingCategory =
  | "syntax"
  | "security"
  | "compliance"
  | "best_practice";

export type ReviewStatus = "pending" | "complete" | "failed";

export type RuleType =
  | "required_command"
  | "banned_command"
  | "required_value"
  | "naming_convention"
  | "structural";

export type UserRole = "admin" | "engineer" | "auditor";

// ---------------------------------------------------------------------------
// Core domain types
// ---------------------------------------------------------------------------

export interface Finding {
  id: string;
  line_start: number;
  line_end: number;
  severity: Severity;
  category: FindingCategory;
  title: string;
  description: string;
  remediation: string;
  rollback: string;
  reference_url?: string;
  compliance_tags: string[];
  config_context?: string;
}

export interface VendorDetection {
  vendor: Vendor;
  os_version?: string;
  confidence: number;
  hostname?: string;
}

export interface SnippetInfo {
  is_snippet: boolean;
  detected_section?: string;
  suppressed_checks: string[];
  external_references: string[];
}

export interface RiskScore {
  score: number; // 0-100
  grade: string; // A-F
  benchmark_label: string;
  breakdown: Record<string, number>;
}

export interface ReviewSummary {
  total_findings: number;
  critical_count: number;
  warning_count: number;
  info_count: number;
  categories: Record<string, number>;
}

export interface AnalyzeResponse {
  review_id: string;
  status: ReviewStatus;
  vendor: VendorDetection;
  snippet_info: SnippetInfo;
  findings: Finding[];
  risk_score: RiskScore;
  pass_fail: boolean;
  summary: ReviewSummary;
  config_hash: string;
}

// ---------------------------------------------------------------------------
// Template types
// ---------------------------------------------------------------------------

export interface TemplateRule {
  id?: string;
  name: string;
  description: string;
  rule_type: RuleType;
  severity: Severity;
  pattern?: string;
  section?: string;
  expected_value?: string;
  condition?: string;
}

export interface Template {
  id: string;
  org_id: string;
  name: string;
  description: string;
  is_starter: boolean;
  created_at: string;
  versions: TemplateVersion[];
}

export interface TemplateVersion {
  id: string;
  template_id: string;
  version_num: number;
  rules: TemplateRule[];
  created_at: string;
  created_by: string;
}

// ---------------------------------------------------------------------------
// Report types
// ---------------------------------------------------------------------------

export interface Report {
  id: string;
  review_id: string;
  format: "pdf" | "json";
  storage_path: string;
  template_version_id?: string;
  config_hash: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// User / Org types
// ---------------------------------------------------------------------------

export interface User {
  id: string;
  org_id: string;
  email: string;
  role: UserRole;
  created_at: string;
}

export interface Organization {
  id: string;
  name: string;
  settings: Record<string, unknown>;
  created_at: string;
}

// ---------------------------------------------------------------------------
// NL Query types
// ---------------------------------------------------------------------------

export interface NLQueryResponse {
  answer: string;
  line_references: number[];
  confidence: number;
}

// ---------------------------------------------------------------------------
// Compare types
// ---------------------------------------------------------------------------

export interface CompareResponse {
  lost_on_reload: Finding[];
  added_since_startup: Array<{ line: string }>;
  removed_since_startup: Array<{ line: string }>;
}
