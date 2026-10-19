// Provider-independent integration interface. Each adapter implements real API calls
// against its provider's documented API. Adapters must never fabricate results.
export interface ActionParams { target: string; durationMin: number; [k: string]: unknown; }

export interface AdapterResult { success: boolean; detail: unknown; }

export interface IntegrationAdapter {
  kind: string;
  // Validate credentials and perform a real health check. Returns scopes actually granted.
  healthCheck(credentials: Record<string, string>): Promise<{ ok: boolean; scopes: string[]; error?: string }>;
  execute(action: { type: string; params: ActionParams; dryRun: boolean }): Promise<AdapterResult>;
  rollback(params: ActionParams): Promise<AdapterResult>;
  testConnection(): Promise<AdapterResult>;
}
