"use client";

import React, { useState } from "react";
import { fieldAssessmentApi } from "@/lib/fieldAssessmentApi";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GovernanceSummary {
  total_vendors: number;
  workflow_distribution: Record<string, number>;
  readiness_distribution: Record<string, number>;
  needs_owner_count: number;
  needs_review_count: number;
  overdue_review_count: number;
  expiring_renewals_30d: number;
  rejected_count: number;
  restricted_count: number;
  exception_count: number;
  no_dpa_count: number;
  no_baa_count: number;
  no_contract_count: number;
  no_security_review_count: number;
}

interface GovernanceRecord {
  id: string;
  vendor: string;
  tool_name: string;
  target_type: string;
  workflow_state: string;
  governance_readiness: string;
  risk_score: string;
  business_owner: string | null;
  technical_owner: string | null;
  executive_sponsor: string | null;
  department: string | null;
  criticality: string;
  dpa_required: boolean;
  dpa_status: string;
  baa_required: boolean;
  baa_status: string;
  contract_status: string;
  security_review_status: string;
  privacy_review_status: string;
  soc2_available: boolean;
  soc2_reviewed: boolean;
  iso27001_available: boolean;
  iso27001_reviewed: boolean;
  risk_acceptance_required: boolean;
  risk_acceptance_status: string;
  risk_acceptance_expiration: string | null;
  review_due_date: string | null;
  renewal_due_date: string | null;
  regulatory_flags: string[];
  risk_categories: string[];
  finding_refs: string[];
  created_at: string;
  updated_at: string;
  last_reviewed_at: string | null;
}

interface GovernanceDecision {
  decision_id: string;
  vendor: string;
  tool_name: string;
  decision: string;
  reason: string;
  previous_state: string | null;
  new_state: string | null;
  actor_name: string;
  created_at: string;
}

interface GovernanceListResponse {
  items: GovernanceRecord[];
  total: number;
  limit: number;
  offset: number;
  summary: GovernanceSummary;
}

interface TransitionRequest {
  new_state: string;
  reason: string;
  actor_name: string;
  actor_email?: string;
  notes?: string;
  exception_expiration?: string;
}

// ---------------------------------------------------------------------------
// Style maps
// ---------------------------------------------------------------------------

const STATE_BADGE: Record<string, string> = {
  discovered: "bg-gray-100 text-gray-700",
  needs_owner: "bg-orange-100 text-orange-800",
  needs_review: "bg-yellow-100 text-yellow-800",
  approved: "bg-green-100 text-green-800",
  restricted: "bg-blue-100 text-blue-800",
  rejected: "bg-red-100 text-red-800",
  exception_granted: "bg-purple-100 text-purple-800",
  retired: "bg-gray-200 text-gray-500",
};

const READINESS_BADGE: Record<string, string> = {
  complete: "bg-green-100 text-green-800",
  partial: "bg-yellow-100 text-yellow-800",
  minimal: "bg-orange-100 text-orange-800",
  unknown: "bg-gray-100 text-gray-600",
};

const RISK_BADGE: Record<string, string> = {
  critical: "bg-red-100 text-red-800",
  high: "bg-orange-100 text-orange-800",
  moderate: "bg-yellow-100 text-yellow-800",
  low: "bg-green-100 text-green-800",
  unknown: "bg-gray-100 text-gray-600",
};

const STATUS_DOT: Record<string, string> = {
  executed: "text-green-600",
  completed: "text-green-600",
  accepted: "text-green-600",
  not_required: "text-gray-400",
  not_started: "text-gray-400",
  unknown: "text-gray-400",
  pending: "text-yellow-500",
  in_progress: "text-yellow-500",
  active: "text-green-600",
  expired: "text-red-500",
  none: "text-red-500",
};

function Badge({
  label,
  cls,
}: {
  label: string;
  cls: string;
}) {
  return (
    <span
      className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${cls}`}
    >
      {label.replace(/_/g, " ")}
    </span>
  );
}

function StatusIcon({ status }: { status: string }) {
  const color = STATUS_DOT[status] || "text-gray-400";
  const ok = ["executed", "completed", "accepted", "active"].includes(status);
  const warn = ["pending", "in_progress"].includes(status);
  return (
    <span className={`text-xs font-medium ${color}`}>
      {ok ? "✓" : warn ? "⏳" : "—"}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Transition modal
// ---------------------------------------------------------------------------

const TRANSITION_OPTIONS: Record<string, string[]> = {
  discovered: ["needs_owner", "needs_review", "approved", "rejected"],
  needs_owner: ["needs_review", "rejected"],
  needs_review: ["approved", "restricted", "rejected", "exception_granted"],
  approved: ["needs_review", "restricted", "rejected", "retired"],
  restricted: ["needs_review", "approved", "rejected", "retired"],
  rejected: ["needs_review", "exception_granted"],
  exception_granted: ["approved", "needs_review", "rejected"],
  retired: [],
};

function TransitionModal({
  record,
  onClose,
  onSubmit,
}: {
  record: GovernanceRecord;
  onClose: () => void;
  onSubmit: (data: TransitionRequest) => void;
}) {
  const options = TRANSITION_OPTIONS[record.workflow_state] || [];
  const [form, setForm] = useState<TransitionRequest>({
    new_state: options[0] || "",
    reason: "",
    actor_name: "",
    actor_email: "",
    notes: "",
    exception_expiration: "",
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl">
        <h3 className="mb-4 text-base font-semibold text-gray-900">
          Governance Transition — {record.tool_name}
        </h3>
        <p className="mb-4 text-xs text-gray-500">
          Current state:{" "}
          <Badge
            label={record.workflow_state}
            cls={STATE_BADGE[record.workflow_state] || "bg-gray-100 text-gray-700"}
          />
        </p>
        {options.length === 0 ? (
          <p className="text-sm text-gray-600">
            This tool is in a terminal state (retired) and cannot be transitioned.
          </p>
        ) : (
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-gray-700">
                New State *
              </label>
              <select
                className="mt-1 w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
                value={form.new_state}
                onChange={(e) => setForm({ ...form, new_state: e.target.value })}
              >
                {options.map((s) => (
                  <option key={s} value={s}>
                    {s.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700">
                Reason *
              </label>
              <textarea
                className="mt-1 w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
                rows={2}
                value={form.reason}
                onChange={(e) => setForm({ ...form, reason: e.target.value })}
                placeholder="Required — governance rationale"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700">
                Actor Name *
              </label>
              <input
                className="mt-1 w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
                value={form.actor_name}
                onChange={(e) => setForm({ ...form, actor_name: e.target.value })}
                placeholder="Full name of authorizing person"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-700">
                Actor Email
              </label>
              <input
                className="mt-1 w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
                value={form.actor_email}
                onChange={(e) => setForm({ ...form, actor_email: e.target.value })}
                placeholder="Optional"
              />
            </div>
            {form.new_state === "exception_granted" && (
              <div>
                <label className="block text-xs font-medium text-gray-700">
                  Exception Expiration (ISO date)
                </label>
                <input
                  className="mt-1 w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
                  value={form.exception_expiration}
                  onChange={(e) =>
                    setForm({ ...form, exception_expiration: e.target.value })
                  }
                  placeholder="e.g. 2027-01-01T00:00:00Z"
                />
              </div>
            )}
            <div>
              <label className="block text-xs font-medium text-gray-700">Notes</label>
              <textarea
                className="mt-1 w-full rounded border border-gray-300 px-3 py-1.5 text-sm"
                rows={2}
                value={form.notes}
                onChange={(e) => setForm({ ...form, notes: e.target.value })}
                placeholder="Optional governance notes"
              />
            </div>
          </div>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <button
            className="rounded px-3 py-1.5 text-sm text-gray-600 hover:bg-gray-100"
            onClick={onClose}
          >
            Cancel
          </button>
          {options.length > 0 && (
            <button
              className="rounded bg-indigo-600 px-4 py-1.5 text-sm text-white hover:bg-indigo-700 disabled:opacity-50"
              disabled={!form.reason.trim() || !form.actor_name.trim()}
              onClick={() => onSubmit(form)}
            >
              Confirm Transition
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Record card
// ---------------------------------------------------------------------------

function GovernanceRecordCard({
  record,
  onTransition,
}: {
  record: GovernanceRecord;
  onTransition: (record: GovernanceRecord) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate text-sm font-semibold text-gray-900">
              {record.tool_name}
            </span>
            <span className="text-xs text-gray-500">{record.vendor}</span>
            <Badge
              label={record.workflow_state}
              cls={STATE_BADGE[record.workflow_state] || "bg-gray-100 text-gray-700"}
            />
            <Badge
              label={record.governance_readiness}
              cls={READINESS_BADGE[record.governance_readiness] || "bg-gray-100"}
            />
            <Badge
              label={record.risk_score}
              cls={RISK_BADGE[record.risk_score] || "bg-gray-100"}
            />
          </div>
          <div className="mt-1 flex flex-wrap gap-2 text-xs text-gray-500">
            {record.business_owner && <span>Biz: {record.business_owner}</span>}
            {record.technical_owner && <span>Tech: {record.technical_owner}</span>}
            {record.department && <span>Dept: {record.department}</span>}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <button
            className="rounded border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-100"
            onClick={() => onTransition(record)}
          >
            Transition
          </button>
          <button
            className="rounded border border-gray-200 px-2.5 py-1 text-xs text-gray-600 hover:bg-gray-50"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? "Less" : "Details"}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 border-t border-gray-100 pt-3 text-xs sm:grid-cols-3">
          <div>
            <span className="font-medium text-gray-500">DPA</span>{" "}
            <StatusIcon status={record.dpa_status} /> {record.dpa_status.replace(/_/g, " ")}
            {record.dpa_required && (
              <span className="ml-1 text-orange-500">(required)</span>
            )}
          </div>
          <div>
            <span className="font-medium text-gray-500">BAA</span>{" "}
            <StatusIcon status={record.baa_status} /> {record.baa_status.replace(/_/g, " ")}
            {record.baa_required && (
              <span className="ml-1 text-orange-500">(required)</span>
            )}
          </div>
          <div>
            <span className="font-medium text-gray-500">Contract</span>{" "}
            <StatusIcon status={record.contract_status} />{" "}
            {record.contract_status.replace(/_/g, " ")}
          </div>
          <div>
            <span className="font-medium text-gray-500">Security</span>{" "}
            <StatusIcon status={record.security_review_status} />{" "}
            {record.security_review_status.replace(/_/g, " ")}
          </div>
          <div>
            <span className="font-medium text-gray-500">Privacy</span>{" "}
            <StatusIcon status={record.privacy_review_status} />{" "}
            {record.privacy_review_status.replace(/_/g, " ")}
          </div>
          <div>
            <span className="font-medium text-gray-500">SOC 2</span>{" "}
            <StatusIcon status={record.soc2_reviewed ? "completed" : "not_started"} />{" "}
            {record.soc2_available ? (record.soc2_reviewed ? "Reviewed" : "Available") : "None"}
          </div>
          <div>
            <span className="font-medium text-gray-500">ISO 27001</span>{" "}
            <StatusIcon
              status={record.iso27001_reviewed ? "completed" : "not_started"}
            />{" "}
            {record.iso27001_available
              ? record.iso27001_reviewed
                ? "Reviewed"
                : "Available"
              : "None"}
          </div>
          <div>
            <span className="font-medium text-gray-500">Risk Accept</span>{" "}
            <StatusIcon status={record.risk_acceptance_status} />{" "}
            {record.risk_acceptance_status.replace(/_/g, " ")}
          </div>
          {record.review_due_date && (
            <div>
              <span className="font-medium text-gray-500">Review Due</span>{" "}
              {record.review_due_date.slice(0, 10)}
            </div>
          )}
          {record.regulatory_flags.length > 0 && (
            <div className="col-span-full mt-1 flex flex-wrap gap-1">
              {record.regulatory_flags.map((f) => (
                <span
                  key={f}
                  className="rounded bg-indigo-50 px-1.5 py-0.5 text-xs text-indigo-700"
                >
                  {f.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main panel
// ---------------------------------------------------------------------------

export function AiGovernancePanel({ engagementId }: { engagementId: string }) {
  const qc = useQueryClient();
  const [stateFilter, setStateFilter] = useState("");
  const [readinessFilter, setReadinessFilter] = useState("");
  const [activeTab, setActiveTab] = useState<"records" | "decisions">("records");
  const [transitionTarget, setTransitionTarget] = useState<GovernanceRecord | null>(null);
  const [runStatus, setRunStatus] = useState<string | null>(null);

  const listQuery = useQuery<GovernanceListResponse>({
    queryKey: ["ai-vendor-governance", engagementId, stateFilter, readinessFilter],
    queryFn: () =>
      fieldAssessmentApi.listAiVendorGovernance(engagementId, {
        workflow_state: stateFilter || undefined,
        governance_readiness: readinessFilter || undefined,
      }),
  });

  const decisionsQuery = useQuery({
    queryKey: ["ai-vendor-governance-decisions", engagementId],
    queryFn: () => fieldAssessmentApi.listAiVendorGovernanceDecisions(engagementId),
    enabled: activeTab === "decisions",
  });

  const runMutation = useMutation({
    mutationFn: () => fieldAssessmentApi.runAiVendorGovernance(engagementId),
    onSuccess: (data) => {
      setRunStatus(`Imported ${data.records_imported} records, ${data.findings_imported} findings.`);
      qc.invalidateQueries({ queryKey: ["ai-vendor-governance", engagementId] });
    },
    onError: (err: Error) => setRunStatus(`Error: ${err.message}`),
  });

  const transitionMutation = useMutation({
    mutationFn: ({
      recordId,
      body,
    }: {
      recordId: string;
      body: TransitionRequest;
    }) => fieldAssessmentApi.transitionAiVendorGovernance(engagementId, recordId, body),
    onSuccess: () => {
      setTransitionTarget(null);
      qc.invalidateQueries({ queryKey: ["ai-vendor-governance", engagementId] });
      qc.invalidateQueries({
        queryKey: ["ai-vendor-governance-decisions", engagementId],
      });
    },
  });

  const s = listQuery.data?.summary;

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-base font-semibold text-gray-900">
          Third-Party AI Governance
        </h2>
        <button
          className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white hover:bg-indigo-700 disabled:opacity-50"
          onClick={() => runMutation.mutate()}
          disabled={runMutation.isPending}
        >
          {runMutation.isPending ? "Running…" : "Run Governance Engine"}
        </button>
      </div>

      {runStatus && (
        <div className="rounded bg-green-50 p-3 text-sm text-green-800">{runStatus}</div>
      )}

      {/* Executive metrics */}
      {s && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: "Total Vendors", value: s.total_vendors },
            { label: "Needs Owner", value: s.needs_owner_count, warn: s.needs_owner_count > 0 },
            { label: "Needs Review", value: s.needs_review_count, warn: s.needs_review_count > 0 },
            {
              label: "Overdue Reviews",
              value: s.overdue_review_count,
              warn: s.overdue_review_count > 0,
            },
            { label: "Rejected", value: s.rejected_count, warn: s.rejected_count > 0 },
            { label: "Restricted", value: s.restricted_count },
            { label: "Exceptions", value: s.exception_count },
            {
              label: "Expiring Renewals",
              value: s.expiring_renewals_30d,
              warn: s.expiring_renewals_30d > 0,
            },
          ].map(({ label, value, warn }) => (
            <div
              key={label}
              className={`rounded-lg border p-3 text-center ${warn ? "border-orange-200 bg-orange-50" : "border-gray-200 bg-white"}`}
            >
              <div
                className={`text-2xl font-bold ${warn ? "text-orange-700" : "text-gray-900"}`}
              >
                {value}
              </div>
              <div className="mt-0.5 text-xs text-gray-500">{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Compliance gap counters */}
      {s && (s.no_dpa_count > 0 || s.no_baa_count > 0 || s.no_contract_count > 0 || s.no_security_review_count > 0) && (
        <div className="flex flex-wrap gap-2">
          {s.no_dpa_count > 0 && (
            <span className="rounded bg-red-50 px-2.5 py-1 text-xs font-medium text-red-700">
              {s.no_dpa_count} missing DPA
            </span>
          )}
          {s.no_baa_count > 0 && (
            <span className="rounded bg-red-50 px-2.5 py-1 text-xs font-medium text-red-700">
              {s.no_baa_count} missing BAA
            </span>
          )}
          {s.no_contract_count > 0 && (
            <span className="rounded bg-orange-50 px-2.5 py-1 text-xs font-medium text-orange-700">
              {s.no_contract_count} no contract
            </span>
          )}
          {s.no_security_review_count > 0 && (
            <span className="rounded bg-orange-50 px-2.5 py-1 text-xs font-medium text-orange-700">
              {s.no_security_review_count} no security review
            </span>
          )}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-4 border-b border-gray-200">
        {(["records", "decisions"] as const).map((tab) => (
          <button
            key={tab}
            className={`pb-2 text-sm font-medium capitalize ${
              activeTab === tab
                ? "border-b-2 border-indigo-600 text-indigo-600"
                : "text-gray-500 hover:text-gray-700"
            }`}
            onClick={() => setActiveTab(tab)}
          >
            {tab === "records" ? "Governance Records" : "Decision Ledger"}
          </button>
        ))}
      </div>

      {/* Records tab */}
      {activeTab === "records" && (
        <>
          <div className="flex flex-wrap gap-3">
            <select
              className="rounded border border-gray-300 px-2.5 py-1.5 text-sm"
              value={stateFilter}
              onChange={(e) => setStateFilter(e.target.value)}
            >
              <option value="">All States</option>
              {[
                "discovered",
                "needs_owner",
                "needs_review",
                "approved",
                "restricted",
                "rejected",
                "exception_granted",
                "retired",
              ].map((s) => (
                <option key={s} value={s}>
                  {s.replace(/_/g, " ")}
                </option>
              ))}
            </select>
            <select
              className="rounded border border-gray-300 px-2.5 py-1.5 text-sm"
              value={readinessFilter}
              onChange={(e) => setReadinessFilter(e.target.value)}
            >
              <option value="">All Readiness</option>
              {["complete", "partial", "minimal", "unknown"].map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>

          {listQuery.isPending ? (
            <p className="text-sm text-gray-500">Loading…</p>
          ) : listQuery.isError ? (
            <p className="text-sm text-red-600">Failed to load governance records.</p>
          ) : listQuery.data?.items.length === 0 ? (
            <div className="rounded-lg border border-dashed border-gray-300 p-8 text-center">
              <p className="text-sm text-gray-500">
                No governance records. Run the governance engine to generate records from
                PR3 risk evidence.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {listQuery.data?.items.map((r) => (
                <GovernanceRecordCard
                  key={r.id}
                  record={r}
                  onTransition={setTransitionTarget}
                />
              ))}
            </div>
          )}
        </>
      )}

      {/* Decisions tab */}
      {activeTab === "decisions" && (
        <>
          {decisionsQuery.isPending ? (
            <p className="text-sm text-gray-500">Loading…</p>
          ) : decisionsQuery.isError ? (
            <p className="text-sm text-red-600">Failed to load decision ledger.</p>
          ) : (decisionsQuery.data as any)?.items?.length === 0 ? (
            <p className="text-sm text-gray-500">No decisions recorded yet.</p>
          ) : (
            <div className="overflow-hidden rounded-lg border border-gray-200">
              <table className="min-w-full divide-y divide-gray-200 text-xs">
                <thead className="bg-gray-50">
                  <tr>
                    {["Tool", "Decision", "State Change", "Actor", "Date"].map((h) => (
                      <th
                        key={h}
                        className="px-3 py-2 text-left font-medium text-gray-500"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 bg-white">
                  {((decisionsQuery.data as any)?.items || []).map(
                    (d: GovernanceDecision) => (
                      <tr key={d.decision_id}>
                        <td className="px-3 py-2 font-medium text-gray-900">
                          {d.tool_name}
                        </td>
                        <td className="px-3 py-2 capitalize text-gray-700">
                          {d.decision.replace(/_/g, " ")}
                        </td>
                        <td className="px-3 py-2 text-gray-500">
                          {d.previous_state
                            ? `${d.previous_state.replace(/_/g, " ")} → ${(d.new_state || "").replace(/_/g, " ")}`
                            : d.new_state?.replace(/_/g, " ")}
                        </td>
                        <td className="px-3 py-2 text-gray-700">{d.actor_name}</td>
                        <td className="px-3 py-2 text-gray-500">
                          {d.created_at.slice(0, 10)}
                        </td>
                      </tr>
                    )
                  )}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* Transition modal */}
      {transitionTarget && (
        <TransitionModal
          record={transitionTarget}
          onClose={() => setTransitionTarget(null)}
          onSubmit={(data) =>
            transitionMutation.mutate({ recordId: transitionTarget.id, body: data })
          }
        />
      )}
    </div>
  );
}
