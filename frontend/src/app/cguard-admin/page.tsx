"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  AlertTriangle,
  ArrowDownUp,
  Download,
  ListChecks,
  Lock,
  LogOut,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  ShieldCheck,
  Users,
} from "lucide-react";
import { cn } from "@/lib/utils";

type AdminAuth = {
  actor: string;
  role: string;
  accessToken: string;
  expiresAt: string;
};

type AdminLoginResponse = {
  actor: string;
  role: string;
  access_token: string;
  expires_at: string;
};

type AdminMeResponse = {
  actor: string;
  role: string;
};

type AdminSession = {
  session_id?: string;
  user_id?: string;
  username?: string | null;
  discord_display_name?: string | null;
  discord_username?: string | null;
  status?: string | null;
  c_guard_ok?: boolean | null;
  client_agent_state?: string | null;
  kernel_bridge_state?: string | null;
  kernel_driver_loaded?: boolean | null;
  heartbeat_stale?: boolean | null;
  final_risk_score?: number | null;
  risk_score?: number | null;
  risk_tier?: string | null;
  decision_reason_code?: string | null;
  status_reason_codes?: string[] | null;
  cli_enforcement_last_confidence?: number | null;
  cli_enforcement_last_reason_code?: string | null;
  upload_status?: string | null;
  updated_at?: string | null;
  last_heartbeat_at?: string | null;
  created_at?: string | null;
};

type SessionsResponse = {
  items?: AdminSession[];
  page?: {
    total?: number;
  };
};

type ReviewNote = {
  note_id: string;
  session_id: string;
  author: string;
  note: string;
  metadata?: Record<string, unknown>;
  created_at: string;
};

type NotesResponse = {
  items?: ReviewNote[];
};

type AdminEvent = {
  event_id?: string;
  event_type?: string;
  severity?: string;
  timestamp?: string;
  received_at?: string;
  session_id?: string;
  user_id?: string;
  client_version?: string;
  evidence?: Record<string, unknown> | null;
};

type EventsResponse = {
  items?: AdminEvent[];
};

type RuntimeConfigResponse = {
  archive?: {
    enabled?: boolean;
    session_group_size?: number;
    memory_event_limit?: number;
  };
  competition?: {
    name?: string | null;
    starts_at?: string | null;
    ends_at?: string | null;
  };
};

type CompetitionDraft = {
  name: string;
  startsAtLocal: string;
  endsAtLocal: string;
};

type SessionStatus = "ACTIVE" | "WARN" | "BLOCKED" | "OFFLINE";
type DetectionKind = "WEB" | "CLI" | "WEB+CLI" | "NONE";
type ViewMode = "sessions" | "participants";
type SortMode = "newest" | "oldest" | "participant" | "risk" | "cguard_off" | "detection";

type SessionRow = {
  sessionId: string;
  userId: string;
  displayName: string;
  status: SessionStatus;
  cguardOn: boolean;
  detection: DetectionKind;
  confidence: number;
  confidenceLabel: string;
  lastSeen: string;
  reasonCode: string;
  evidence: string;
};

type ParticipantRow = {
  userId: string;
  displayName: string;
  liveStatus: SessionStatus;
  cguardOn: boolean;
  detection: DetectionKind;
  confidence: number;
  confidenceLabel: string;
  latestSessionId: string;
  lastSeen: string;
  sessionCount: number;
};

type SavedNote = {
  note: string;
  author: string;
  createdAt: string;
};

type NoteTarget = {
  userId: string;
  displayName: string;
  latestSessionId: string;
};

type RecentHighSignal = {
  key: string;
  userId: string;
  displayName: string;
  latestSessionId: string;
  status: SessionStatus;
  cguardOn: boolean;
  detection: DetectionKind;
  confidence: number;
  count: number;
  lastSeen: string;
  firstSeen: string;
  reasonCode: string;
  evidence: string;
};

const AUTH_STORAGE_KEY = "cguard_admin_server_auth_v1";
const PARTICIPANT_NOTE_TYPE = "operator_participant_note";
const PAGE_SIZE = 20;
const SESSION_FETCH_LIMIT = 1000;
const NOTE_FETCH_LIMIT = 1000;
const RECENT_EVENT_FETCH_LIMIT = 300;
const AUTO_REFRESH_MS = 15000;
const RECENT_HIGH_WINDOW_MS = 3 * 60 * 1000;
const MAX_RECENT_HIGH_ITEMS = 10;
const MOCK_AUTH: AdminAuth = {
  actor: "preview-admin",
  role: "reviewer",
  accessToken: "mock-preview-token",
  expiresAt: "2099-01-01T00:00:00.000Z",
};

class ApiRequestError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown, fallback = "") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function asNumber(value: unknown, fallback = 0) {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function isMeaningfulEvidenceText(value: string) {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return false;
  return !["-", "normal", "none", "ok", "healthy"].includes(normalized);
}

function timeValue(value: string) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function clampPercent(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function formatDateTime(value: string) {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return "-";
  return new Intl.DateTimeFormat("ko-KR", {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(parsed));
}

function toDateTimeLocalValue(value: string | null | undefined) {
  const parsed = value ? Date.parse(value) : NaN;
  if (!Number.isFinite(parsed)) return "";
  const date = new Date(parsed);
  const offsetMs = date.getTimezoneOffset() * 60 * 1000;
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16);
}

function fromDateTimeLocalValue(value: string) {
  if (!value.trim()) return null;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function authHeaders(account: AdminAuth) {
  return {
    Authorization: `Bearer ${account.accessToken}`,
  };
}

async function fetchJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, init);
  const payload = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    const message = isRecord(payload)
      ? asString(payload.message) || asString(payload.code) || "요청을 처리하지 못했습니다."
      : "요청을 처리하지 못했습니다.";
    throw new ApiRequestError(message, response.status);
  }
  return payload as T;
}

function parseStoredAuth(raw: string | null): AdminAuth | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (!isRecord(parsed)) return null;
    const actor = asString(parsed.actor);
    const role = asString(parsed.role);
    const accessToken = asString(parsed.accessToken);
    const expiresAt = asString(parsed.expiresAt);
    if (!actor || !role || !accessToken || !expiresAt) return null;
    if (Date.parse(expiresAt) <= Date.now()) return null;
    return { actor, role, accessToken, expiresAt };
  } catch {
    return null;
  }
}

function canWriteNotes(role: string) {
  return ["reviewer", "enforcer", "admin"].includes(role);
}

function canEnforce(role: string) {
  return ["enforcer", "admin"].includes(role);
}

function filenameFromDisposition(value: string | null, fallback: string) {
  if (!value) return fallback;
  const utf8Match = /filename\*=UTF-8''([^;]+)/i.exec(value);
  if (utf8Match) return decodeURIComponent(utf8Match[1]);
  const plainMatch = /filename="?([^";]+)"?/i.exec(value);
  return plainMatch ? plainMatch[1] : fallback;
}

function normalizeStatus(value: unknown): SessionStatus {
  const status = asString(value, "ACTIVE").toUpperCase();
  if (status === "WARN" || status === "BLOCKED" || status === "OFFLINE") return status;
  return "ACTIVE";
}

function resolveDisplayName(session: AdminSession) {
  return (
    asString(session.username) ||
    asString(session.discord_display_name) ||
    asString(session.discord_username) ||
    asString(session.user_id, "unknown-user")
  );
}

function resolveCGuardOn(session: AdminSession) {
  if (typeof session.c_guard_ok === "boolean") return session.c_guard_ok;
  return (
    asString(session.client_agent_state).toLowerCase() === "running" &&
    asString(session.kernel_bridge_state).toLowerCase() === "connected" &&
    session.kernel_driver_loaded === true &&
    session.heartbeat_stale !== true
  );
}

function resolveReasonCodes(session: AdminSession) {
  const codes = [
    asString(session.decision_reason_code),
    ...(Array.isArray(session.status_reason_codes)
      ? session.status_reason_codes.map((code) => asString(code)).filter(Boolean)
      : []),
    asString(session.cli_enforcement_last_reason_code),
  ];
  return Array.from(new Set(codes.filter(Boolean)));
}

function resolveDetection(session: AdminSession): DetectionKind {
  const haystack = resolveReasonCodes(session).join(" ").toUpperCase();
  const hasCli = haystack.includes("CLI");
  const hasWeb =
    haystack.includes("LLM") ||
    haystack.includes("WEB") ||
    haystack.includes("BROWSER") ||
    haystack.includes("SUBMISSION_SOURCE");
  if (hasCli && hasWeb) return "WEB+CLI";
  if (hasCli) return "CLI";
  if (hasWeb) return "WEB";
  return "NONE";
}

function detectionRank(detection: DetectionKind) {
  if (detection === "WEB+CLI") return 3;
  if (detection === "CLI") return 2;
  if (detection === "WEB") return 1;
  return 0;
}

function statusRank(status: SessionStatus) {
  if (status === "BLOCKED") return 4;
  if (status === "WARN") return 3;
  if (status === "OFFLINE") return 2;
  return 1;
}

function resolveConfidence(session: AdminSession, detection: DetectionKind, status: SessionStatus, reasonCodes: string[]) {
  const cliConfidence = asNumber(session.cli_enforcement_last_confidence, 0);
  if (cliConfidence > 0) return clampPercent(cliConfidence);
  const score = asNumber(session.final_risk_score, asNumber(session.risk_score, 0));
  if (score > 0) return clampPercent(score);
  if (detection === "WEB+CLI") return 95;
  if (detection === "CLI") return 90;
  if (detection === "WEB") return 85;
  if (status === "BLOCKED" && reasonCodes.some(isMeaningfulEvidenceText)) return 80;
  if (status === "WARN" && reasonCodes.some(isMeaningfulEvidenceText)) return 60;
  return 0;
}

function formatConfidence(value: number) {
  return value > 0 ? `${value}%` : "-";
}

function toSessionRow(session: AdminSession): SessionRow {
  const reasonCodes = resolveReasonCodes(session);
  const lastSeen =
    asString(session.last_heartbeat_at) || asString(session.updated_at) || asString(session.created_at);
  const status = normalizeStatus(session.status);
  const detection = resolveDetection(session);
  const confidence = resolveConfidence(session, detection, status, reasonCodes);
  return {
    sessionId: asString(session.session_id, "unknown-session"),
    userId: asString(session.user_id, "unknown-user"),
    displayName: resolveDisplayName(session),
    status,
    cguardOn: resolveCGuardOn(session),
    detection,
    confidence,
    confidenceLabel: formatConfidence(confidence),
    lastSeen,
    reasonCode: reasonCodes[0] || "-",
    evidence: [
      ...reasonCodes.slice(1),
      asString(session.risk_tier),
      asString(session.upload_status),
    ]
      .filter(isMeaningfulEvidenceText)
      .join(", ") || "-",
  };
}

function compareSessions(a: SessionRow, b: SessionRow, sortMode: SortMode) {
  const aTime = timeValue(a.lastSeen);
  const bTime = timeValue(b.lastSeen);
  if (sortMode === "oldest") return aTime - bTime;
  if (sortMode === "participant") return a.displayName.localeCompare(b.displayName, "ko");
  if (sortMode === "risk") return b.confidence - a.confidence || bTime - aTime;
  if (sortMode === "cguard_off") {
    return Number(a.cguardOn) - Number(b.cguardOn) || bTime - aTime;
  }
  if (sortMode === "detection") {
    return detectionRank(b.detection) - detectionRank(a.detection) || bTime - aTime;
  }
  return bTime - aTime;
}

function isRecentHighSession(row: SessionRow, nowMs = Date.now()) {
  const seenAt = timeValue(row.lastSeen);
  if (!seenAt || nowMs - seenAt > RECENT_HIGH_WINDOW_MS) return false;
  if (row.confidence >= 80 || row.detection === "WEB+CLI") return true;
  return row.status === "BLOCKED" && isMeaningfulEvidenceText(row.reasonCode);
}

function extractSignalLabel(row: SessionRow) {
  const source = `${row.reasonCode} ${row.evidence}`;
  const host = source.match(/\b[a-z0-9.-]+\.[a-z]{2,}\b/i)?.[0] || "";
  return host || row.reasonCode || row.detection;
}

function asEventEvidence(event: AdminEvent) {
  return isRecord(event.evidence) ? event.evidence : {};
}

function eventTime(event: AdminEvent) {
  return asString(event.timestamp) || asString(event.received_at);
}

function isChatGptDesktopOrWebText(text: string) {
  const normalized = text.toLowerCase();
  if (normalized.includes("chatgpt-cli")) return false;
  return (
    normalized.includes("chatgpt.exe") ||
    normalized.includes("chatgpt.com") ||
    normalized.includes("chat.openai.com") ||
    normalized.includes("\\chatgpt\\") ||
    normalized.includes("/chatgpt/")
  );
}

function isHighSeverityEvent(event: AdminEvent, nowMs = Date.now()) {
  const seenAt = timeValue(eventTime(event));
  if (!seenAt || nowMs - seenAt > RECENT_HIGH_WINDOW_MS) return false;
  const severity = asString(event.severity).toLowerCase();
  return severity === "high" || severity === "critical";
}

function detectEventKind(event: AdminEvent): DetectionKind {
  const evidence = asEventEvidence(event);
  const text = [
    asString(event.event_type),
    asString(evidence.domain),
    asString(evidence.remote_host),
    asString(evidence.process_name),
    asString(evidence.command_line),
    asString(evidence.executable_path),
    asString(evidence.matched),
    asString(evidence.policy),
  ]
    .join(" ")
    .toLowerCase();
  if (isChatGptDesktopOrWebText(text)) return "WEB";
  const hasCli = text.includes("cli") || text.includes("gemini.exe") || text.includes("gemini.cmd");
  const hasWeb =
    text.includes("play.googleapis.com") ||
    text.includes("generativelanguage.googleapis.com") ||
    text.includes("llm") ||
    text.includes("browser") ||
    text.includes("web");
  if (hasCli && hasWeb) return "WEB+CLI";
  if (hasCli) return "CLI";
  if (hasWeb) return "WEB";
  return "NONE";
}

function extractEventSignalLabel(event: AdminEvent) {
  const evidence = asEventEvidence(event);
  return (
    asString(evidence.domain) ||
    asString(evidence.remote_host) ||
    asString(evidence.process_name) ||
    asString(evidence.policy) ||
    asString(event.event_type, "high event")
  );
}

function eventConfidence(event: AdminEvent) {
  const severity = asString(event.severity).toLowerCase();
  if (severity === "critical") return 100;
  if (severity === "high") return 92;
  return 80;
}

function buildRecentHighSignals(rows: SessionRow[], events: AdminEvent[] = [], nowMs = Date.now()) {
  const byKey = new Map<string, RecentHighSignal>();
  const sessionsById = new Map(rows.map((row) => [row.sessionId, row]));

  for (const event of events) {
    if (!isHighSeverityEvent(event, nowMs)) continue;
    const sessionId = asString(event.session_id, "unknown-session");
    const session = sessionsById.get(sessionId);
    const userId = asString(event.user_id, session?.userId || "unknown-user");
    const label = extractEventSignalLabel(event);
    const key = `${userId}|${label}`;
    const seenAt = eventTime(event);
    const detection = detectEventKind(event);
    const confidence = eventConfidence(event);
    const current = byKey.get(key);
    if (!current) {
      byKey.set(key, {
        key,
        userId,
        displayName: session?.displayName || userId,
        latestSessionId: sessionId,
        status: session?.status || "WARN",
        cguardOn: session?.cguardOn ?? true,
        detection,
        confidence,
        count: 1,
        lastSeen: seenAt,
        firstSeen: seenAt,
        reasonCode: asString(event.event_type, "HIGH_EVENT"),
        evidence: label,
      });
      continue;
    }
    const eventSeenAt = timeValue(seenAt);
    const currentLastTime = timeValue(current.lastSeen);
    const currentFirstTime = timeValue(current.firstSeen);
    byKey.set(key, {
      ...current,
      latestSessionId: eventSeenAt >= currentLastTime ? sessionId : current.latestSessionId,
      status: session && statusRank(session.status) > statusRank(current.status) ? session.status : current.status,
      cguardOn: current.cguardOn && (session?.cguardOn ?? true),
      detection: detectionRank(detection) > detectionRank(current.detection) ? detection : current.detection,
      confidence: Math.max(current.confidence, confidence),
      count: current.count + 1,
      lastSeen: eventSeenAt >= currentLastTime ? seenAt : current.lastSeen,
      firstSeen: eventSeenAt <= currentFirstTime ? seenAt : current.firstSeen,
    });
  }

  for (const row of rows) {
    if (!isRecentHighSession(row, nowMs)) continue;
    const label = extractSignalLabel(row);
    const key = `${row.userId}|${label}`;
    const current = byKey.get(key);
    if (!current) {
      byKey.set(key, {
        key,
        userId: row.userId,
        displayName: row.displayName,
        latestSessionId: row.sessionId,
        status: row.status,
        cguardOn: row.cguardOn,
        detection: row.detection,
        confidence: row.confidence,
        count: 1,
        lastSeen: row.lastSeen,
        firstSeen: row.lastSeen,
        reasonCode: row.reasonCode,
        evidence: label,
      });
      continue;
    }
    const rowTime = timeValue(row.lastSeen);
    const currentLastTime = timeValue(current.lastSeen);
    const currentFirstTime = timeValue(current.firstSeen);
    byKey.set(key, {
      ...current,
      latestSessionId: rowTime >= currentLastTime ? row.sessionId : current.latestSessionId,
      status: statusRank(row.status) > statusRank(current.status) ? row.status : current.status,
      cguardOn: current.cguardOn && row.cguardOn,
      detection: detectionRank(row.detection) > detectionRank(current.detection) ? row.detection : current.detection,
      confidence: Math.max(current.confidence, row.confidence),
      count: current.count + 1,
      lastSeen: rowTime >= currentLastTime ? row.lastSeen : current.lastSeen,
      firstSeen: rowTime <= currentFirstTime ? row.lastSeen : current.firstSeen,
    });
  }
  return Array.from(byKey.values())
    .sort(
      (a, b) =>
        timeValue(b.lastSeen) - timeValue(a.lastSeen) ||
        b.confidence - a.confidence ||
        b.count - a.count,
    )
    .slice(0, MAX_RECENT_HIGH_ITEMS);
}

function buildMockSessions(nowMs = Date.now()): SessionRow[] {
  const iso = (offsetMs: number) => new Date(nowMs - offsetMs).toISOString();
  return [
    {
      sessionId: "sess-demo-codex-01",
      userId: "team03-user12",
      displayName: "team03 / user12",
      status: "BLOCKED",
      cguardOn: true,
      detection: "CLI",
      confidence: 96,
      confidenceLabel: "96%",
      lastSeen: iso(22_000),
      reasonCode: "CLI_USAGE_DETECTED",
      evidence: "codex.exe / 6회 / command_line",
    },
    {
      sessionId: "sess-demo-gemini-01",
      userId: "team07-user04",
      displayName: "team07 / user04",
      status: "WARN",
      cguardOn: true,
      detection: "WEB",
      confidence: 88,
      confidenceLabel: "88%",
      lastSeen: iso(74_000),
      reasonCode: "LLM_LINK_ACTIVITY_DETECTED",
      evidence: "play.googleapis.com / dns_cache / 9회",
    },
    {
      sessionId: "sess-demo-cguard-off",
      userId: "team11-user02",
      displayName: "team11 / user02",
      status: "WARN",
      cguardOn: false,
      detection: "WEB+CLI",
      confidence: 91,
      confidenceLabel: "91%",
      lastSeen: iso(138_000),
      reasonCode: "CLIENT_NONCOMPLIANT",
      evidence: "C-Guard OFF + generativelanguage.googleapis.com",
    },
    {
      sessionId: "sess-demo-old-high",
      userId: "team02-user08",
      displayName: "team02 / user08",
      status: "BLOCKED",
      cguardOn: true,
      detection: "CLI",
      confidence: 98,
      confidenceLabel: "98%",
      lastSeen: iso(260_000),
      reasonCode: "CLI_USAGE_DETECTED",
      evidence: "old high, 3분 창 밖",
    },
    {
      sessionId: "sess-demo-normal",
      userId: "team14-user01",
      displayName: "team14 / user01",
      status: "ACTIVE",
      cguardOn: true,
      detection: "NONE",
      confidence: 0,
      confidenceLabel: "-",
      lastSeen: iso(18_000),
      reasonCode: "-",
      evidence: "-",
    },
  ];
}

function reduceParticipantNotes(notes: ReviewNote[]) {
  const byUser: Record<string, SavedNote> = {};
  for (const note of notes) {
    const metadata = isRecord(note.metadata) ? note.metadata : {};
    if (metadata.note_type !== PARTICIPANT_NOTE_TYPE) continue;
    const userId = asString(metadata.user_id);
    if (!userId) continue;
    const current = byUser[userId];
    if (!current || timeValue(note.created_at) > timeValue(current.createdAt)) {
      byUser[userId] = {
        note: note.note,
        author: note.author,
        createdAt: note.created_at,
      };
    }
  }
  return byUser;
}

function statusTone(status: SessionStatus) {
  if (status === "ACTIVE") return "border-status-ok/35 bg-status-ok/10 text-status-ok";
  if (status === "WARN") return "border-status-warning/35 bg-status-warning/10 text-status-warning";
  if (status === "BLOCKED") return "border-status-danger/35 bg-status-danger/10 text-status-danger";
  return "border-border bg-bg-tertiary text-text-muted";
}

function detectionTone(detection: DetectionKind) {
  if (detection === "WEB+CLI") return "border-status-danger/35 bg-status-danger/10 text-status-danger";
  if (detection === "WEB" || detection === "CLI") {
    return "border-status-warning/35 bg-status-warning/10 text-status-warning";
  }
  return "border-status-ok/35 bg-status-ok/10 text-status-ok";
}

function buildPaginationItems(currentPage: number, totalPages: number): Array<number | "ellipsis"> {
  if (totalPages <= 6) {
    return Array.from({ length: totalPages }, (_, index) => index + 1);
  }

  const pages = new Set<number>([1, totalPages, currentPage]);
  if (currentPage <= 3) {
    [2, 3, 4].forEach((value) => pages.add(value));
  } else if (currentPage >= totalPages - 2) {
    [totalPages - 3, totalPages - 2, totalPages - 1].forEach((value) => pages.add(value));
  } else {
    [currentPage - 1, currentPage + 1].forEach((value) => pages.add(value));
  }

  const sorted = Array.from(pages)
    .filter((value) => value >= 1 && value <= totalPages)
    .sort((a, b) => a - b);
  const items: Array<number | "ellipsis"> = [];
  for (const value of sorted) {
    const previous = items[items.length - 1];
    if (typeof previous === "number" && value - previous > 1) {
      items.push("ellipsis");
    }
    items.push(value);
  }
  return items;
}

function Pill({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span className={cn("inline-flex rounded-full border px-2 py-1 text-xs font-medium", className)}>
      {children}
    </span>
  );
}

export default function CGuardAdminPage() {
  const [account, setAccount] = useState<AdminAuth | null>(null);
  const [bootstrapping, setBootstrapping] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [requestError, setRequestError] = useState("");
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [recentEvents, setRecentEvents] = useState<AdminEvent[]>([]);
  const [runtimeConfig, setRuntimeConfig] = useState<RuntimeConfigResponse | null>(null);
  const [competitionDraft, setCompetitionDraft] = useState<CompetitionDraft>({
    name: "",
    startsAtLocal: "",
    endsAtLocal: "",
  });
  const [serverTotal, setServerTotal] = useState(0);
  const [savedNotes, setSavedNotes] = useState<Record<string, SavedNote>>({});
  const [draftNotes, setDraftNotes] = useState<Record<string, string>>({});
  const [dirtyNotes, setDirtyNotes] = useState<Record<string, boolean>>({});
  const [savingNotes, setSavingNotes] = useState<Record<string, boolean>>({});
  const [resettingParticipants, setResettingParticipants] = useState<Record<string, boolean>>({});
  const [savingCompetition, setSavingCompetition] = useState(false);
  const [exporting, setExporting] = useState("");
  const [viewMode, setViewMode] = useState<ViewMode>("sessions");
  const [sortMode, setSortMode] = useState<SortMode>("newest");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [lastUpdatedAt, setLastUpdatedAt] = useState("");
  const [mockPreview, setMockPreview] = useState(false);
  const [skippedRefreshes, setSkippedRefreshes] = useState(0);
  const dirtyNotesRef = useRef<Record<string, boolean>>({});
  const refreshInFlightRef = useRef(false);

  const clearAuth = useCallback((message = "") => {
    window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
    setAccount(null);
    setPassword("");
    setSessions([]);
    setRecentEvents([]);
    setRuntimeConfig(null);
    setCompetitionDraft({ name: "", startsAtLocal: "", endsAtLocal: "" });
    setSavedNotes({});
    setDraftNotes({});
    setDirtyNotes({});
    setResettingParticipants({});
    setSavingCompetition(false);
    setExporting("");
    setMockPreview(false);
    setSkippedRefreshes(0);
    dirtyNotesRef.current = {};
    if (message) setLoginError(message);
  }, []);

  const loadDashboard = useCallback(
    async (activeAccount: AdminAuth) => {
      if (refreshInFlightRef.current) {
        setSkippedRefreshes((current) => current + 1);
        return;
      }
      refreshInFlightRef.current = true;
      setLoading(true);
      setRequestError("");
      try {
        if (mockPreview) {
          const rows = buildMockSessions();
          setSessions(rows);
          setRecentEvents([]);
          setRuntimeConfig(null);
          setServerTotal(rows.length);
          setLastUpdatedAt(new Date().toISOString());
          return;
        }
        const [sessionPayload, notePayload, eventPayload, runtimePayload] = await Promise.all([
          fetchJson<SessionsResponse>(
            `/cguard-api/v1/admin/sessions?limit=${SESSION_FETCH_LIMIT}&offset=0`,
            { headers: authHeaders(activeAccount) },
          ),
          fetchJson<NotesResponse>(
            `/cguard-api/v1/admin/review-notes?metadata_note_type=${PARTICIPANT_NOTE_TYPE}&limit=${NOTE_FETCH_LIMIT}&offset=0`,
            { headers: authHeaders(activeAccount) },
          ),
          fetchJson<EventsResponse>(
            `/cguard-api/v1/admin/events?limit=${RECENT_EVENT_FETCH_LIMIT}&offset=0`,
            { headers: authHeaders(activeAccount) },
          ),
          fetchJson<RuntimeConfigResponse>("/cguard-api/v1/admin/runtime-config", {
            headers: authHeaders(activeAccount),
          }),
        ]);
        const rows = Array.isArray(sessionPayload.items) ? sessionPayload.items.map(toSessionRow) : [];
        const latestNotes = reduceParticipantNotes(Array.isArray(notePayload.items) ? notePayload.items : []);

        setSessions(rows);
        setRecentEvents(Array.isArray(eventPayload.items) ? eventPayload.items : []);
        setRuntimeConfig(runtimePayload);
        setCompetitionDraft({
          name: asString(runtimePayload.competition?.name),
          startsAtLocal: toDateTimeLocalValue(runtimePayload.competition?.starts_at),
          endsAtLocal: toDateTimeLocalValue(runtimePayload.competition?.ends_at),
        });
        setServerTotal(sessionPayload.page?.total ?? rows.length);
        setSavedNotes(latestNotes);
        setDraftNotes((current) => {
          const next = { ...current };
          for (const row of rows) {
            if (dirtyNotesRef.current[row.userId]) continue;
            next[row.userId] = latestNotes[row.userId]?.note || "";
          }
          return next;
        });
        setLastUpdatedAt(new Date().toISOString());
      } catch (error) {
        if (error instanceof ApiRequestError && error.status === 401) {
          clearAuth("관리자 세션이 만료되었습니다. 다시 로그인하세요.");
          return;
        }
        setRequestError(error instanceof Error ? error.message : "C-Guard 서버에 연결하지 못했습니다.");
      } finally {
        setLoading(false);
        refreshInFlightRef.current = false;
      }
    },
    [clearAuth, mockPreview],
  );

  useEffect(() => {
    let cancelled = false;
    const params = new URLSearchParams(window.location.search);
    if (process.env.NODE_ENV !== "production" && params.get("mock") === "1") {
      const rows = buildMockSessions();
      setMockPreview(true);
      setAccount(MOCK_AUTH);
      setSessions(rows);
      setRuntimeConfig(null);
      setCompetitionDraft({ name: "", startsAtLocal: "", endsAtLocal: "" });
      setServerTotal(rows.length);
      setLastUpdatedAt(new Date().toISOString());
      setBootstrapping(false);
      return undefined;
    }

    const stored = parseStoredAuth(window.sessionStorage.getItem(AUTH_STORAGE_KEY));
    if (!stored) {
      window.sessionStorage.removeItem(AUTH_STORAGE_KEY);
      setBootstrapping(false);
      return undefined;
    }

    fetchJson<AdminMeResponse>("/cguard-api/v1/admin/auth/me", {
      headers: authHeaders(stored),
    })
      .then((me) => {
        if (cancelled) return;
        setAccount({
          ...stored,
          actor: me.actor || stored.actor,
          role: me.role || stored.role,
        });
      })
      .catch(() => {
        if (!cancelled) clearAuth();
      })
      .finally(() => {
        if (!cancelled) setBootstrapping(false);
      });

    return () => {
      cancelled = true;
    };
  }, [clearAuth]);

  useEffect(() => {
    if (!account) return undefined;
    void loadDashboard(account);
    const timer = window.setInterval(() => {
      void loadDashboard(account);
    }, AUTO_REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [account, loadDashboard]);

  const filteredSessions = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const rows = needle
      ? sessions.filter((row) =>
          [
            row.sessionId,
            row.userId,
            row.displayName,
            row.detection,
            row.reasonCode,
            row.evidence,
            draftNotes[row.userId] || savedNotes[row.userId]?.note || "",
          ]
            .join(" ")
            .toLowerCase()
            .includes(needle),
        )
      : sessions;
    return [...rows].sort((a, b) => compareSessions(a, b, sortMode));
  }, [draftNotes, query, savedNotes, sessions, sortMode]);

  const recentHighSignals = useMemo(
    () => buildRecentHighSignals(sessions, recentEvents),
    [recentEvents, sessions],
  );
  const sessionPageCount = Math.max(1, Math.ceil(filteredSessions.length / PAGE_SIZE));
  const pageSessions = filteredSessions.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const participants = useMemo(() => {
    const groups = new Map<string, SessionRow[]>();
    for (const row of filteredSessions) {
      groups.set(row.userId, [...(groups.get(row.userId) || []), row]);
    }
    return Array.from(groups.entries())
      .map(([userId, rows]): ParticipantRow => {
        const latest = [...rows].sort((a, b) => timeValue(b.lastSeen) - timeValue(a.lastSeen))[0];
        const mostImportant = [...rows].sort(
          (a, b) =>
            statusRank(b.status) - statusRank(a.status) ||
            detectionRank(b.detection) - detectionRank(a.detection) ||
            b.confidence - a.confidence,
        )[0];
        return {
          userId,
          displayName: latest.displayName,
          liveStatus: mostImportant.status,
          cguardOn: latest.cguardOn,
          detection: mostImportant.detection,
          confidence: mostImportant.confidence,
          confidenceLabel: mostImportant.confidenceLabel,
          latestSessionId: latest.sessionId,
          lastSeen: latest.lastSeen,
          sessionCount: rows.length,
        };
      })
      .sort((a, b) => {
        if (sortMode === "participant") return a.displayName.localeCompare(b.displayName, "ko");
        if (sortMode === "risk") return b.confidence - a.confidence;
        if (sortMode === "cguard_off") {
          return Number(a.cguardOn) - Number(b.cguardOn) || timeValue(b.lastSeen) - timeValue(a.lastSeen);
        }
        if (sortMode === "detection") {
          return detectionRank(b.detection) - detectionRank(a.detection) || b.confidence - a.confidence;
        }
        if (sortMode === "oldest") return timeValue(a.lastSeen) - timeValue(b.lastSeen);
        return timeValue(b.lastSeen) - timeValue(a.lastSeen);
      });
  }, [filteredSessions, sortMode]);

  const participantPageCount = Math.max(1, Math.ceil(participants.length / PAGE_SIZE));
  const pageParticipants = participants.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);
  const activePageCount = viewMode === "sessions" ? sessionPageCount : participantPageCount;

  useEffect(() => {
    setPage(1);
  }, [query, sortMode, viewMode]);

  useEffect(() => {
    if (page > activePageCount) setPage(activePageCount);
  }, [page, activePageCount]);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginError("");
    try {
      const response = await fetchJson<AdminLoginResponse>("/cguard-api/v1/admin/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password }),
      });
      const nextAccount: AdminAuth = {
        actor: response.actor,
        role: response.role,
        accessToken: response.access_token,
        expiresAt: response.expires_at,
      };
      window.sessionStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(nextAccount));
      setAccount(nextAccount);
      setPassword("");
      setRequestError("");
    } catch (error) {
      setLoginError(error instanceof Error ? error.message : "관리자 계정으로 로그인하세요.");
    }
  }

  function logout() {
    clearAuth();
    setUsername("");
    setQuery("");
    setLoginError("");
  }

  function updateDraftNote(userId: string, value: string) {
    dirtyNotesRef.current = { ...dirtyNotesRef.current, [userId]: true };
    setDirtyNotes((current) => ({ ...current, [userId]: true }));
    setDraftNotes((current) => ({ ...current, [userId]: value }));
  }

  function clearDirtyNote(userId: string) {
    const nextDirty = { ...dirtyNotesRef.current };
    delete nextDirty[userId];
    dirtyNotesRef.current = nextDirty;
    setDirtyNotes(nextDirty);
  }

  async function saveNote(target: NoteTarget) {
    if (!account) return;
    const note = (draftNotes[target.userId] || "").trim();
    if (!note) {
      setRequestError("비고 내용을 입력한 뒤 저장하세요.");
      return;
    }

    setSavingNotes((current) => ({ ...current, [target.userId]: true }));
    setRequestError("");
    try {
      const saved = await fetchJson<ReviewNote>("/cguard-api/v1/admin/review-notes", {
        method: "POST",
        headers: {
          ...authHeaders(account),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          session_id: target.latestSessionId,
          note,
          metadata: {
            note_type: PARTICIPANT_NOTE_TYPE,
            user_id: target.userId,
            participant_display_name: target.displayName,
          },
        }),
      });
      setSavedNotes((current) => ({
        ...current,
        [target.userId]: {
          note: saved.note,
          author: saved.author,
          createdAt: saved.created_at,
        },
      }));
      setDraftNotes((current) => ({ ...current, [target.userId]: saved.note }));
      clearDirtyNote(target.userId);
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) {
        clearAuth("관리자 세션이 만료되었습니다. 다시 로그인하세요.");
        return;
      }
      setRequestError(error instanceof Error ? error.message : "비고 저장에 실패했습니다.");
    } finally {
      setSavingNotes((current) => ({ ...current, [target.userId]: false }));
    }
  }

  async function downloadExport(format: "json" | "csv" | "zip", dataset?: "sessions" | "events" | "review_notes" | "audit_logs") {
    if (!account || mockPreview) return;
    const key = dataset ? `${format}:${dataset}` : format;
    setExporting(key);
    setRequestError("");
    try {
      const params = new URLSearchParams({ format });
      if (dataset) params.set("dataset", dataset);
      const response = await fetch(`/cguard-api/v1/admin/export?${params.toString()}`, {
        headers: authHeaders(account),
      });
      if (!response.ok) {
        const payload = (await response.json().catch(() => null)) as unknown;
        const message = isRecord(payload)
          ? asString(payload.message) || asString(payload.code) || "내보내기에 실패했습니다."
          : "내보내기에 실패했습니다.";
        throw new ApiRequestError(message, response.status);
      }
      const blob = await response.blob();
      const fallback = dataset ? `cguard-${dataset}.${format}` : `cguard-export.${format}`;
      const filename = filenameFromDisposition(response.headers.get("content-disposition"), fallback);
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) {
        clearAuth("관리자 세션이 만료되었습니다. 다시 로그인하세요.");
        return;
      }
      setRequestError(error instanceof Error ? error.message : "내보내기에 실패했습니다.");
    } finally {
      setExporting("");
    }
  }

  async function saveCompetitionConfig() {
    if (!account || mockPreview || !canEnforce(account.role)) return;
    const startsAt = fromDateTimeLocalValue(competitionDraft.startsAtLocal);
    const endsAt = fromDateTimeLocalValue(competitionDraft.endsAtLocal);
    if (competitionDraft.startsAtLocal && !startsAt) {
      setRequestError("대회 시작 시간이 올바르지 않습니다.");
      return;
    }
    if (competitionDraft.endsAtLocal && !endsAt) {
      setRequestError("대회 종료 시간이 올바르지 않습니다.");
      return;
    }
    if (startsAt && endsAt && Date.parse(startsAt) > Date.parse(endsAt)) {
      setRequestError("대회 시작 시간은 종료 시간보다 빨라야 합니다.");
      return;
    }

    setSavingCompetition(true);
    setRequestError("");
    try {
      const payload = await fetchJson<{ runtime_config?: RuntimeConfigResponse }>(
        "/cguard-api/v1/admin/runtime-config/policy",
        {
          method: "POST",
          headers: {
            ...authHeaders(account),
            "content-type": "application/json",
          },
          body: JSON.stringify({
            reason: "operator updated competition schedule",
            competition: {
              name: competitionDraft.name.trim(),
              starts_at: startsAt,
              ends_at: endsAt,
            },
          }),
        },
      );
      if (payload.runtime_config) {
        setRuntimeConfig(payload.runtime_config);
        setCompetitionDraft({
          name: asString(payload.runtime_config.competition?.name),
          startsAtLocal: toDateTimeLocalValue(payload.runtime_config.competition?.starts_at),
          endsAtLocal: toDateTimeLocalValue(payload.runtime_config.competition?.ends_at),
        });
      }
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) {
        clearAuth("관리자 세션이 만료되었습니다. 다시 로그인해주세요.");
        return;
      }
      setRequestError(error instanceof Error ? error.message : "대회 설정 저장에 실패했습니다.");
    } finally {
      setSavingCompetition(false);
    }
  }

  async function resetParticipant(target: NoteTarget) {
    if (!account || mockPreview || !canEnforce(account.role)) return;
    const ok = window.confirm(
      `${target.displayName} 참가자의 활성 세션과 토큰을 리셋할까요?\n기존 이벤트, 비고, 감사 로그는 삭제하지 않습니다.`,
    );
    if (!ok) return;

    setResettingParticipants((current) => ({ ...current, [target.userId]: true }));
    setRequestError("");
    try {
      await fetchJson(`/cguard-api/v1/admin/participants/${encodeURIComponent(target.userId)}/reset`, {
        method: "POST",
        headers: {
          ...authHeaders(account),
          "content-type": "application/json",
        },
        body: JSON.stringify({
          reason: "operator requested participant reconnect reset from admin UI",
          clear_bans: true,
        }),
      });
      await loadDashboard(account);
    } catch (error) {
      if (error instanceof ApiRequestError && error.status === 401) {
        clearAuth("관리자 세션이 만료되었습니다. 다시 로그인하세요.");
        return;
      }
      setRequestError(error instanceof Error ? error.message : "참가자 리셋에 실패했습니다.");
    } finally {
      setResettingParticipants((current) => ({ ...current, [target.userId]: false }));
    }
  }

  function renderNoteEditor(target: NoteTarget) {
    const canSave = account ? canWriteNotes(account.role) && !mockPreview : false;
    const isDirty = dirtyNotes[target.userId] === true;
    const saved = savedNotes[target.userId];
    return (
      <div className="min-w-64">
        <textarea
          value={draftNotes[target.userId] ?? saved?.note ?? ""}
          onChange={(event) => updateDraftNote(target.userId, event.target.value)}
          placeholder="운영 메모"
          rows={2}
          disabled={!canSave}
          className="w-full resize-y rounded-lg border border-border bg-bg-primary px-3 py-2 text-sm text-text-primary outline-none placeholder:text-text-muted focus:border-accent disabled:cursor-not-allowed disabled:opacity-60"
        />
        <div className="mt-2 flex items-center justify-between gap-2">
          <span className="truncate text-xs text-text-muted">
            {saved ? `${saved.author} · ${formatDateTime(saved.createdAt)}` : "저장된 비고 없음"}
          </span>
          <button
            type="button"
            onClick={() => void saveNote(target)}
            disabled={!canSave || !isDirty || savingNotes[target.userId] === true}
            className="inline-flex h-8 shrink-0 items-center gap-1 rounded-lg border border-border bg-bg-secondary px-2 text-xs text-text-secondary hover:bg-bg-tertiary hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Save className="h-3.5 w-3.5" />
            {savingNotes[target.userId] ? "저장 중" : "저장"}
          </button>
        </div>
      </div>
    );
  }

  function renderResetButton(target: NoteTarget) {
    const allowed = account ? canEnforce(account.role) && !mockPreview : false;
    const busy = resettingParticipants[target.userId] === true;
    return (
      <button
        type="button"
        onClick={() => void resetParticipant(target)}
        disabled={!allowed || busy}
        className="inline-flex h-9 items-center gap-1 rounded-lg border border-border bg-bg-secondary px-2 text-xs text-text-secondary hover:bg-bg-tertiary hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-50"
        title={allowed ? "활성 세션과 토큰을 정리하고 다시 접속할 수 있게 합니다." : "admin-enforcer 권한이 필요합니다."}
      >
        <RotateCcw className={cn("h-3.5 w-3.5", busy && "animate-spin")} />
        {busy ? "리셋 중" : "재연결 리셋"}
      </button>
    );
  }

  function renderPagination(totalItems: number, totalPages: number) {
    const pageItems = buildPaginationItems(page, totalPages);
    return (
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-border px-4 py-3">
        <span className="text-sm text-text-muted">
          페이지 {page} / {totalPages} · 총 {totalItems}개
        </span>
        <div className="flex flex-wrap gap-1">
          {pageItems.map((item, index) =>
            item === "ellipsis" ? (
              <span
                key={`ellipsis-${index}`}
                className="inline-flex h-9 min-w-9 items-center justify-center px-2 text-sm text-text-muted"
              >
                ...
              </span>
            ) : (
              <button
                key={item}
                type="button"
                onClick={() => setPage(item)}
                className={cn(
                  "h-9 min-w-9 rounded-lg border px-3 text-sm",
                  item === page
                    ? "border-accent bg-accent text-white"
                    : "border-border bg-bg-secondary text-text-secondary hover:bg-bg-tertiary",
                )}
              >
                {item}
              </button>
            ),
          )}
        </div>
      </div>
    );
  }

  if (bootstrapping) {
    return (
      <main className="min-h-screen bg-bg-primary px-5 py-8 text-text-primary">
        <section className="mx-auto flex min-h-[calc(100vh-4rem)] w-full max-w-md items-center justify-center text-sm text-text-muted">
          관리자 세션 확인 중...
        </section>
      </main>
    );
  }

  if (!account) {
    return (
      <main className="min-h-screen bg-bg-primary px-5 py-8 text-text-primary">
        <section className="mx-auto flex min-h-[calc(100vh-4rem)] w-full max-w-md items-center">
          <form
            onSubmit={login}
            className="w-full rounded-lg border border-border bg-bg-secondary p-6 shadow-sm"
          >
            <div className="mb-6 flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/10 text-accent">
                <Lock className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-lg font-semibold text-text-primary">C-Guard 관리자 로그인</h1>
                <p className="text-sm text-text-muted">서버 관리자 계정으로만 접속</p>
              </div>
            </div>

            <label className="mb-3 block text-sm font-medium text-text-secondary">
              아이디
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                className="mt-1 h-11 w-full rounded-lg border border-border bg-bg-primary px-3 text-sm text-text-primary outline-none focus:border-accent"
                autoComplete="username"
                required
              />
            </label>
            <label className="mb-4 block text-sm font-medium text-text-secondary">
              비밀번호
              <input
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="mt-1 h-11 w-full rounded-lg border border-border bg-bg-primary px-3 text-sm text-text-primary outline-none focus:border-accent"
                type="password"
                autoComplete="current-password"
                required
              />
            </label>

            {loginError && (
              <div className="mb-4 rounded-lg border border-status-danger/30 bg-status-danger/10 px-3 py-2 text-sm text-status-danger">
                {loginError}
              </div>
            )}

            <button
              type="submit"
              className="inline-flex h-11 w-full items-center justify-center gap-2 rounded-lg bg-accent px-4 text-sm font-semibold text-white transition-colors hover:bg-accent-hover"
            >
              <ShieldCheck className="h-4 w-4" />
              로그인
            </button>
          </form>
        </section>
      </main>
    );
  }

  return (
    <main className="min-h-screen bg-bg-primary text-text-primary">
      <header className="border-b border-border bg-bg-secondary px-5 py-4">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">
              {viewMode === "sessions" ? "C-Guard 세션" : "C-Guard 참가자"}
            </h1>
            <p className="mt-1 text-sm text-text-muted">
              {viewMode === "sessions"
                ? `${filteredSessions.length}개 세션${serverTotal > filteredSessions.length ? ` / 서버 ${serverTotal}개` : ""}, ${sessionPageCount}페이지`
                : `${participants.length}명 참가자 실시간 상태, ${participantPageCount}페이지`}
              {lastUpdatedAt ? `, 갱신 ${formatDateTime(lastUpdatedAt)}` : ""}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setViewMode("sessions")}
              className={cn(
                "inline-flex h-10 items-center gap-2 rounded-lg border px-3 text-sm",
                viewMode === "sessions"
                  ? "border-accent bg-accent/10 text-accent"
                  : "border-border bg-bg-secondary text-text-secondary hover:bg-bg-tertiary",
              )}
            >
              <ListChecks className="h-4 w-4" />
              세션
            </button>
            <button
              type="button"
              onClick={() => setViewMode("participants")}
              className={cn(
                "inline-flex h-10 items-center gap-2 rounded-lg border px-3 text-sm",
                viewMode === "participants"
                  ? "border-accent bg-accent/10 text-accent"
                  : "border-border bg-bg-secondary text-text-secondary hover:bg-bg-tertiary",
              )}
            >
              <Users className="h-4 w-4" />
              참가자
            </button>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-text-muted" />
              <input
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="검색"
                className="h-10 w-56 rounded-lg border border-border bg-bg-primary pl-9 pr-3 text-sm text-text-primary outline-none placeholder:text-text-muted focus:border-accent"
              />
            </div>
            <label className="inline-flex h-10 items-center gap-2 rounded-lg border border-border bg-bg-primary px-3 text-sm text-text-secondary">
              <ArrowDownUp className="h-4 w-4" />
              <select
                value={sortMode}
                onChange={(event) => setSortMode(event.target.value as SortMode)}
                className="bg-transparent text-text-primary outline-none"
              >
                <option value="newest">최신순</option>
                <option value="oldest">오래된순</option>
                <option value="participant">참가자순</option>
                <option value="risk">위험도순</option>
                <option value="cguard_off">C-Guard OFF 우선</option>
                <option value="detection">탐지 우선</option>
              </select>
            </label>
            <button
              type="button"
              onClick={() => void loadDashboard(account)}
              className="inline-flex h-10 items-center gap-2 rounded-lg border border-border bg-bg-secondary px-3 text-sm text-text-secondary hover:bg-bg-tertiary hover:text-text-primary disabled:cursor-wait disabled:opacity-60"
              disabled={loading}
            >
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
              새로고침
            </button>
            <button
              type="button"
              onClick={() => void downloadExport("zip")}
              className="inline-flex h-10 items-center gap-2 rounded-lg border border-border bg-bg-secondary px-3 text-sm text-text-secondary hover:bg-bg-tertiary hover:text-text-primary disabled:cursor-wait disabled:opacity-60"
              disabled={mockPreview || exporting === "zip"}
            >
              <Download className={cn("h-4 w-4", exporting === "zip" && "animate-pulse")} />
              기록 다운로드
            </button>
            <Pill className="border-accent/30 bg-accent/10 text-accent">
              {account.actor} · {account.role}
            </Pill>
            <button
              type="button"
              onClick={logout}
              className="inline-flex h-10 items-center gap-2 rounded-lg border border-border bg-bg-secondary px-3 text-sm text-text-secondary hover:bg-bg-tertiary hover:text-text-primary"
            >
              <LogOut className="h-4 w-4" />
              로그아웃
            </button>
          </div>
        </div>
      </header>

      <section className="mx-auto max-w-7xl px-5 py-5">
        {requestError && (
          <div className="mb-4 rounded-lg border border-status-danger/30 bg-status-danger/10 px-3 py-2 text-sm text-status-danger">
            {requestError}
          </div>
        )}

        <section className="mb-4 rounded-lg border border-status-danger/25 bg-status-danger/5">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-status-danger/15 px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-status-danger/10 text-status-danger">
                <AlertTriangle className="h-4 w-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-text-primary">최근 3분 고위험 TOP</h2>
                <p className="text-xs text-text-muted">
                  high 후보는 3분 동안 상단에 유지되고, 같은 참가자/근거는 한 줄로 묶입니다.
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs text-text-muted">
              <Pill className="border-border bg-bg-primary text-text-secondary">
                자동 갱신 {Math.round(AUTO_REFRESH_MS / 1000)}초
              </Pill>
              <Pill className="border-border bg-bg-primary text-text-secondary">
                중복 요청 차단 {skippedRefreshes}회
              </Pill>
              {mockPreview && (
                <Pill className="border-status-warning/35 bg-status-warning/10 text-status-warning">
                  mock preview
                </Pill>
              )}
            </div>
          </div>

          {recentHighSignals.length > 0 ? (
            <div className="grid gap-2 p-4 lg:grid-cols-2">
              {recentHighSignals.map((signal) => (
                <div
                  key={signal.key}
                  className="rounded-lg border border-status-danger/25 bg-bg-secondary px-4 py-3"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <div className="font-medium text-text-primary">{signal.displayName}</div>
                      <div className="mt-1 text-xs text-text-muted">{signal.userId}</div>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      <Pill className={statusTone(signal.status)}>{signal.status}</Pill>
                      <Pill className={detectionTone(signal.detection)}>{signal.detection}</Pill>
                      <Pill className="border-status-danger/35 bg-status-danger/10 text-status-danger">
                        {signal.confidence}%
                      </Pill>
                    </div>
                  </div>
                  <div className="mt-3 text-sm text-text-secondary">
                    <span className="font-medium text-text-primary">{signal.evidence}</span>
                    <span className="text-text-muted"> / {signal.count}회</span>
                  </div>
                  <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-text-muted">
                    <span>마지막 {formatDateTime(signal.lastSeen)}</span>
                    <span>최초 {formatDateTime(signal.firstSeen)}</span>
                    <span>C-Guard {signal.cguardOn ? "ON" : "OFF"}</span>
                    <code>{signal.latestSessionId}</code>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="px-4 py-6 text-sm text-text-muted">
              최근 3분 안에 상단 고정할 고위험 후보가 없습니다.
            </div>
          )}
        </section>

        {viewMode === "sessions" ? (
          <div className="overflow-hidden rounded-lg border border-border bg-bg-secondary">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1080px] border-collapse text-sm">
                <thead className="bg-bg-tertiary text-left text-xs uppercase text-text-muted">
                  <tr>
                    <th className="px-4 py-3 font-semibold">세션</th>
                    <th className="px-4 py-3 font-semibold">참가자</th>
                    <th className="px-4 py-3 font-semibold">C-Guard</th>
                    <th className="px-4 py-3 font-semibold">탐지</th>
                    <th className="px-4 py-3 font-semibold">신뢰도</th>
                    <th className="px-4 py-3 font-semibold">최근 시각</th>
                    <th className="px-4 py-3 font-semibold">판정 코드</th>
                    <th className="px-4 py-3 font-semibold">증거</th>
                    <th className="px-4 py-3 font-semibold">비고</th>
                  </tr>
                </thead>
                <tbody>
                  {pageSessions.map((row) => (
                    <tr key={row.sessionId} className="border-t border-border">
                      <td className="px-4 py-3 align-top">
                        <code className="text-xs text-text-primary">{row.sessionId}</code>
                      </td>
                      <td className="px-4 py-3 align-top">
                        <div className="font-medium text-text-primary">{row.displayName}</div>
                        <div className="mt-1 text-xs text-text-muted">{row.userId}</div>
                      </td>
                      <td className="px-4 py-3 align-top">
                        <Pill
                          className={
                            row.cguardOn
                              ? "border-status-ok/35 bg-status-ok/10 text-status-ok"
                              : "border-status-danger/35 bg-status-danger/10 text-status-danger"
                          }
                        >
                          {row.cguardOn ? "ON" : "OFF"}
                        </Pill>
                      </td>
                      <td className="px-4 py-3 align-top">
                        <Pill className={detectionTone(row.detection)}>{row.detection}</Pill>
                      </td>
                      <td className="px-4 py-3 align-top font-mono text-sm">{row.confidenceLabel}</td>
                      <td className="px-4 py-3 align-top text-text-secondary">
                        {formatDateTime(row.lastSeen)}
                      </td>
                      <td className="px-4 py-3 align-top">
                        <code className="text-xs text-text-primary">{row.reasonCode}</code>
                      </td>
                      <td className="max-w-xs px-4 py-3 align-top text-text-secondary">{row.evidence}</td>
                      <td className="px-4 py-3 align-top">
                        {renderNoteEditor({
                          userId: row.userId,
                          displayName: row.displayName,
                          latestSessionId: row.sessionId,
                        })}
                        <div className="mt-2">
                          {renderResetButton({
                            userId: row.userId,
                            displayName: row.displayName,
                            latestSessionId: row.sessionId,
                          })}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {pageSessions.length === 0 && (
                    <tr>
                      <td colSpan={9} className="border-t border-border px-4 py-8 text-center text-text-muted">
                        표시할 세션이 없습니다.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {renderPagination(filteredSessions.length, sessionPageCount)}
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-border bg-bg-secondary">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[960px] border-collapse text-sm">
                <thead className="bg-bg-tertiary text-left text-xs uppercase text-text-muted">
                  <tr>
                    <th className="px-4 py-3 font-semibold">참가자</th>
                    <th className="px-4 py-3 font-semibold">실시간 상태</th>
                    <th className="px-4 py-3 font-semibold">C-Guard</th>
                    <th className="px-4 py-3 font-semibold">탐지</th>
                    <th className="px-4 py-3 font-semibold">신뢰도</th>
                    <th className="px-4 py-3 font-semibold">최신 세션</th>
                    <th className="px-4 py-3 font-semibold">최근 시각</th>
                    <th className="px-4 py-3 font-semibold">비고</th>
                  </tr>
                </thead>
                <tbody>
                  {pageParticipants.map((row) => (
                    <tr key={row.userId} className="border-t border-border">
                      <td className="px-4 py-3 align-top">
                        <div className="font-medium text-text-primary">{row.displayName}</div>
                        <div className="mt-1 text-xs text-text-muted">
                          {row.userId} / 세션 {row.sessionCount}
                        </div>
                      </td>
                      <td className="px-4 py-3 align-top">
                        <Pill className={statusTone(row.liveStatus)}>{row.liveStatus}</Pill>
                      </td>
                      <td className="px-4 py-3 align-top">
                        <Pill
                          className={
                            row.cguardOn
                              ? "border-status-ok/35 bg-status-ok/10 text-status-ok"
                              : "border-status-danger/35 bg-status-danger/10 text-status-danger"
                          }
                        >
                          {row.cguardOn ? "ON" : "OFF"}
                        </Pill>
                      </td>
                      <td className="px-4 py-3 align-top">
                        <Pill className={detectionTone(row.detection)}>{row.detection}</Pill>
                      </td>
                      <td className="px-4 py-3 align-top font-mono text-sm">{row.confidenceLabel}</td>
                      <td className="px-4 py-3 align-top">
                        <code className="text-xs text-text-primary">{row.latestSessionId}</code>
                      </td>
                      <td className="px-4 py-3 align-top text-text-secondary">
                        {formatDateTime(row.lastSeen)}
                      </td>
                      <td className="px-4 py-3 align-top">
                        {renderNoteEditor({
                          userId: row.userId,
                          displayName: row.displayName,
                          latestSessionId: row.latestSessionId,
                        })}
                        <div className="mt-2">
                          {renderResetButton({
                            userId: row.userId,
                            displayName: row.displayName,
                            latestSessionId: row.latestSessionId,
                          })}
                        </div>
                      </td>
                    </tr>
                  ))}
                  {pageParticipants.length === 0 && (
                    <tr>
                      <td colSpan={8} className="border-t border-border px-4 py-8 text-center text-text-muted">
                        표시할 참가자가 없습니다.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {renderPagination(participants.length, participantPageCount)}
          </div>
        )}

        <section className="mt-5 rounded-lg border border-border bg-bg-secondary p-4">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-semibold text-text-primary">운영 도구</h2>
              <p className="text-xs text-text-muted">
                대회 시간과 기록 보관 상태를 한 곳에서 확인합니다.
              </p>
            </div>
            <div className="flex flex-wrap gap-2 text-xs text-text-muted">
              <Pill className="border-border bg-bg-primary text-text-secondary">
                아카이브 {runtimeConfig?.archive?.enabled ? "ON" : "OFF"}
              </Pill>
              {runtimeConfig?.archive?.session_group_size && (
                <Pill className="border-border bg-bg-primary text-text-secondary">
                  {runtimeConfig.archive.session_group_size}세션 단위
                </Pill>
              )}
            </div>
          </div>
          <div className="grid gap-3 lg:grid-cols-[1.2fr_1fr_1fr_auto]">
            <label className="text-xs font-medium text-text-muted">
              대회명
              <input
                value={competitionDraft.name}
                onChange={(event) =>
                  setCompetitionDraft((current) => ({ ...current, name: event.target.value }))
                }
                placeholder="대회명"
                className="mt-1 h-10 w-full rounded-lg border border-border bg-bg-primary px-3 text-sm text-text-primary outline-none placeholder:text-text-muted focus:border-accent"
              />
            </label>
            <label className="text-xs font-medium text-text-muted">
              시작 시간
              <input
                type="datetime-local"
                value={competitionDraft.startsAtLocal}
                onChange={(event) =>
                  setCompetitionDraft((current) => ({
                    ...current,
                    startsAtLocal: event.target.value,
                  }))
                }
                className="mt-1 h-10 w-full rounded-lg border border-border bg-bg-primary px-3 text-sm text-text-primary outline-none focus:border-accent"
              />
            </label>
            <label className="text-xs font-medium text-text-muted">
              종료 시간
              <input
                type="datetime-local"
                value={competitionDraft.endsAtLocal}
                onChange={(event) =>
                  setCompetitionDraft((current) => ({
                    ...current,
                    endsAtLocal: event.target.value,
                  }))
                }
                className="mt-1 h-10 w-full rounded-lg border border-border bg-bg-primary px-3 text-sm text-text-primary outline-none focus:border-accent"
              />
            </label>
            <button
              type="button"
              onClick={() => void saveCompetitionConfig()}
              disabled={mockPreview || savingCompetition || !account || !canEnforce(account.role)}
              className="mt-5 inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-border bg-bg-primary px-3 text-sm text-text-secondary hover:bg-bg-tertiary hover:text-text-primary disabled:cursor-not-allowed disabled:opacity-60"
            >
              <Save className={cn("h-4 w-4", savingCompetition && "animate-pulse")} />
              저장
            </button>
          </div>
        </section>
      </section>
    </main>
  );
}
