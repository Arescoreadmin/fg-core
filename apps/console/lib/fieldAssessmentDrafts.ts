/**
 * fieldAssessmentDrafts.ts
 *
 * IndexedDB-backed draft queue for field assessment forms.
 * Allows assessors to auto-save in-progress observations and scan imports
 * without losing work on page refresh or accidental navigation.
 *
 * This subsystem is NOT standalone. It is a tenant-scoped component of
 * the Field Assessment Engagement Substrate.
 *
 * Security: drafts are local-only, never transmitted, and cleared on submit.
 * No governance state or tenant data persists in browser storage APIs beyond IndexedDB.
 */

const DB_NAME = 'fg_fa_drafts';
const DB_VERSION = 1;
const STORE_NAME = 'drafts';

type DraftType = 'observation' | 'scan';

interface DraftKey {
  type: DraftType;
  engagementId: string;
}

interface DraftRecord {
  key: string; // `${type}:${engagementId}`
  type: DraftType;
  engagementId: string;
  data: Record<string, unknown>;
  savedAt: string;
}

function draftKey(type: DraftType, engagementId: string): string {
  return `${type}:${engagementId}`;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE_NAME, { keyPath: 'key' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveDraft(
  type: DraftType,
  engagementId: string,
  data: Record<string, unknown>,
): Promise<void> {
  try {
    const db = await openDb();
    const record: DraftRecord = {
      key: draftKey(type, engagementId),
      type,
      engagementId,
      data,
      savedAt: new Date().toISOString(),
    };
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).put(record);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // Draft save failures are non-fatal
  }
}

export async function loadDraft(
  type: DraftType,
  engagementId: string,
): Promise<Record<string, unknown> | null> {
  try {
    const db = await openDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(draftKey(type, engagementId));
      req.onsuccess = () => {
        const record = req.result as DraftRecord | undefined;
        resolve(record?.data ?? null);
      };
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
}

export async function clearDraft(type: DraftType, engagementId: string): Promise<void> {
  try {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      tx.objectStore(STORE_NAME).delete(draftKey(type, engagementId));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // Clearing a non-existent draft is fine
  }
}
