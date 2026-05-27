/**
 * attestationDrafts.ts
 *
 * IndexedDB-backed draft queue for client attestation forms.
 * Drafts are auto-saved on input changes and cleared on successful submit.
 *
 * Security: drafts are local-only, never transmitted, and cleared on submit.
 * No governance state or tenant data persists in browser storage APIs beyond IndexedDB.
 */

const DB_NAME = 'fg_portal_drafts';
const DB_VERSION = 1;
const STORE_NAME = 'attestation_drafts';

interface AttestationDraftRecord {
  key: string; // `${assetId}`
  assetId: string;
  ownerEmail: string;
  attestationType: string;
  statement: string;
  notes: string;
  savedAt: string;
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

export interface AttestationDraft {
  ownerEmail: string;
  attestationType: string;
  statement: string;
  notes: string;
}

export async function saveAttestationDraft(
  assetId: string,
  draft: AttestationDraft,
): Promise<void> {
  try {
    const db = await openDb();
    const record: AttestationDraftRecord = {
      key: assetId,
      assetId,
      ...draft,
      savedAt: new Date().toISOString(),
    };
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const req = tx.objectStore(STORE_NAME).put(record);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
    db.close();
  } catch {
    // Draft save is best-effort; never block the UI
  }
}

export async function loadAttestationDraft(
  assetId: string,
): Promise<AttestationDraft | null> {
  try {
    const db = await openDb();
    const record = await new Promise<AttestationDraftRecord | undefined>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const req = tx.objectStore(STORE_NAME).get(assetId);
      req.onsuccess = () => resolve(req.result as AttestationDraftRecord | undefined);
      req.onerror = () => reject(req.error);
    });
    db.close();
    if (!record) return null;
    return {
      ownerEmail: record.ownerEmail,
      attestationType: record.attestationType,
      statement: record.statement,
      notes: record.notes,
    };
  } catch {
    return null;
  }
}

export async function clearAttestationDraft(assetId: string): Promise<void> {
  try {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const req = tx.objectStore(STORE_NAME).delete(assetId);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
    db.close();
  } catch {
    // Best-effort
  }
}
