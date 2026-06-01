-- PR 104: Add client_access_code column to fa_engagements
-- Generated at QA-approve time; null until first QA approval.
ALTER TABLE fa_engagements
    ADD COLUMN IF NOT EXISTS client_access_code VARCHAR(64);
