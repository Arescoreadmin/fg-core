DO $$
BEGIN
    BEGIN
        EXECUTE format(
            'ALTER ROLE %I NOSUPERUSER NOBYPASSRLS',
            current_user
        );
    EXCEPTION
        WHEN insufficient_privilege THEN
            -- Best-effort hardening: ignore if role cannot self-demote.
            NULL;
    END;
END $$;
