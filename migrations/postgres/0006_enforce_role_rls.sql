DO $$
BEGIN
    BEGIN
        EXECUTE 'ALTER ROLE '
            || quote_ident(current_user)
            || ' NOSUPERUSER NOBYPASSRLS';
    EXCEPTION
        WHEN insufficient_privilege THEN
            -- Best-effort hardening: ignore if role cannot self-demote.
            NULL;
    END;
END $$;
