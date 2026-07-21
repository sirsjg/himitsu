BEGIN;
DROP TRIGGER IF EXISTS audit_events_reject_update_delete ON audit_events;
DROP FUNCTION IF EXISTS reject_audit_event_mutation();
COMMIT;
