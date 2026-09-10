-- V3__rls_policies.sql

-- Enable Row-Level Security on case_person
ALTER TABLE case_person ENABLE ROW LEVEL SECURITY;

-- Create policy allowing access only if the current user is assigned to the case
CREATE POLICY case_person_policy ON case_person
    USING (
        EXISTS (
            SELECT 1 FROM case_assignment ca 
            WHERE ca.case_id = case_person.case_id 
            AND ca.user_id = current_setting('app.current_user_id', true)::uuid
        )
    );
