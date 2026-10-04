-- U3b: persist observed entity attributes. Apply after 06; safe to re-run.
-- Existing volumes must apply this migration explicitly before the service upgrade.
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS username Nullable(String);
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS role Nullable(String);
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS os_hint Nullable(String);
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS criticality Nullable(String);
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS owner Nullable(String);
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS applications Array(String) DEFAULT [];
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS listening_services Array(String) DEFAULT [];
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS certificates Array(String) DEFAULT [];
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS ja4 Array(String) DEFAULT [];
ALTER TABLE ndr.asset ADD COLUMN IF NOT EXISTS attribute_provenance String DEFAULT '';
