--- an identity table for notifications
CREATE TABLE IF NOT EXISTS notification (
    id uuid PRIMARY KEY
);

--- a relation expressing the latest update operation
--- processed for a given updater name
CREATE TABLE IF NOT EXISTS notifier_update_operation (
    uo_id uuid PRIMARY KEY,
    updater text,
    ts timestamptz
);

--- a relation mapping notifications to their serialized json bodies
CREATE TABLE IF NOT EXISTS notification_body (
    id uuid PRIMARY KEY,
    notification_id uuid REFERENCES notification,
    body jsonb NOT NULL -- serialized json body of notification
);

CREATE INDEX notification_body_idx ON notification_body (notification_id, id);

--- an enumeration identifying the possible status a receipt may be in
CREATE TYPE receiptstatus AS ENUM (
    'created',
    'delivered',
    'delivery_failed',
    'deleted'
);

--- a relation expressing the current status of a notification
--- this acts as a trigger for application business logic
CREATE TABLE IF NOT EXISTS receipt (
    notification_id uuid PRIMARY KEY REFERENCES notification,
    uo_id uuid REFERENCES notifier_update_operation (uo_id),
    status receiptstatus NOT NULL,
    ts timestamptz,
    details jsonb -- any additional details specific to the delivery mechanism
);

CREATE INDEX receipt_idx ON receipt (notification_id, uo_id);

--- a relation holding a pub_key in PKIX, ASN.1 DER form
--- expiration is application defined and not associated with the public key
CREATE TABLE IF NOT EXISTS key (
    id uuid PRIMARY KEY,
    expiration timestamptz,
    pub_key bytea
);

