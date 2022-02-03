ALTER TABLE notification_body
    DROP CONSTRAINT notification_body_notification_id_fkey,
    ADD CONSTRAINT notification_body_notification_id_fkey FOREIGN KEY (notification_id) REFERENCES notification (id) ON DELETE CASCADE;

