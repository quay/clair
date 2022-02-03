ALTER TABLE receipt
    DROP CONSTRAINT receipt_notification_id_fkey,
    DROP CONSTRAINT receipt_uo_id_fkey,
    ADD CONSTRAINT receipt_notification_id_fkey FOREIGN KEY (notification_id) REFERENCES notification (id) ON DELETE CASCADE,
    ADD CONSTRAINT receipt_uo_id_fkey FOREIGN KEY (uo_id) REFERENCES notifier_update_operation (uo_id) ON DELETE CASCADE;

