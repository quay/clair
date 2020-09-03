# Notifier 

When ClairV4 is running in Notifier mode its is responsible for generating notifications when new vulnerabilities affecting an indexed manifest enter the system. The notifier will either send a notification to a message borker (AMPQ, STOMP) or fire a webhook at a configurable target.
