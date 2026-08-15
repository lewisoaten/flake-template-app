Feature: Item Lifecycle And Its Side Effects
  As the application
  I want a status change on an item to drive the rest of the system
  So that the audit trail and any partner integration stay in step with the record.

  Background:
    Given an integration holding an API key scoped to items and audit
    And an item "item-101" in status "draft"

  Scenario: Activating a draft item is recorded in the audit trail
    When the integration changes the item status to "active"
    Then the change is accepted
    And an audit entry named "ItemStatusChanged" is recorded for the item

  Scenario: Archiving an item dispatches a signed webhook that is logged
    Given a registered webhook endpoint "http://127.0.0.1:9099/hooks/items"
    When the integration changes the item status to "active"
    And the integration changes the item status to "archived"
    Then 2 HTTP POST payloads are dispatched to the endpoint
    And every dispatched payload carries a valid signature
    And the response status code logged in the DB audit trail should be 200

  Scenario: A failing endpoint is retried and recorded as failed
    Given a registered webhook endpoint "http://127.0.0.1:9099/hooks/items"
    And the partner endpoint responds with status 500
    When the integration changes the item status to "active"
    Then 3 delivery attempts are recorded in the DB audit trail
    And no delivery is marked as successful

  Scenario: An illegal transition is rejected and dispatches nothing
    Given a registered webhook endpoint "http://127.0.0.1:9099/hooks/items"
    And the item is already in status "archived"
    When the integration changes the item status to "active"
    Then the change is rejected as invalid
    And no HTTP POST is dispatched to the endpoint
