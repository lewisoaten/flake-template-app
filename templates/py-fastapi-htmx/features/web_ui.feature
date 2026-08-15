Feature: Server-Rendered Web Interface
  As an administrator
  I want a fast server-rendered interface driven by HTMX
  So that I can work with items without shipping a single-page application.

  Background:
    Given a seeded application with an admin user and two items

  Scenario: Admin signs in with a one-time code
    Given I am on the sign-in page
    When I sign in as the admin with a valid authentication code
    Then I land on the item list
    And exactly 2 item rows are listed

  Scenario: Admin is refused without a one-time code
    Given I am on the sign-in page
    When I sign in as the admin without an authentication code
    Then I am shown an authentication error
    And I remain signed out

  Scenario: Admin changes an item status without a page reload
    Given I am signed in as the admin
    When I open the item "item-101"
    And I change its status to "active"
    Then the item status badge reads "active"
    And a save confirmation is shown

  Scenario: Admin filters the item list by searching
    Given I am signed in as the admin
    When I search the item list for "Telemetry"
    Then exactly 1 item row is listed
