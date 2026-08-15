Feature: Ownership Scoping And Admin Areas
  As the application
  I want every surface scoped to the records the signed-in user owns
  So that one member can neither see nor reach another member's data.

  Background:
    Given two members who each own one item

  Scenario: A member sees only their own items
    Given I am signed in as the first member
    When I open the item list
    Then exactly 1 item row is listed
    And the listed item is the one I own

  Scenario: Another member's item is not found rather than forbidden
    Given I am signed in as the first member
    When I request the item belonging to the second member
    Then I am shown a not found page

  Scenario: The webhooks admin area is closed to members
    Given I am signed in as the first member
    When I request the webhooks admin area
    Then I am shown a permission denied page
