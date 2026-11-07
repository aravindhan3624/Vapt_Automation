@ckyc @security
Feature: CKYC API Security Regression
  Automated subset of the Banking Domain VAPT checklist (catalog/vapt-banking-catalog.yaml).
  Each scenario is tagged with its catalog finding id so results roll straight into the
  VAPT report / closure tracker under that id.

  Background:
    Given the "CKYC" project configuration is loaded
    And the project's authorization scope is valid for this environment

  @VAPT-010 @headers
  Scenario: Content-Security-Policy and other security headers are enforced
    When I call endpoint "customer.getById" as role "Maker"
    Then security headers should be secure
    And the result is recorded against finding "VAPT-010"

  @VAPT-014 @cookies
  Scenario: Session cookies carry Secure, HttpOnly and SameSite attributes
    When I log in as role "Maker" via the UI
    Then session cookies should have Secure, HttpOnly and SameSite set
    And the result is recorded against finding "VAPT-014"

  @VAPT-050 @auth
  Scenario: API rejects requests with no Authorization header
    When I call endpoint "customer.getById" without authentication
    Then the response status should be 401 or 403
    And the result is recorded against finding "VAPT-050"

  @VAPT-051 @jwt
  Scenario Outline: Tampered JWTs are rejected
    Given I am authenticated as role "Maker"
    When I call endpoint "customer.getById" with a "<tamperType>" token
    Then the response status should be 401 or 403
    And the result is recorded against finding "VAPT-051"
    Examples:
      | tamperType           |
      | alg-none              |
      | signature-stripped     |
      | expired                |

  @VAPT-049 @idor
  Scenario: Maker cannot read another customer's record via BOLA/IDOR
    Given I am authenticated as role "Maker"
    And a test customer id belonging to a different test user is known
    When I call endpoint "customer.getById" using that other customer id
    Then the response status should be 401, 403 or 404
    And the result is recorded against finding "VAPT-049"

  @VAPT-046 @sqli
  Scenario Outline: SQL injection probes are rejected on the customer search endpoint
    Given I am authenticated as role "Maker"
    When I submit SQL injection probe "<payload>" to endpoint "customer.getById"
    Then no SQL error signature should appear in the response
    And the result is recorded against finding "VAPT-046"
    Examples:
      | payload        |
      | '               |
      | ' OR '1'='1     |
      | 1 AND 1=2       |

  @VAPT-045 @xss
  Scenario Outline: XSS probes are encoded, not executed, on customer create
    Given I am authenticated as role "Maker"
    When I submit XSS probe "<payload>" to endpoint "customer.create" field "remarks"
    Then the stored/reflected value should be HTML-encoded
    And the result is recorded against finding "VAPT-045"
    Examples:
      | payload                        |
      | <script>alert(1)</script>       |
      | <img src=x onerror=alert(1)>    |

  @BR-CKYC-001 @business-logic
  Scenario: Maker cannot approve their own transaction
    Given I am authenticated as role "Maker"
    And I have created a test transaction
    When the same Maker attempts to approve that transaction
    Then the server should reject the approval with 403
    And the result is recorded against business rule "BR-CKYC-001"
