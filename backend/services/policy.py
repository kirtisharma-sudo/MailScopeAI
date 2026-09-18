"""
Centralized policy language for attribution and cross-case relationships.
New code should import these constants rather than writing its own phrasing
inline, so the project's attribution stance stays consistent in one place
going forward. (Some pre-existing modules still carry their own inline
policy comments predating this file — this is the canonical version for
anything cross-case/relationship-related added from this point on.)
"""

ATTRIBUTION_LIMITATION = (
    "This relationship is based on shared observable technical indicators only. "
    "It does not establish common authorship, a confirmed campaign, or attacker identity."
)

RELATIONSHIP_LABEL = "Potentially Related Activity Detected"

RELATIONSHIP_BASIS = "Relationship based on shared observable indicators."

INFRASTRUCTURE_DISCLAIMER = (
    "Observable infrastructure (IPs, domains) may be shared, proxied, cloud-hosted, or otherwise "
    "not exclusively controlled by a single party. Infrastructure overlap is contextual evidence, not proof of identity."
)
