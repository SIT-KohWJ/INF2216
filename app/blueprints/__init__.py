"""Boundary controllers. Routing + rendering ONLY — no security logic (E1).
Each route delegates to a domain/security service and re-checks authz via
AccessControlService server-side."""
