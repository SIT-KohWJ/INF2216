"""Isolated security services (from the Report 1 class diagram).

Each service owns one cohesive security concern so the logic lives in exactly
one place and is unit-testable. Boundary controllers and domain services call
these; they never re-implement crypto/authz inline.

The bodies are intentionally left as TODOs — they are the graded security
stories. Each docstring records the requirement IDs and the assigned lead from
the sprint plan so whoever picks it up has the spec in front of them.
"""
