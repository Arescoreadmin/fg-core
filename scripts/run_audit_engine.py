#!/usr/bin/env python3
from services.audit_engine import AuditEngine


if __name__ == "__main__":
    sid = AuditEngine().run_cycle("light")
    print(f"audit session: {sid}")
