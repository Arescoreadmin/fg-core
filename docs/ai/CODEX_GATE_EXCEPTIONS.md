# Codex Gate Exceptions (Registry)

# Format:
# GATE_EXCEPTION|<gate>|<status>|reason=<...>|scope=<...>|follow_up=<...>|owner=<...>|expires=YYYY-MM-DD
#
# status: active|inactive
#
# Rules:
# - Exactly one active entry per gate
# - Active entries MUST include reason/scope/follow_up/owner/expires
# - Expired entries MUST be set inactive or removed per policy