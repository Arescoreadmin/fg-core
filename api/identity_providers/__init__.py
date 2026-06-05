"""Identity provider implementations for FrostGate (H14).

Each provider validates credentials from its identity system and returns
an ActorContext. Routes never import from provider modules directly —
api.auth_dispatch resolves the correct provider at request time.
"""
