from loguru import logger


async def job() -> None:
    """
    Smoke-test job entrypoint for simulation validator.

    Real implementation should:
      - load/generate simulated telemetry
      - run it through FrostGate (API or engine)
      - compare against expected decisions
    """
    logger.info("sim_validator.job: placeholder run (noop)")
