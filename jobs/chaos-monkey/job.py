# jobs/chaos-monkey/job.py
from loguru import logger


def main():
    # MVP: just log. Real version would hit K8s API and kill pods / inject latency.
    logger.warning("Chaos monkey (MVP) – no real chaos yet, just logging.")


if __name__ == "__main__":
    main()
