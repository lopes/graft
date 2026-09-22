import logging
import uuid

from graft.core.models.rule import (
    BaseDeploymentConfig,
    RuleEnvelope,
    RuleMetadata,
    TestVector,
)
from graft.core.ports.replay import ReplayHarnessPort, ReplayResult
from graft.engines.secops.client import SecOpsClient
from graft.engines.secops.config import SecOpsConfig
from graft.engines.secops.deployer import SecOpsDeployerAdapter

logger = logging.getLogger("graft.secops.replay")


class SecOpsReplayAdapter(ReplayHarnessPort):
    def __init__(
        self,
        client: SecOpsClient,
        deployer: SecOpsDeployerAdapter | None = None,
        config: SecOpsConfig | None = None,
    ) -> None:
        self._client = client
        self._deployer = deployer or SecOpsDeployerAdapter(client=client)
        self._config = config

    @property
    def unavailable_reason(self) -> str | None:
        if self._config is None or not self._config.project or self._config.project == "mock":
            return "Staging tenant not configured"
        try:
            prod_config = SecOpsConfig.from_env(target="prod")
            if self._config.is_same_instance(prod_config):
                return (
                    "Replay tests require a dedicated staging tenant and cannot "
                    "run against production coordinates."
                )
        except Exception as exc:
            logger.debug("Failed checking prod config for replay coordinates: %s", exc)
        return None

    def is_available(self) -> bool:
        if self._config is None:
            return False
        if not (self._config.project and self._config.project != "mock"):
            return False
        try:
            prod_config = SecOpsConfig.from_env(target="prod")
            if self._config.is_same_instance(prod_config):
                return False
        except Exception as exc:
            logger.debug("Failed checking prod config for replay coordinates: %s", exc)
        return True

    def run_test_vector(self, rule: RuleEnvelope, vector: TestVector) -> ReplayResult:
        rule_id: str | None = None
        quarantine_name = f"graft_test_{rule.metadata.name}_{uuid.uuid4().hex[:8]}"

        quarantined_rule = RuleEnvelope(
            metadata=RuleMetadata(
                id="",
                name=quarantine_name,
                description=f"Quarantined test rule for {rule.metadata.name}",
                authors=rule.metadata.authors,
                mitre=rule.metadata.mitre,
            ),
            logic=rule.logic,
            deployment=BaseDeploymentConfig(enabled=True, alerting=False, run_frequency="live"),
            runbook=rule.runbook,
            tests=(),
        )

        try:
            # 1. Ingest synthetic UDM test events
            if vector.events:
                events_payload = [e.payload for e in vector.events]
                self._client.request("POST", ":udmIngest", body={"events": events_payload})

            # 2. Deploy quarantined rule (non-alerting)
            rule_id = self._deployer.create_rule(quarantined_rule)

            # 3. Determine time range for evaluation
            start_time = vector.events[0].timestamp if vector.events else "2026-09-17T00:00:00Z"
            end_time = vector.events[-1].timestamp if vector.events else "2026-09-17T23:59:59Z"

            # 4. Run rule evaluation
            eval_resp = self._client.request(
                "POST",
                f"rules/{rule_id}:run",
                body={"timeRange": {"startTime": start_time, "endTime": end_time}},
            )
            raw_detections = eval_resp.get("detections")
            raw_count = eval_resp.get("detectionCount", 0)
            matched_count = (
                len(raw_detections)
                if isinstance(raw_detections, list)
                else (int(raw_count) if isinstance(raw_count, (int, str)) else 0)
            )

            passed = matched_count == vector.expect
            if passed:
                msg = f"Passed: matched {matched_count} detection(s) as expected."
            else:
                msg = f"Failed: expected {vector.expect} detection(s), got {matched_count}."

            return ReplayResult(
                test_id=vector.id,
                passed=passed,
                message=msg,
                matched_events_count=matched_count,
            )

        except Exception as exc:
            return ReplayResult(
                test_id=vector.id,
                passed=False,
                message=f"Execution error during replay test: {exc}",
                matched_events_count=0,
            )

        finally:
            if rule_id:
                try:
                    self._deployer.delete_rule(rule_id)
                except Exception as cleanup_err:
                    logger.warning(
                        "Failed to delete quarantined test rule %s: %s",
                        rule_id,
                        cleanup_err,
                    )
