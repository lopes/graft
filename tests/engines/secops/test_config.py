import pytest

from graft.engines.secops.config import SecOpsConfig


def test_secops_config_initialization_and_properties() -> None:
    config = SecOpsConfig(
        project="test-project",
        location="us",
        instance_id="11111111-2222-3333-4444-555555555555",
        service_account_email="sa@test-project.iam.gserviceaccount.com",
    )
    assert config.project == "test-project"
    assert config.location == "us"
    assert config.instance_id == "11111111-2222-3333-4444-555555555555"
    assert config.service_account_email == "sa@test-project.iam.gserviceaccount.com"
    assert config.api_version == "v1"
    assert config.base_url == "https://us-chronicle.googleapis.com/v1"
    assert (
        config.instance_path
        == "projects/test-project/locations/us/instances/11111111-2222-3333-4444-555555555555"
    )


def test_secops_config_from_env_staging(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAFT_STAGING_PROJECT", "staging-proj")
    monkeypatch.setenv("GRAFT_STAGING_LOCATION", "europe-west3")
    monkeypatch.setenv("GRAFT_STAGING_INSTANCE_ID", "22222222-3333-4444-5555-666666666666")
    monkeypatch.setenv("GRAFT_STAGING_SA_EMAIL", "staging-sa@staging-proj.iam.gserviceaccount.com")

    config = SecOpsConfig.from_env("staging")
    assert config.project == "staging-proj"
    assert config.location == "europe-west3"
    assert config.instance_id == "22222222-3333-4444-5555-666666666666"
    assert config.service_account_email == "staging-sa@staging-proj.iam.gserviceaccount.com"
    assert config.base_url == "https://europe-west3-chronicle.googleapis.com/v1"


def test_secops_config_from_env_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GRAFT_PROD_PROJECT", "prod-proj")
    monkeypatch.setenv("GRAFT_PROD_LOCATION", "us")
    monkeypatch.setenv("GRAFT_PROD_INSTANCE_ID", "33333333-4444-5555-6666-777777777777")
    monkeypatch.delenv("GRAFT_PROD_SA_EMAIL", raising=False)

    config = SecOpsConfig.from_env("prod")
    assert config.project == "prod-proj"
    assert config.location == "us"
    assert config.instance_id == "33333333-4444-5555-6666-777777777777"
    assert config.service_account_email is None


def test_secops_config_engine_namespaced_staging_and_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_PROJECT", "secops-stage-proj")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_LOCATION", "europe-west3")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_INSTANCE_ID", "secops-stage-uuid")
    monkeypatch.setenv("GRAFT_SECOPS_STAGING_SA_EMAIL", "sa@secops-stage.iam.gserviceaccount.com")

    config = SecOpsConfig.from_env("staging")
    assert config.project == "secops-stage-proj"
    assert config.location == "europe-west3"
    assert config.instance_id == "secops-stage-uuid"
    assert config.service_account_email == "sa@secops-stage.iam.gserviceaccount.com"


def test_secops_config_engine_namespaced_single_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GRAFT_SECOPS_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_SECOPS_PROD_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_PROD_PROJECT", raising=False)
    monkeypatch.setenv("GRAFT_SECOPS_PROJECT", "secops-lab-proj")
    monkeypatch.setenv("GRAFT_SECOPS_LOCATION", "us")
    monkeypatch.setenv("GRAFT_SECOPS_INSTANCE_ID", "secops-lab-uuid")

    staging_cfg = SecOpsConfig.from_env("staging")
    prod_cfg = SecOpsConfig.from_env("prod")
    assert staging_cfg.project == "secops-lab-proj"
    assert staging_cfg.is_same_instance(prod_cfg)


def test_secops_config_single_tenant_generic_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_SECOPS_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_SECOPS_PROD_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_SECOPS_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_PROD_PROJECT", raising=False)
    monkeypatch.setenv("GRAFT_PROJECT", "lab-proj")
    monkeypatch.setenv("GRAFT_LOCATION", "us")
    monkeypatch.setenv("GRAFT_INSTANCE_ID", "lab-instance-uuid")
    monkeypatch.setenv("GRAFT_SA_EMAIL", "lab-sa@lab-proj.iam.gserviceaccount.com")

    staging_cfg = SecOpsConfig.from_env("staging")
    prod_cfg = SecOpsConfig.from_env("prod")

    assert staging_cfg.project == "lab-proj"
    assert staging_cfg.instance_id == "lab-instance-uuid"
    assert staging_cfg.is_same_instance(prod_cfg)


def test_secops_config_staging_fallback_to_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_PROJECT", raising=False)
    monkeypatch.setenv("GRAFT_PROD_PROJECT", "single-prod-proj")
    monkeypatch.setenv("GRAFT_PROD_LOCATION", "us")
    monkeypatch.setenv("GRAFT_PROD_INSTANCE_ID", "single-prod-instance")

    staging_cfg = SecOpsConfig.from_env("staging")
    assert staging_cfg.project == "single-prod-proj"
    assert staging_cfg.instance_id == "single-prod-instance"


def test_secops_config_from_env_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_LOCATION", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_INSTANCE_ID", raising=False)
    monkeypatch.delenv("GRAFT_PROD_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_PROJECT", raising=False)

    with pytest.raises(KeyError, match="Missing required SecOps environment variables"):
        SecOpsConfig.from_env("staging")
