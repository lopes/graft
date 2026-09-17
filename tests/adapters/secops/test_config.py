import pytest

from graft.adapters.secops.config import SecOpsConfig


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


def test_secops_config_from_env_missing_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GRAFT_STAGING_PROJECT", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_LOCATION", raising=False)
    monkeypatch.delenv("GRAFT_STAGING_INSTANCE_ID", raising=False)

    with pytest.raises(KeyError, match="GRAFT_STAGING_PROJECT"):
        SecOpsConfig.from_env("staging")
