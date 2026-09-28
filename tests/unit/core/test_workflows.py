import stat
from pathlib import Path
from typing import Any

import yaml


def test_github_workflows_exist_and_are_valid_yaml() -> None:
    workflows_dir = Path(".github/workflows")
    assert workflows_dir.is_dir(), ".github/workflows directory must exist"

    pr_workflow = workflows_dir / "pr-validation.yml"
    deploy_workflow = workflows_dir / "deploy-production.yml"

    assert pr_workflow.is_file(), "pr-validation.yml must exist"
    assert deploy_workflow.is_file(), "deploy-production.yml must exist"

    with pr_workflow.open("r", encoding="utf-8") as f:
        pr_data = yaml.safe_load(f)
    assert isinstance(pr_data, dict), "pr-validation.yml must be a valid YAML mapping"

    with deploy_workflow.open("r", encoding="utf-8") as f:
        deploy_data = yaml.safe_load(f)
    assert isinstance(deploy_data, dict), "deploy-production.yml must be a valid YAML mapping"


def test_pr_validation_workflow_structure() -> None:
    pr_path = Path(".github/workflows/pr-validation.yml")
    with pr_path.open("r", encoding="utf-8") as f:
        data: dict[str, Any] = yaml.safe_load(f)

    # 1. Trigger verification
    triggers = data.get("on") or data.get("pull_request")
    assert triggers is not None, "Workflow must define triggers"
    assert "pull_request" in triggers, "Workflow must trigger on pull_request"

    # 2. Least-privilege permissions
    permissions = data.get("permissions", {})
    assert permissions == {"contents": "read"}, (
        "Top-level workflow permissions must be restricted to contents: read"
    )
    jobs = data.get("jobs", {})
    assert len(jobs) >= 1, "Workflow must define at least one job"

    cloud_job = jobs.get("secops-cloud-gates", {})
    cloud_perms = cloud_job.get("permissions", {})
    assert cloud_perms.get("id-token") == "write", (
        "secops-cloud-gates must declare id-token: write for WIF OIDC"
    )
    assert cloud_perms.get("pull-requests") == "write", (
        "secops-cloud-gates must declare pull-requests: write for PR diff comments"
    )
    assert cloud_perms.get("issues") == "write", (
        "secops-cloud-gates must declare issues: write for PR diff comments"
    )

    # 3. Step verification
    all_steps: list[dict[str, Any]] = []
    for job in jobs.values():
        all_steps.extend(job.get("steps", []))

    step_runs = [s.get("run", "") for s in all_steps if "run" in s]
    step_uses = [s.get("uses", "") for s in all_steps if "uses" in s]

    assert any("ruff check" in r for r in step_runs), "Must execute ruff check"
    assert any("ruff format" in r for r in step_runs), "Must execute ruff format check"
    assert any("mypy" in r for r in step_runs), "Must execute mypy strict"
    assert any("pytest" in r for r in step_runs), "Must execute pytest"
    assert any("graft lint" in r for r in step_runs), "Must execute graft lint"

    assert any("google-github-actions/auth" in u for u in step_uses), (
        "Must use google-github-actions/auth for WIF"
    )
    assert any("graft secops verify --env staging" in r for r in step_runs), (
        "Must execute graft secops verify --env staging to match staging/fallback SA token"
    )
    assert any("graft secops test" in r for r in step_runs), "Must execute graft secops test"
    assert any("graft secops diff" in r for r in step_runs), "Must execute graft secops diff"


def test_deploy_production_workflow_structure() -> None:
    deploy_path = Path(".github/workflows/deploy-production.yml")
    with deploy_path.open("r", encoding="utf-8") as f:
        data: dict[str, Any] = yaml.safe_load(f)

    # 1. Trigger verification
    triggers = data.get("on") or data.get("push")
    assert triggers is not None, "Workflow must define triggers"
    assert "push" in triggers, "Workflow must trigger on push to main"

    # 2. Least-privilege permissions
    permissions = data.get("permissions", {})
    assert permissions.get("contents") == "read", (
        "deploy-production.yml only needs contents: read (uploads Actions artifacts)"
    )
    jobs = data.get("jobs", {})
    has_id_token = permissions.get("id-token") == "write" or any(
        j.get("permissions", {}).get("id-token") == "write" for j in jobs.values()
    )
    assert has_id_token, "Workflow must declare id-token: write for WIF OIDC"

    # 3. Steps
    all_steps: list[dict[str, Any]] = []
    for job in jobs.values():
        all_steps.extend(job.get("steps", []))

    step_runs = [s.get("run", "") for s in all_steps if "run" in s]
    step_uses = [s.get("uses", "") for s in all_steps if "uses" in s]

    assert any("google-github-actions/auth" in u for u in step_uses), (
        "Must use google-github-actions/auth"
    )
    assert any("graft secops apply" in r for r in step_runs), "Must execute graft secops apply"
    assert any("graft export matrix" in r for r in step_runs), "Must export threat matrix layer"
    assert any("graft export catalog" in r for r in step_runs), "Must export catalog"
    assert any("actions/upload-artifact" in u for u in step_uses), "Must upload release artifacts"


def test_pre_commit_hook_exists_and_is_executable() -> None:
    hook_path = Path(".githooks/pre-commit")
    assert hook_path.is_file(), ".githooks/pre-commit hook must exist"

    # Verify executable bit
    mode = hook_path.stat().st_mode
    assert bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)), (
        ".githooks/pre-commit must be executable"
    )

    content = hook_path.read_text(encoding="utf-8")
    assert "graft lint" in content, "Pre-commit hook must execute graft lint"
    assert "ruff" in content, "Pre-commit hook must execute ruff"


def test_workflows_do_not_reference_secrets_in_if_conditionals() -> None:
    workflows_dir = Path(".github/workflows")
    for wf in workflows_dir.glob("*.yml"):
        with wf.open("r", encoding="utf-8") as f:
            data: dict[str, Any] = yaml.safe_load(f)
        jobs = data.get("jobs", {})
        for job_name, job_data in jobs.items():
            job_if = str(job_data.get("if", ""))
            assert "secrets." not in job_if, (
                f"Workflow {wf.name} job {job_name} references secrets in 'if': {job_if}. "
                "GitHub Actions disallows secrets in 'if:' expressions."
            )
            for step in job_data.get("steps", []):
                step_name = step.get("name", "unnamed")
                step_if = str(step.get("if", ""))
                assert "secrets." not in step_if, (
                    f"Workflow {wf.name} step {step_name} references secrets in 'if': {step_if}. "
                    "GitHub Actions disallows secrets in 'if:' expressions."
                )
