import json
import shlex
import textwrap
import time
from pathlib import Path
from typing import Annotated

import typer
from daytona import (
    CreateSandboxFromSnapshotParams,
    CreateSnapshotParams,
    Daytona,
    DaytonaConfig,
    Image,
    SessionExecuteRequest,
)

DEFAULT_SNAPSHOT_NAME = "airlock-daytona-soft-sandbox-main"
DEFAULT_SANDBOX_USER = "daytona"
DEFAULT_DOCKERFILE = Path(__file__).resolve().with_name("Dockerfile")
DEFAULT_AIRLOCK_SESSION = "airlock-proxy"
DEFAULT_LITELLM_MODEL = "openai/gpt-5-mini"
DEFAULT_LITELLM_PROMPT = "Reply with exactly: airlock-litellm-ok"
LITELLM_SCRIPT_PATH = "/workspace/airlock_litellm_probe.py"
SANDBOX_ENV = {
    "AIRLOCK_POLICY_PATH": "/opt/airlock/policies/openai-api.yaml",
    "AIRLOCK_PROXY_LISTEN": "127.0.0.1:18080",
    "HTTP_PROXY": "http://127.0.0.1:18080",
    "HTTPS_PROXY": "http://127.0.0.1:18080",
    "http_proxy": "http://127.0.0.1:18080",
    "https_proxy": "http://127.0.0.1:18080",
    "NO_PROXY": "localhost,127.0.0.1,::1",
    "no_proxy": "localhost,127.0.0.1,::1",
    "AIRLOCK_CA_CERT": "/run/airlock/ca/ca.crt",
    "SSL_CERT_FILE": "/run/airlock/ca/ca.crt",
    "REQUESTS_CA_BUNDLE": "/run/airlock/ca/ca.crt",
    "GIT_SSL_CAINFO": "/run/airlock/ca/ca.crt",
    "NODE_EXTRA_CA_CERTS": "/run/airlock/ca/ca.crt",
    "LITELLM_LOCAL_MODEL_COST_MAP": "True",
}

app = typer.Typer(no_args_is_help=True)
snapshot_app = typer.Typer(no_args_is_help=True)
app.add_typer(snapshot_app, name="snapshot")


def require_value(name: str, value: str | None) -> str:
    if not value:
        typer.echo(f"{name} is required", err=True)
        raise typer.Exit(1)
    return value


def new_daytona(api_key: str | None, target: str | None) -> Daytona:
    return Daytona(
        DaytonaConfig(
            api_key=require_value("DAYTONA_API_KEY", api_key),
            target=target or None,
        )
    )


def print_json(value: object) -> None:
    typer.echo(json.dumps(value, indent=2))


def snapshot_summary(snapshot: object) -> dict[str, object]:
    return {
        "id": getattr(snapshot, "id", None),
        "name": getattr(snapshot, "name", None),
        "state": getattr(snapshot, "state", None),
        "image_name": getattr(snapshot, "image_name", None),
        "entrypoint": getattr(snapshot, "entrypoint", None),
        "error_reason": getattr(snapshot, "error_reason", None),
        "cpu": getattr(snapshot, "cpu", None),
        "mem": getattr(snapshot, "mem", None),
        "disk": getattr(snapshot, "disk", None),
    }


def sandbox_summary(
    sandbox: object, snapshot_name: str, sandbox_user: str
) -> dict[str, object]:
    return {
        "id": getattr(sandbox, "id", None),
        "name": getattr(sandbox, "name", None),
        "state": getattr(sandbox, "state", None),
        "snapshot": snapshot_name,
        "os_user": sandbox_user,
    }


def find_snapshot(daytona: Daytona, name: str) -> object | None:
    page = 1
    while True:
        snapshots = daytona.snapshot.list(page=page, limit=100)
        for snapshot in snapshots.items:
            if getattr(snapshot, "name", None) == name:
                return snapshot
        if page >= snapshots.total_pages:
            return None
        page += 1


def wait_for_snapshot_deleted(
    daytona: Daytona, name: str, timeout_seconds: int
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if find_snapshot(daytona, name) is None:
            return
        time.sleep(2)
    typer.echo(f"timed out waiting for snapshot {name!r} to be deleted", err=True)
    raise typer.Exit(1)


def exec_output(response: object) -> str:
    return (
        getattr(response, "result", "")
        or getattr(response, "output", "")
        or getattr(response, "stdout", "")
        or ""
    )


def print_exec(label: str, response: object) -> None:
    typer.echo(f"{label}: {exec_output(response) or '(empty)'}")
    stderr = getattr(response, "stderr", "")
    if stderr:
        typer.echo(f"{label} stderr: {stderr}")
    exit_code = getattr(response, "exit_code", 0)
    if exit_code not in (None, 0):
        raise typer.Exit(exit_code or 1)


def litellm_probe_source(model: str, prompt: str) -> str:
    return textwrap.dedent(
        f"""
        import json
        import os

        os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

        from litellm import completion

        if os.environ.get("OPENAI_API_KEY"):
            raise SystemExit("OPENAI_API_KEY should not be visible to this process")

        response = completion(
            model={model!r},
            api_key="airlock-placeholder",
            messages=[{{"role": "user", "content": {prompt!r}}}],
            max_tokens=32,
        )
        content = response.choices[0].message.content
        print(json.dumps({{
            "model": {model!r},
            "openai_api_key_visible": False,
            "content": content,
        }}, indent=2))
        """
    ).lstrip()


@snapshot_app.command("create")
def create_snapshot(
    api_key: Annotated[
        str | None,
        typer.Option(envvar="DAYTONA_API_KEY", help="Daytona API key."),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(envvar="DAYTONA_TARGET", help="Daytona target/region."),
    ] = None,
    name: Annotated[
        str,
        typer.Option(
            "--name", envvar="AIRLOCK_DAYTONA_SNAPSHOT_NAME", help="Snapshot name."
        ),
    ] = DEFAULT_SNAPSHOT_NAME,
    dockerfile: Annotated[
        Path,
        typer.Option(
            "--dockerfile",
            envvar="AIRLOCK_DAYTONA_DOCKERFILE",
            exists=True,
            file_okay=True,
            dir_okay=False,
            resolve_path=True,
            help="Local Dockerfile to send to Daytona.",
        ),
    ] = DEFAULT_DOCKERFILE,
    image: Annotated[
        str | None,
        typer.Option(
            "--image",
            envvar="AIRLOCK_DAYTONA_IMAGE",
            help="Use a prebuilt image instead of --dockerfile.",
        ),
    ] = None,
    replace: Annotated[
        bool,
        typer.Option(
            "--replace/--keep-existing",
            help="Delete an existing snapshot with the same name first.",
        ),
    ] = True,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Snapshot creation timeout in seconds."),
    ] = 600,
    delete_timeout: Annotated[
        int,
        typer.Option(
            "--delete-timeout", help="Existing snapshot deletion timeout in seconds."
        ),
    ] = 120,
) -> None:
    daytona = new_daytona(api_key, target)
    snapshot_image = image or Image.from_dockerfile(dockerfile)

    existing_snapshot = find_snapshot(daytona, name)
    if existing_snapshot is not None:
        if not replace:
            print_json(
                {"snapshot": snapshot_summary(existing_snapshot), "created": False}
            )
            return
        print_json({"snapshot": snapshot_summary(existing_snapshot), "deleting": True})
        daytona.snapshot.delete(existing_snapshot)
        wait_for_snapshot_deleted(daytona, name, delete_timeout)

    snapshot = daytona.snapshot.create(
        CreateSnapshotParams(
            name=name,
            image=snapshot_image,
        ),
        on_logs=lambda chunk: typer.echo(chunk),
        timeout=timeout,
    )

    print_json({"snapshot": snapshot_summary(snapshot), "created": True})


@snapshot_app.command("run")
def run_snapshot(
    api_key: Annotated[
        str | None,
        typer.Option(envvar="DAYTONA_API_KEY", help="Daytona API key."),
    ] = None,
    target: Annotated[
        str | None,
        typer.Option(envvar="DAYTONA_TARGET", help="Daytona target/region."),
    ] = None,
    name: Annotated[
        str,
        typer.Option(
            "--name", envvar="AIRLOCK_DAYTONA_SNAPSHOT_NAME", help="Snapshot name."
        ),
    ] = DEFAULT_SNAPSHOT_NAME,
    sandbox_user: Annotated[
        str,
        typer.Option(
            "--sandbox-user",
            envvar="AIRLOCK_DAYTONA_SANDBOX_USER",
            help="Sandbox OS user.",
        ),
    ] = DEFAULT_SANDBOX_USER,
    sandbox_name: Annotated[
        str | None,
        typer.Option(
            "--sandbox-name",
            envvar="DAYTONA_SANDBOX_NAME",
            help="Optional sandbox name.",
        ),
    ] = None,
    openai_api_key: Annotated[
        str | None,
        typer.Option(
            "--openai-api-key",
            envvar="OPENAI_API_KEY",
            help="Secret value written into /run/daytona-secrets/secrets.env.",
        ),
    ] = None,
    airlock_session: Annotated[
        str,
        typer.Option(
            "--airlock-session",
            help="Daytona session name for the Airlock proxy process.",
        ),
    ] = DEFAULT_AIRLOCK_SESSION,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Sandbox creation timeout in seconds."),
    ] = 600,
    readiness_timeout: Annotated[
        int,
        typer.Option(
            "--readiness-timeout", help="Airlock readiness timeout in seconds."
        ),
    ] = 120,
    litellm_prompt: Annotated[
        str,
        typer.Option(
            "--litellm-prompt",
            envvar="AIRLOCK_LITELLM_PROMPT",
            help="Prompt for the LiteLLM probe.",
        ),
    ] = DEFAULT_LITELLM_PROMPT,
) -> None:
    daytona = new_daytona(api_key, target)
    secret_value = require_value("OPENAI_API_KEY", openai_api_key)

    snapshot = daytona.snapshot.get(name)
    print_json({"snapshot": snapshot_summary(snapshot)})

    sandbox = daytona.create(
        CreateSandboxFromSnapshotParams(
            snapshot=name,
            os_user=sandbox_user,
            name=sandbox_name,
            labels={
                "app": "airlock",
                "example": "daytona-soft-sandbox",
            },
            env_vars=SANDBOX_ENV,
            auto_stop_interval=0,
        ),
        timeout=timeout,
    )
    print_json(sandbox_summary(sandbox, name, sandbox_user))

    entrypoint_logs = sandbox.process.get_entrypoint_logs()
    typer.echo(f"Entrypoint logs: {entrypoint_logs}")

    secret_setup = sandbox.process.exec(
        """
set -eu
printf "OPENAI_API_KEY=%s\\n" "$OPENAI_API_KEY" >/run/daytona-secrets/secrets.env
echo "secret_bundle_ready=/run/daytona-secrets/secrets.env"
""",
        env={"OPENAI_API_KEY": secret_value},
        timeout=30,
    )
    print_exec("Secret setup", secret_setup)

    sandbox.process.create_session(airlock_session)
    airlock_start = sandbox.process.execute_session_command(
        airlock_session,
        SessionExecuteRequest(
            command="sudo -n -u airlock -- /usr/local/bin/airlock-daytona-start-proxy",
            run_async=True,
        ),
    )
    typer.echo(
        f"Airlock session start: {getattr(airlock_start, 'output', '') or '(started)'}"
    )

    readiness = sandbox.process.exec(
        f"""
set -eu
for attempt in $(seq 1 {readiness_timeout}); do
  if nc -z 127.0.0.1 18080; then
    echo "airlock_proxy=ready"
    exit 0
  fi
  sleep 1
done
echo "airlock_proxy=not_ready"
sed -n '1,160p' /var/log/airlock/proxy-worker.log 2>&1 || true
exit 1
""",
        timeout=readiness_timeout + 30,
    )
    print_exec("Readiness", readiness)

    sandbox.process.create_session("probe")
    command = sandbox.process.execute_session_command(
        "probe",
        SessionExecuteRequest(command="whoami"),
    )
    typer.echo(f"Session: {command.output}")
    typer.echo(f"Sandbox User: {sandbox.user}")

    response = sandbox.process.exec("whoami", timeout=30)
    print_exec("Process exec whoami", response)

    permission_probe = sandbox.process.exec(
        """
set -eu
if test -r /run/daytona-secrets/secrets.env; then
  echo "daytona_can_read_source_secret=true"
  exit 1
fi
echo "daytona_can_read_source_secret=false"
if test -r /run/airlock/secrets/openai-api-key; then
  echo "daytona_can_read_airlock_secret=true"
  exit 1
fi
echo "daytona_can_read_airlock_secret=false"
if test -r /run/airlock/ca/ca.key; then
  echo "daytona_can_read_ca_key=true"
  exit 1
fi
echo "daytona_can_read_ca_key=false"
""",
        timeout=30,
    )
    print_exec("Permission probe", permission_probe)

    script = litellm_probe_source(DEFAULT_LITELLM_MODEL, litellm_prompt)
    sandbox.fs.upload_file(script.encode("utf-8"), LITELLM_SCRIPT_PATH)
    typer.echo(f"LiteLLM probe script: {LITELLM_SCRIPT_PATH}")
    litellm_response = sandbox.process.exec(
        f"python3 {shlex.quote(LITELLM_SCRIPT_PATH)}",
        timeout=120,
    )
    print_exec("LiteLLM OpenAI probe", litellm_response)

    run_code = sandbox.code_interpreter.run_code(
        textwrap.dedent(
            """
            import json
            import os
            import pwd

            uid = os.getuid()
            gid = os.getgid()
            print(json.dumps({
                "uid": uid,
                "gid": gid,
                "username": pwd.getpwuid(uid).pw_name,
                "group": pwd.getpwuid(uid).pw_gid,
                "home": os.path.expanduser("~"),
                "cwd": os.getcwd(),
                "env_user": os.environ.get("USER"),
                "env_home": os.environ.get("HOME"),
            }, indent=2))
            """
        ),
        timeout=30,
    )
    typer.echo("run_code stdout:")
    typer.echo(run_code.stdout or "(empty)")
    if run_code.stderr:
        typer.echo("run_code stderr:")
        typer.echo(run_code.stderr)
    if run_code.error:
        typer.echo("run_code error:")
        typer.echo(run_code.error)


if __name__ == "__main__":
    app()
