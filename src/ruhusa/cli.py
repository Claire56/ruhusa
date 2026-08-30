from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from typing import Any

EXIT_OK = 0
EXIT_UNHEALTHY = 1
EXIT_USAGE = 2

_DEFAULT_DSN_ENV = "RUHUSA_POSTGRES_DSN"


def _package_version() -> str:
    try:
        return version("ruhusa")
    except PackageNotFoundError:
        return "unknown"


def _positive_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _emit_error(
    message: str,
    *,
    exit_code: int,
    json_mode: bool,
) -> int:
    if json_mode:
        _emit_json(
            {
                "error": message,
                "exit_code": exit_code,
                "ok": False,
            }
        )
    else:
        print(f"error: {message}", file=sys.stderr)
    return exit_code


def _read_dsn(environment_variable: str) -> str | None:
    value = os.getenv(environment_variable)
    if value is None or not value.strip():
        return None
    return value


def _postgres_support():
    """Import PostgreSQL support lazily so base Ruhusa has no PG dependency."""

    try:
        from .postgres import create_postgres_pool
        from .postgres_health import (
            build_postgres_health_registry,
            postgres_audit_chain_probe,
            postgres_schema_probe,
        )
    except ImportError as exc:
        raise RuntimeError("POSTGRES_EXTRA_NOT_INSTALLED") from exc

    return (
        create_postgres_pool,
        build_postgres_health_registry,
        postgres_schema_probe,
        postgres_audit_chain_probe,
    )


def _open_postgres(
    *,
    dsn_env: str,
    timeout: float,
    json_mode: bool,
):
    dsn = _read_dsn(dsn_env)
    if dsn is None:
        return None, _emit_error(
            f"PostgreSQL DSN environment variable {dsn_env!r} is not set",
            exit_code=EXIT_USAGE,
            json_mode=json_mode,
        )

    try:
        create_pool, build_registry, schema_probe, audit_probe = _postgres_support()
    except RuntimeError as exc:
        if str(exc) != "POSTGRES_EXTRA_NOT_INSTALLED":
            raise
        return None, _emit_error(
            "PostgreSQL support is not installed; install ruhusa[postgres]",
            exit_code=EXIT_USAGE,
            json_mode=json_mode,
        )

    try:
        pool = create_pool(dsn, timeout=timeout)
    except Exception as exc:
        return None, _emit_error(
            f"PostgreSQL connection failed ({type(exc).__name__})",
            exit_code=EXIT_UNHEALTHY,
            json_mode=json_mode,
        )

    return (
        (pool, build_registry, schema_probe, audit_probe),
        None,
    )


def _close_pool(pool) -> None:
    try:
        pool.close()
    except Exception:
        # Diagnostics are already complete. Do not expose close exception text
        # or let cleanup mask the diagnostic result.
        pass


def _cmd_version(args: argparse.Namespace) -> int:
    if args.json:
        _emit_json(
            {
                "ok": True,
                "version": _package_version(),
            }
        )
    else:
        print(_package_version())
    return EXIT_OK


def _cmd_doctor(args: argparse.Namespace) -> int:
    payload = {
        "fastapi_extra_available": importlib.util.find_spec("fastapi") is not None,
        "ok": True,
        "postgres_extra_available": importlib.util.find_spec("psycopg") is not None,
        "python": platform.python_version(),
        "ruhusa": _package_version(),
    }

    if args.json:
        _emit_json(payload)
    else:
        print(f"ruhusa: {payload['ruhusa']}")
        print(f"python: {payload['python']}")
        print(
            "postgres extra: "
            + ("available" if payload["postgres_extra_available"] else "not installed")
        )
        print(
            "fastapi extra: "
            + ("available" if payload["fastapi_extra_available"] else "not installed")
        )

    return EXIT_OK


def _cmd_postgres_health(args: argparse.Namespace) -> int:
    opened, error_code = _open_postgres(
        dsn_env=args.dsn_env,
        timeout=args.timeout,
        json_mode=args.json,
    )
    if error_code is not None:
        return error_code

    assert opened is not None
    pool, build_registry, _, _ = opened

    try:
        try:
            report = build_registry(
                pool,
                include_audit_chain=not args.no_audit_chain,
            ).check()
        except Exception as exc:
            return _emit_error(
                f"PostgreSQL health diagnostic failed ({type(exc).__name__})",
                exit_code=EXIT_UNHEALTHY,
                json_mode=args.json,
            )

        if args.json:
            payload = report.as_dict()
            payload["ok"] = report.healthy
            _emit_json(payload)
        else:
            for check in report.checks:
                line = f"{check.status.value.upper():9} {check.name}"
                if check.detail:
                    line += f" - {check.detail}"
                print(line)
            print("overall: " + ("healthy" if report.healthy else "unhealthy"))

        return EXIT_OK if report.healthy else EXIT_UNHEALTHY
    finally:
        _close_pool(pool)


def _cmd_postgres_schema(args: argparse.Namespace) -> int:
    opened, error_code = _open_postgres(
        dsn_env=args.dsn_env,
        timeout=args.timeout,
        json_mode=args.json,
    )
    if error_code is not None:
        return error_code

    assert opened is not None
    pool, _, schema_probe, _ = opened

    try:
        try:
            healthy = bool(schema_probe(pool))
        except Exception as exc:
            return _emit_error(
                f"PostgreSQL schema diagnostic failed ({type(exc).__name__})",
                exit_code=EXIT_UNHEALTHY,
                json_mode=args.json,
            )

        if args.json:
            _emit_json(
                {
                    "check": "postgres.schema",
                    "healthy": healthy,
                    "ok": healthy,
                }
            )
        else:
            print("postgres.schema: " + ("healthy" if healthy else "unhealthy"))

        return EXIT_OK if healthy else EXIT_UNHEALTHY
    finally:
        _close_pool(pool)


def _cmd_postgres_audit(args: argparse.Namespace) -> int:
    opened, error_code = _open_postgres(
        dsn_env=args.dsn_env,
        timeout=args.timeout,
        json_mode=args.json,
    )
    if error_code is not None:
        return error_code

    assert opened is not None
    pool, _, _, audit_probe = opened

    try:
        try:
            valid = bool(audit_probe(pool))
        except Exception as exc:
            return _emit_error(
                f"PostgreSQL audit diagnostic failed ({type(exc).__name__})",
                exit_code=EXIT_UNHEALTHY,
                json_mode=args.json,
            )

        if args.json:
            _emit_json(
                {
                    "check": "postgres.audit_chain",
                    "ok": valid,
                    "valid": valid,
                }
            )
        else:
            print("postgres.audit_chain: " + ("valid" if valid else "invalid"))

        return EXIT_OK if valid else EXIT_UNHEALTHY
    finally:
        _close_pool(pool)


def _add_postgres_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dsn-env",
        default=_DEFAULT_DSN_ENV,
        help=(f"environment variable containing the PostgreSQL DSN (default: {_DEFAULT_DSN_ENV})"),
    )
    parser.add_argument(
        "--timeout",
        default=5.0,
        type=_positive_float,
        help="connection timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ruhusa",
        description="Read-only Ruhusa administrative diagnostics.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    version_parser = subcommands.add_parser(
        "version",
        help="show the installed Ruhusa version",
    )
    version_parser.add_argument("--json", action="store_true")
    version_parser.set_defaults(handler=_cmd_version)

    doctor_parser = subcommands.add_parser(
        "doctor",
        help="show local Ruhusa runtime diagnostics",
    )
    doctor_parser.add_argument("--json", action="store_true")
    doctor_parser.set_defaults(handler=_cmd_doctor)

    postgres_parser = subcommands.add_parser(
        "postgres",
        help="run read-only PostgreSQL diagnostics",
    )
    postgres_commands = postgres_parser.add_subparsers(
        dest="postgres_command",
        required=True,
    )

    health_parser = postgres_commands.add_parser(
        "health",
        help="check PostgreSQL connectivity, schema, and audit-chain health",
    )
    _add_postgres_common_arguments(health_parser)
    health_parser.add_argument(
        "--no-audit-chain",
        action="store_true",
        help="skip audit-chain verification",
    )
    health_parser.set_defaults(handler=_cmd_postgres_health)

    schema_parser = postgres_commands.add_parser(
        "schema",
        help="check Ruhusa PostgreSQL schema compatibility",
    )
    _add_postgres_common_arguments(schema_parser)
    schema_parser.set_defaults(handler=_cmd_postgres_schema)

    audit_parser = postgres_commands.add_parser(
        "audit",
        help="verify Ruhusa PostgreSQL audit-chain integrity",
    )
    _add_postgres_common_arguments(audit_parser)
    audit_parser.set_defaults(handler=_cmd_postgres_audit)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
