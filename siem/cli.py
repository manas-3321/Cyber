"""Command line interface.

    python -m siem run                # ingest, detect, correlate, report
    python -m siem generate           # regenerate the simulated log bundle
    python -m siem serve --port 8000  # serve the dashboard for review
"""
from __future__ import annotations

import argparse
import functools
import http.server
import socketserver
import sys
from pathlib import Path

from . import config, pipeline


class DashboardHandler(http.server.SimpleHTTPRequestHandler):
    """Serve the output directory and map / to the dashboard."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(config.OUTPUT_DIR), **kwargs)

    def do_GET(self):  # noqa: N802 - stdlib naming
        if self.path in ("/", "/index.html"):
            self.path = "/dashboard.html"
        return super().do_GET()

    def log_message(self, fmt, *args):  # quieter logs
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))


def cmd_run(args) -> int:
    data_path = Path(args.data) if args.data else None
    output_dir = Path(args.out) if args.out else None
    result = pipeline.run(data_path, output_dir, write_events=not args.no_events)
    pipeline.print_summary(result)
    return 0


def cmd_generate(args) -> int:
    from scenarios import generator

    manifest = generator.generate(seed=args.seed)
    total = sum(manifest["counts"].values())
    print(f"generated {total:,} raw log records in data/logs")
    for name, count in manifest["counts"].items():
        print(f"  {name:>18}: {count}")
    return 0


def cmd_serve(args) -> int:
    if not config.DASHBOARD_FILE.exists() or args.refresh:
        pipeline.run(write_events=False)
    handler = functools.partial(DashboardHandler)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    with socketserver.ThreadingTCPServer((args.host, args.port), handler) as httpd:
        print(f"dashboard available at http://{args.host}:{args.port}/ (Ctrl+C to stop)")
        print(f"serving {config.OUTPUT_DIR}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="siem",
        description="Security Incident Detection and Analysis — lab SIEM pipeline",
    )
    sub = parser.add_subparsers(dest="command")

    run_parser = sub.add_parser("run", help="run the detection pipeline")
    run_parser.add_argument("--data", help="log directory (default: data/logs)")
    run_parser.add_argument("--out", help="output directory (default: output)")
    run_parser.add_argument("--no-events", action="store_true",
                            help="skip writing events.jsonl")
    run_parser.set_defaults(func=cmd_run)

    gen_parser = sub.add_parser("generate", help="regenerate the simulated log bundle")
    gen_parser.add_argument("--seed", type=int, default=20261031)
    gen_parser.set_defaults(func=cmd_generate)

    serve_parser = sub.add_parser("serve", help="serve the generated dashboard")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--refresh", action="store_true",
                              help="re-run the pipeline before serving")
    serve_parser.set_defaults(func=cmd_serve)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        args = parser.parse_args(["run"])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
