"""G9 nginx — OPTIONAL private-prefix template syntax evidence (V3 Run D).

Host install-ready HTTPS/proxy/TLS is not a local V1 mandatory acceptance gate.
This module invokes the shipped generate + private-prefix ``nginx -t`` path
(``nginx validate``), never ``nginx -v`` as integration proof, and never touches
host ``/etc/nginx``.
"""

from __future__ import annotations

import shutil
from argparse import Namespace
from pathlib import Path

import pytest

from sbfleet import registry as reg
from sbfleet.nginx import nginx_cmd


@pytest.mark.docker
def test_nginx_private_prefix_template_validate_g9_optional(tmp_path: Path) -> None:
    """Optional: skip unless nginx binary present; prove private-prefix -t only."""
    if shutil.which("nginx") is None:
        pytest.skip("optional: host nginx binary not installed (G9 OPTIONAL template syntax)")

    root = reg.ensure_root(tmp_path / "home")
    fid = reg.fleet_id(root)
    pid = "00000000-0000-4000-8000-0000000000a9"
    slug = "g9tmpl"
    meta = {
        "format_version": 1,
        "id": pid,
        "fleet_id": fid,
        "slug": slug,
        "display_name": slug,
        "created_at": "2026-01-01T00:00:00Z",
        "profile": "standard",
        "compose_project": reg.compose_project_name(fid, pid),
        "ports": {
            "gateway": 25010,
            "db_direct": 25011,
            "pooler_session": 25012,
            "pooler_transaction": 25013,
        },
        "domain": "g9.example.test",
        "public_url": "https://g9.example.test",
        "upstream": {"ref": "self-hosted/v0.8.2", "sha": "a" * 40},
        "creation_complete": True,
        "image_digests": {},
    }
    reg.write_project(root, meta)
    (reg.project_dir(root, slug) / "deployment").mkdir(parents=True)

    gen = Namespace(action="generate", project=slug, json=False)
    assert nginx_cmd(root, gen) == 0
    conf = reg.project_dir(root, slug) / "generated" / "nginx.conf"
    assert conf.is_file()

    val = Namespace(action="validate", project=slug, json=False)
    code = nginx_cmd(root, val)
    assert code == 0, "private-prefix nginx -t must succeed on generated template"
