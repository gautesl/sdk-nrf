"""
Copyright (c) 2023 Nordic Semiconductor ASA

SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

This extension adds a custom role, :ncs-tool-version: that can be used as a
placeholder for the actual tool version used. The extension collects
tool versions from the "tool-versions-{os}" and pip requirement files.

The role takes one argument, which is the tool that is inquired about.
The tool must be in all uppercase, only uses underscores and follows the
following pattern:

For tool-versions-{os} files:
    {TOOL_NAME}_VERSION_{OS}
where OS is one of WIN10, LINUX or DARWIN

For pip requirement files:
    {TOOL_NAME}_VERSION

Examples of use:
- :ncs-tool-version:`CMAKE_VERSION_LINUX`
- :ncs-tool-version:`SPHINX_VERSION`
- :ncs-tool-version:`SPHINX_NCS_THEME_VERSION`

"""

from docutils import nodes
from sphinx.application import Sphinx
from typing import List, Dict, Callable
from sphinx.util import logging
from west.manifest import Manifest
from pathlib import Path
import subprocess
import re

__version__ = "0.1.0"

logger = logging.getLogger(__name__)


def get_zephyr_version(version_file: str) -> Dict[str, str]:
    version = {}
    for line in version_file.split("\n"):
        if not line.strip():
            continue
        match = re.match("(\w+)\s*=\s*([\w\d_-]*)", line)
        if match:
            label, value = match.groups()
            version[label] = value
        else:
            logger.warning(f"unexpected line in Zephyr VERSION file: {line}")
    return version


def find_migration_guides(merge_base: str, cwd: Path):
    def git_show_file(revision: str, filename: str, cwd: Path) -> str:
        try:
            return subprocess.run(
                ["git", "show", f"{revision}:{filename}"],
                check=True,
                cwd=cwd,
                capture_output=True,
                text=True,
            ).stdout
        except subprocess.CalledProcessError:
            logger.info(f"Could not find file '{filename}' in revision {revision}")
            return None

    def get_guide_file(revision: str, version: Dict[str, str]) -> str:
        minor = (
            int(version["VERSION_MINOR"]) + 1
            if version["PATCHLEVEL"] == "99"
            else version["VERSION_MINOR"]
        )
        major = int(version["VERSION_MAJOR"])
        guide_file = git_show_file(
            revision, f"doc/releases/migration-guide-{major}.{minor}.rst", cwd
        )
        if not guide_file:
            major += 1
            minor = 0
            guide_file = git_show_file(
                revision, f"doc/releases/migration-guide-{major}.{minor}.rst", cwd
            )
        return guide_file

    current_version_file = git_show_file("FETCH_HEAD", "VERSION", cwd)
    base_version_file = git_show_file(merge_base, "VERSION", cwd)
    if not current_version_file or not base_version_file:
        return None

    current_version = get_zephyr_version(current_version_file)
    base_version = get_zephyr_version(base_version_file)

    current_guide_file = get_guide_file("FETCH_HEAD", base_version)
    if not current_guide_file:
        return None

    base_guide_file = get_guide_file(merge_base, base_version)
    ##### FOR TESTING #####
    base_guide_file = (Path(__file__).parent / "test_migration.rst").read_text()
    ### END FOR TESTING ###

    if (
        base_version["VERSION_MINOR"] == current_version["VERSION_MINOR"]
        and base_version["VERSION_MAJOR"] == current_version["VERSION_MAJOR"]
        or current_version["EXTRAVERSION"].startswith("rc")
    ):
        return assemble_migration_guide(base_guide_file, current_guide_file, None)

    next_guide_file = get_guide_file("FETCH_HEAD", current_version)
    return assemble_migration_guide(
        base_guide_file, current_guide_file, next_guide_file
    )


def assemble_migration_guide(base: str, current: str, next: str) -> None:
    print(f"Assembling migration guide from:\nbase: {len(str(base))}\ncurrent: {len(str(current))}\nnext: {len(str(next))}")

    match = re.match(r".*\nRequired changes\n.*(\* .+)*\nRecommended Changes\n(\* .*)*", current)
    print(match)

    # import docutils.parsers.rst
    # import docutils.utils
    # import docutils.frontend
    # parser = docutils.parsers.rst.Parser()                                                                               
    # settings = docutils.frontend.get_default_settings(docutils.parsers.rst.Parser)
    # document = docutils.utils.new_document('assembled-migration-guide', settings=settings)                                               
    # parser.parse(current, document)      
    # from docutils.core import publish_doctree
    # tree = publish_doctree(current)
    # for node in tree.children:
    #     print(repr(node))
    # for item in tree:
    #     print(len(item))                                                                                 


def commit_replace(app: Sphinx) -> Callable:
    """Create a version mapping and a role function to replace versions given the
    content of the mapping.
    """

    app.config.init_values()
    manifest = Manifest.from_topdir()
    topdir = Path(manifest.topdir)

    shas = {
        "merge-base": {},
        "merge-base-short": {},
        "revision": {},
        "revision-short": {},
    }

    for project in manifest.get_projects(app.config.fetch_upstream_repos):
        url = app.config.fetch_upstream_repos[project.name]
        print(f"Fetching {url}")

        # Check that project.revision is present in sdk-zephyr folder
        # ... contains ref
        # git merge-base --is-ancestor {rev1} {rev2}

        # git fetch URL BRANCH else we get a random branch in FETCH_HEAD

        merge_base = subprocess.run(
            f"git fetch {url} main && git merge-base {project.revision} FETCH_HEAD",
            check=True,
            cwd=topdir / project.path,
            capture_output=True,
            text=True,
            # shell=True, Don't use shell
        ).stdout.strip()

        print("merge_base:", merge_base)

        shas["revision"][project.name] = project.revision
        shas["merge-base"][project.name] = merge_base
        shas["revision-short"][project.name] = project.revision[:11]
        shas["merge-base-short"][project.name] = merge_base[:11]

        if project.name == "zephyr":
            find_migration_guides(merge_base, topdir / project.path)

    def commit_role(name, rawtext, text, lineno, inliner, options={}, content=[]):
        if text in shas[name]:
            node = nodes.Text(shas[name][text])
        else:
            logger.error(f"{lineno}: Could not find SHA for {rawtext}")
            node = nodes.Text("")

        return [node], []

    return commit_role


def setup(app: Sphinx):
    app.add_config_value("fetch_upstream_repos", None, "env")
    role_func = commit_replace(app)
    app.add_role("merge-base", role_func)
    app.add_role("revision", role_func)
    app.add_role("merge-base-short", role_func)
    app.add_role("revision-short", role_func)
    # app.connect("builder-inited", assemble_migration_guide)

    return {
        "version": __version__,
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
