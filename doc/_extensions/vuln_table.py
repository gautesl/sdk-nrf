"""
Copyright (c) 2022 Nordic Semiconductor ASA

SPDX-License-Identifier: Apache-2.0

This extension will produce generated content on known vulnerabilities.
Information on the vulnerabilities is downloaded from a cache in Azure,
and stored in the build environment.
"""

from typing import List, Union
from docutils import nodes
from sphinx.util.docutils import SphinxDirective
from sphinx.application import Sphinx
from azure.storage.blob import ContainerClient
from sphinx.util import logging
import requests
import json
import re

from page_filter import FilterDropdown, read_versions

__version__ = "0.1.0"

AZ_CONN_STR_PUBLIC = ";".join(
    (
        "DefaultEndpointsProtocol=https",
        "EndpointSuffix=core.windows.net",
        "AccountName=ncsdocsa",
    )
)
"""Azure connection string (public acces)."""

AZ_CONTAINER = "ncs-doc-generated-reports"
"""Azure container."""

REPORT_PREFIX = "vuln_reports"
"""Prefix of all vulnerability reports in the Azure container."""

CVE_DATABASE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
"""Incomplete CVE database URL, missing CVE ID"""

logger = logging.getLogger(__name__)


def find_affected_versions(
    firstv: str, fixv: str, versions: List[str], backport_versions: List[str]
) -> List[str]:
    """List versions from first affected (inclusive) to fixed (exclusive).

    versions in ``backport_versions`` are exceptions to the range.

    Args:
        firstv: First affected version.
        Fixv: Fix version.
        versions: List of all versions to date.
        backport_versions: List of exceptions to the affected versions range.

    Returns:
        A list of affected versions.
    """

    vformat = lambda version: f"v{version.replace('.', '-')}"
    firstv = vformat(firstv)
    fixv = vformat(fixv)
    backport_versions = list(map(vformat, backport_versions))

    if firstv not in versions:
        return []

    affected = [firstv]
    for i in range(versions.index(firstv) + 1, len(versions)):
        if versions[i] == fixv:
            break
        elif versions[i] in backport_versions:
            continue
        affected.append(versions[i])

    return affected


def component_str(name: str) -> str:
    """Transform a component name into a html component identifier.

    Args:
        name: The component name.

    Returns:
        A component identifier usable as a html class.
    """
    return name.replace(" ", "_").replace(".", "-").lower() + "_component"


class VulnTable(SphinxDirective):
    """This class creates a new directive ``vuln-table``.

    The table displays summary information on vulnerabilities retrieved from
    a cache in Azure.

    This class uses funcionality from the ``PageFilter`` class.
    """

    @staticmethod
    def create_cve_links(cve_ids: str) -> List[nodes.Element]:
        """Transform CVE IDs to links to the CVE database.

        Args:
            cve_ids: Comma separated string of CVE IDs.

        Returns:
            A list of links.
        """

        ids = cve_ids.replace(",", " ").split()

        refs = []
        for id in ids:
            para = nodes.paragraph()
            refuri = CVE_DATABASE_URL + id
            para += nodes.reference(text=id, refuri=refuri)
            refs.append(para)
        return refs

    def create_reference(self, vuln: dict) -> nodes.Element:
        """Create a reference and a corresponding target node.

        A unique "advisory id" is created to be associated with the
        vulnerability, and a link is created to its details section.

        Args:
            vuln: Data on the vulnerability.

        Returns:
            A reference object to the target section, containing the advisory
            ID as text.
        """

        advisory_id = str(self.env.new_serialno("vuln") + 1).zfill(5)
        vuln["Advisory ID"] = advisory_id

        refuri = self.env.app.builder.get_relative_uri("", self.env.docname)
        refuri += "#" + nodes.make_id(vuln["Summary"])
        ref = nodes.reference(text=advisory_id, internal=True)
        ref["refdocname"] = self.env.docname
        ref["refuri"] = refuri
        return ref

    def run(self) -> List[nodes.Element]:
        """Create a filterable table displaying information on vulnerabilities.

        Returns:
            A component filter and the table.
        """

        if not hasattr(self.env, "vuln_cache"):
            return [nodes.paragraph(text="No vulnerabilities found")]

        cache = self.env.vuln_cache
        keys = cache["schema"]
        table = nodes.table()
        tgroup = nodes.tgroup(cols=len(keys))
        for key in keys:
            if key in ["First affected version", "Fixed version", "CVSS"]:
                colspec = nodes.colspec(colwidth=0.3)
            elif key in ["CVE ID"]:
                colspec = nodes.colspec(colwidth=1.5)
            else:
                colspec = nodes.colspec(colwidth=1)
            tgroup.append(colspec)
        table += tgroup

        # table head row
        thead = nodes.thead()
        tgroup += thead
        row = nodes.row()

        for key in keys:
            entry = nodes.entry()
            entry += nodes.paragraph(text=key)
            row += entry
        thead.append(row)

        # table body
        rows = []
        for vuln in cache["body"]:
            row = nodes.row()
            version_classes = find_affected_versions(
                vuln["First affected version"],
                vuln["Fixed version"],
                self.env.nrf_versions,
                vuln["Backport versions"],
            )
            vuln["affected_version_classes"] = version_classes
            row["classes"].extend(version_classes)
            component_class_names = [component_str(name) for name in vuln["Components"]]
            row["classes"].extend(component_class_names)
            row["classes"].append("hideable")
            rows.append(row)

            for key in keys:
                entry = nodes.entry()
                para = nodes.paragraph()
                # Advisory ID links to the corresponding detailed section
                if key == "Advisory ID":
                    para += self.create_reference(vuln)
                # CVE column links to database
                elif key == "CVE ID":
                    para += self.create_cve_links(vuln[key])
                elif isinstance(vuln[key], list):
                    para += nodes.Text(", ".join(vuln[key]))
                else:
                    para += nodes.Text(vuln[key])
                entry += para
                row += entry

        tbody = nodes.tbody()
        tbody.extend(rows)
        tgroup += tbody

        # Include a component filter
        all_components = {comp for vuln in cache["body"] for comp in vuln["Components"]}
        create_tuple = lambda c: (component_str(c), c)
        content = list(map(create_tuple, all_components))
        component_select_node = FilterDropdown("components", content)

        return [component_select_node, table]


class VulnDetails(SphinxDirective):
    """This class creates a new directive ``vuln-details``.

    Bulletlist sections detailing the available vulnerabilities are inserted
    into the page, and are filterable on components and affected version
    number.
    """

    @staticmethod
    def create_description(text: str) -> nodes.Element:
        """Look for and transform links in the description.

        Links are on the following format:

            [displayed text|https://link.to.site|]

        The | on the end is optional. If no links are found,
        ``create_list_item`` is used instead.

        Args:
            text: CVE dexcription.

        Returns:
            A list item containing ``text`` with any links transformed.
        """

        url_reg = r"(https?://[^\s/$.?#].[^\s]*?)"
        link_reg = r"(\[([^|]+?)\|" + url_reg + r"(?:\|)?\])"
        locate_link_reg = r"^(.*?)" + link_reg + r"(.*)$"
        """
        RE groups:
            1. Text before link start
            2. Entire link               [displayed text|https://link.to.site|]
            3. Displayed text of link    displayed text
            4. URL of link               https://link.to.site
            5. Text after link end
        """

        if not re.search(link_reg, text):
            return VulnDetails.create_list_item("Description", text)

        para = nodes.paragraph()
        para += nodes.strong(text="Description: ")

        match = re.search(locate_link_reg, text)
        while match:
            para += nodes.Text(match.group(1))
            para += nodes.reference(
                text=match.group(3), refuri=match.group(4), internal=False
            )
            text = match.group(5)
            match = re.search(locate_link_reg, text)

        para += nodes.Text(text)
        return nodes.list_item("", para)

    @staticmethod
    def create_list_item(title: str, value: Union[str, List[str]]) -> nodes.Element:
        """Return a list item on the format <strong>title: </strong>value.

        If the value is a list, it is transformed to a comma separated string.

        Args:
            title: Title of the list item, put in bold.
            value: The list item text.
        """

        para = nodes.paragraph()
        para += nodes.strong(text=title + ": ")
        if isinstance(value, list):
            value = ", ".join(value)
        para += nodes.Text(value)
        return nodes.list_item("", para)

    @staticmethod
    def create_bullet_list(vuln: dict) -> nodes.Element:
        """Return a bullet list of all known information about a vulnerability.

        Args:
            vuln: Data and metadata on the vulnerability.

        Returns:
            A bullet list object with containing all information except the
            metadata.
        """

        bulletlist = nodes.bullet_list()
        for description, value in vuln.items():
            if description in ["Summary", "affected_version_classes"]:
                continue
            elif not value:
                continue
            elif description == "CVE description":
                bulletlist += VulnDetails.create_description(value)
            else:
                bulletlist += VulnDetails.create_list_item(description, value)

        return bulletlist

    def run(self) -> List[nodes.Element]:
        """Insert vulnerability details sections into the page.

        Information on the vulnerabilities must be present in
        ``self.env.vuln_cache`` to work.

        The inserted sections will have affected versions and components as
        class names so that they can be filtered.

        Returns:
            An empty list. This extension only alters the existing page.
        """

        if not hasattr(self.env, "vuln_cache"):
            return []

        vulnerabilities = self.env.vuln_cache["body"]
        for vuln in vulnerabilities:
            bulletlist = self.create_bullet_list(vuln)

            self.state.section(
                title=vuln["Summary"],
                source="",
                style="",
                lineno=self.lineno,
                messages=[bulletlist],
            )

            self.state.parent[-1]["classes"].extend(vuln["affected_version_classes"])
            component_class_names = [component_str(name) for name in vuln["Components"]]
            self.state.parent[-1]["classes"].extend(component_class_names)

        return []


def download_vuln_table(app: Sphinx) -> None:
    """Download vulnerability table from Azure.

    The vulnerabilities are stored in ``app.env.vuln_cache``.

    Args:
        app: The Sphinx app to store the vulnerabilities in.
    """

    # Check if local cache exists
    if hasattr(app.env, "vuln_cache"):
        local_cache = app.env.vuln_cache
    else:
        logger.info("No vulnerability cache found locally")
        local_cache = None

    # Check internet connection
    try:
        requests.get("https://ncsdocsa.blob.core.windows.net", timeout=3)
    except (requests.ConnectionError, requests.Timeout):
        logger.info("Could not retrieve vulnerability information online")
        if local_cache:
            logger.info("Using local vulnerability cache")
            app.env.vuln_cache = local_cache
        return

    cc = ContainerClient.from_connection_string(AZ_CONN_STR_PUBLIC, AZ_CONTAINER)
    remote_files = sorted(
        [b for b in cc.list_blobs(name_starts_with=REPORT_PREFIX)],
        key=lambda b: b.last_modified,
        reverse=True,
    )

    target = remote_files[0]
    if local_cache and local_cache["md5"] == target.content_settings["content_md5"]:
        logger.info("Up to date vulnerability table found in cache")
        return

    bc = cc.get_blob_client(target)
    res = bc.download_blob().content_as_text()
    app.env.vuln_cache = json.loads(res)
    app.env.vuln_cache["md5"] = target.content_settings["content_md5"]
    logger.info("Vulnerability table cached locally")


def setup(app: Sphinx) -> dict:
    """Setup the ``vuln-table`` and ``vuln-details`` extensions.

    Necessary information are retrieved at the "builder-inited" stage.

    Args:
        app: The Sphinx app.
    """

    app.add_directive("vuln-table", VulnTable)
    app.add_directive("vuln-details", VulnDetails)

    app.connect("builder-inited", download_vuln_table)
    app.connect("builder-inited", read_versions)

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
