from django.conf import settings  # noqa
from celeryconf import app  # noqa
from django.core.files.base import ContentFile

import requests
import subprocess
import logging
import os
import networkx as nx
import json
import hashlib


class DeadCodeAnalysis():
    def __init__(self, prefix, source, target, progress_callback):
        self.logger = logging.getLogger("analysis")
        self.progress_callback = progress_callback

        self.prefix = prefix
        self.source = os.path.join(prefix, source)
        self.target = os.path.join(prefix, target)

        # Used by Analysis
        self.target_defs = {}
        self.target_uses = {}
        self.flows_to_target = set()
        self.flows_in_target = set()
        self.macro_table = {}

        # Results
        self.isolates = []
        self.clusters = []
        self.nodes = None
        self.edges = None

        klass = self

        class ProgressFilter(logging.Filter):
            def filter(self, record):
                if record.levelno >= logging.INFO:
                    klass.progress_callback(record.msg)
                return True
        self.filter = ProgressFilter()

        if self.progress_callback:
            self.logger.addFilter(self.filter)

    def result(self):
        self.logger.removeFilter(self.filter)

        prefix = self.prefix
        if prefix[-1] != os.sep:
            prefix += os.sep

        nodes = [x.replace(prefix, "", 1) for x in self.nodes]
        isolates = [x.replace(prefix, "", 1) for x in self.isolates]
        clusters = [[x.replace(prefix, "", 1) for x in y] for y in self.clusters]

        edges = []
        for edge in self.edges:
            edge = list(edge)
            edge[0] = edge[0].replace(prefix, "", 1)
            edge[1] = edge[1].replace(prefix, "", 1)
            edges.append(edge)

        ret = {
            'type': 0,
            'graph': {
                'nodes': nodes,
                'edges': edges,
            },
            'isolates': isolates,
            'clusters': clusters,
        }

        return ret

    def run(self):
        self.logger.info("Scanning target...")

        for (path, dirs, files) in os.walk(self.target):
            for file in files:
                fp_file = os.path.join(path, file)
                (defs, uses, macros) = self.get_defs_uses(fp_file)

                if defs is not None:
                    self.target_defs[fp_file] = defs

                if uses is not None:
                    self.target_uses[fp_file] = uses

                if macros:
                    self.macro_table.update(macros)

        if self.macro_table:
            self.logger.info("Found %s macro uses that are function defs, rewriting their uses..."
                             % len(self.macro_table))

            for file in self.target_uses:
                if not self.target_uses[file]:
                    continue
                for macro in self.macro_table:
                    if macro in self.target_uses[file]:
                        self.target_uses[file][self.macro_table[macro]] = 1
                        del self.target_uses[file][macro]

        self.logger.info("Searching source for flows to target...")

        for (path, dirs, files) in os.walk(self.source):
            if (os.path.abspath(path).startswith(os.path.abspath(self.target))):
                continue
            for file in files:
                fp_file = os.path.join(path, file)
                ret = self.find_uses(fp_file)
                if ret:
                    self.flows_to_target.update(ret)

        self.logger.info("Computing target-internal flows...")

        for tdfile in self.target_defs:
            filedefs = self.target_defs[tdfile]

            for tufile in self.target_uses:
                fileuses = self.target_uses[tufile]

                for tdef in filedefs:
                    if tdef in fileuses:
                        # if tufile in self.trace_targets and tdfile in self.trace_targets:
                        #     self.logger.debug("%s -> %s (%s)" % (tufile, tdfile, tdef))
                        self.flows_in_target.add((tufile, tdfile))

        self.logger.info("Building graph...")

        g = nx.DiGraph()

        # Add all target files that define something as nodes
        for tdfile in self.target_defs:
            g.add_node(tdfile)

        # Add all flows within the target (certain nodes might remain isolated)
        g.add_edges_from(self.flows_in_target)

        # Add all flows to the target
        for flow in self.flows_to_target:
            g.add_edges_from([(flow[0], flow[1], {"inflow": True})])

        self.logger.info("Computing isolated subgraphs...")

        gdead = g.copy()

        self.logger.debug("Initial graph size: %s Nodes" % len(gdead.nodes()))

        # For every flow to the target, compute the BFS tree that is
        # reachable from that point and remove it from the graph.
        for flow in self.flows_to_target:
            if gdead.has_node(flow[0]):
                live = nx.bfs_tree(gdead, flow[0]).nodes()
                if live:
                    gdead.remove_nodes_from(live)
                    self.logger.debug("Node size: %s" % len(gdead.nodes()))

        # Remove any self-loops, so they don't show up as clusters
        gdead.remove_edges_from(list(gdead.selfloop_edges()))

        # Determine isolated nodes, we can just list them instead of visualizing
        self.isolates = list(nx.isolates(gdead))
        gdead.remove_nodes_from(self.isolates)

        self.nodes = list(gdead.nodes)
        self.edges = list(gdead.edges)

        total = len(self.nodes) + len(self.isolates)

        self.clusters = sorted(nx.weakly_connected_component_subgraphs(gdead), key=len, reverse=True)

        self.logger.info("Analysis complete: %s nodes, %s of them in isolated subgraphs." % (total, len(self.nodes)))

    def get_defs_uses(self, file):
        defs = {}
        uses = {}
        macro_table = {}

        # TODO: This should live somewhere else
        blacklist = [
            'intl/icu/source/common/unicode/urename.h',  # defines a rename macro for all API functions
            'intl/icu/source/common/unicode/localpointer.h',  # defines smart pointer class macro
        ]

        for bfile in blacklist:
            if file.endswith(bfile):
                return (None, None, None)

        with open(file, 'r') as fd:
            line = fd.readline()
            previous_data = None

            while line:
                try:
                    data = json.loads(line)
                    if "syntax" in data and "sym" in data and ("function" in data["syntax"] or "constructor" in data["syntax"] or "enum" in data["syntax"] or "macro" in data["syntax"] or "variable" in data["syntax"]):
                        syms = data["sym"].split(",")
                        if "def" in data["syntax"]:
                            for sym in syms:
                                defs[sym] = 1
                        elif "use" in data["syntax"]:
                            if "macro" in data["syntax"] and previous_data and data["loc"] == previous_data["loc"] and ("function" in previous_data["syntax"] or "variable" in previous_data["syntax"]):
                                if "def" in previous_data["syntax"]:
                                    # TODO: This doesn't support comma-separated syms
                                    macro_table[data["sym"]] = previous_data["sym"]
                                elif "decl" in previous_data["syntax"]:
                                    # Ignore this, it is a declaration with the macro rewriting
                                    pass
                                else:
                                    for sym in syms:
                                        uses[sym] = 1
                            else:
                                for sym in syms:
                                    uses[sym] = 1
                        elif "decl" in data["syntax"]:
                            pass
                        else:
                            self.logger.error("Unknown syntax: %s %s" % (file, data["syntax"]))
                            return (None, None, None)
                        previous_data = data
                except ValueError:
                    return (None, None, None)

                line = fd.readline()
        return (defs, uses, macro_table)

    def find_uses(self, file):
        (_, uses, _) = self.get_defs_uses(file)

        if not uses:
            return

        relations = set()

        for tfile in self.target_defs:
            filedefs = self.target_defs[tfile]

            for use in uses:
                if use in self.macro_table:
                    if self.macro_table[use] in filedefs:
                        relations.add((file, tfile))
                elif use in filedefs:
                    relations.add((file, tfile))

        return relations


@app.task
def perform_analysis(pk):
    from reachable.models import MozsearchIndexFile, QueryResult, QUERY_TYPE  # noqa

    result = QueryResult.objects.get(pk=pk)

    query = result.query
    indexfiles = result.indexfiles

    # TODO: Support multipe index files in analysis
    indexfile = indexfiles.all()[0]
    path_prefix = os.path.join(getattr(settings, 'DATA_STORAGE', None), os.path.splitext(indexfile.file.name)[0])

    target_path = query.target_path
    source_path = query.source_path

    def update_progress(msg):
        result = QueryResult.objects.get(pk=pk)
        if result.progress:
            result.progress += "\n%s" % msg
        else:
            result.progress = msg
        result.save()

    if query.type == QUERY_TYPE["dead-code"]:
        analysis = DeadCodeAnalysis(path_prefix, source_path, target_path, update_progress)
        analysis.run()
        analysis_result = analysis.result()
    else:
        raise RuntimeError("NYI")

    # Load the object again in case it has been changed by the analysis
    result = QueryResult.objects.get(pk=pk)

    # Save the result blob to disk
    content = json.dumps(analysis_result, separators=(',', ':'))
    h = hashlib.new('sha1')
    h.update(content.encode('utf-8'))
    result.file.save("%s.json" % h.hexdigest(), ContentFile(content))
    result.save()


@app.task
def fetch_and_unpack_latest_data():
    from reachable.models import MozsearchIndexFile  # noqa

    baseUrl = "https://index.taskcluster.net/v1/task/gecko.v2.mozilla-central.latest.firefox.%s64-searchfox-debug"
    artifactBaseUrl = "https://taskcluster-artifacts.net/%s/0/%s"

    for index_os in ['linux', 'win', 'macosx']:
        indexUrl = baseUrl % index_os
        indexRequest = requests.get(indexUrl)
        if not indexRequest.ok:
            # TODO: Logging, return
            pass

        indexEntry = indexRequest.json()
        taskId = indexEntry["taskId"]

        targetJsonUrl = artifactBaseUrl % (taskId, "public/build/target.json")
        targetJsonRequest = requests.get(targetJsonUrl)
        if not targetJsonRequest.ok:
            # TODO: Logging, return
            pass

        targetJson = targetJsonRequest.json()

        rev = targetJson["moz_source_stamp"]

        targetZipUrl = artifactBaseUrl % (taskId, "public/build/target.mozsearch-index.zip")
        targetZipBasename = "%s_%s" % (rev, index_os)

        storage_path = os.path.join(getattr(settings, 'DATA_STORAGE', None), "data", targetZipBasename)

        os.makedirs(storage_path)

        targetZipRequest = requests.get(targetZipUrl, stream=True)
        with open(storage_path + ".zip", 'wb') as f:
            for chunk in targetZipRequest.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)

        dbobj = MozsearchIndexFile()
        dbobj.revision = rev
        dbobj.os = index_os
        dbobj.file.name = storage_path + ".zip"
        dbobj.save()

        # TODO: This uses unzip, we might want to use Python instead. However, the archive
        # is a highly-compressed 300 MB file, that needs to be decompressed efficiently.
        subprocess.check_call(["unzip", storage_path + ".zip"], cwd=storage_path)

    return
