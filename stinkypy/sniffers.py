import re

from collections import defaultdict, OrderedDict

from difftools import chunkify_diff
from .unidiff.patch import LINE_TYPE_ADD


def sniff_diff(diff, sniffers):
    smells = defaultdict(list)
    for d_file, chunks in chunkify_diff(diff):
        for sniffer in sniffers:
            result = sniffer.sniff(d_file, chunks)
            if result:
                smells[d_file.path].append(result)
    # Sort the smells by the file paths that contain them
    return OrderedDict(sorted(smells.items(), key=lambda x: x[0]))


class Smell(object):
    def __init__(self, title, matches):
        self.title = title
        # Sort the matches by line number
        self.matches = OrderedDict(sorted(matches.items(), key=lambda x: x[0]))


class AbstractCodeSniffer(object):
    def __init__(self, title, path_re=None, op_types={LINE_TYPE_ADD}):
        self.title = title
        self._path_re = path_re
        self._op_types = op_types

    def sniff(self, d_file, chunks):
        if self._path_re:
            if not re.match(self._path_re, d_file.path, re.IGNORECASE):
                return
        # (start line, end line) -> result dict
        # indexed that way so we can ignore hits on the same line
        # by multiple regexes checking for the same issue.
        matches = {}
        for chunk in chunks:
            # TODO: When sniffing additions we can just sniff the remote file
            # and look for smells that intersect with chunks in the diff. That
            # way we have the whole file available as context, and aren't
            # limited to lines in the diff's context.
            if chunk.op_type not in self._op_types:
                continue
            matches.update(self._sniffImpl(d_file, chunk))

        if not matches:
            return None
        return Smell(self.title, matches)

    def _sniffImpl(self, d_file, chunk):
        raise NotImplementedError()


class RegExpCodeSniffer(AbstractCodeSniffer):
    def __init__(self, title, code_res, path_re=None, op_types={LINE_TYPE_ADD}):
        super(RegExpCodeSniffer, self).__init__(title, path_re, op_types)
        self._code_res = code_res

    def _sniffImpl(self, d_file, chunk):
        matches = {}
        for code_re in self._code_res:
            for match in re.finditer(code_re, chunk.contents):
                coords = chunk.linenos_for_match(match)
                matches[coords] = match
        return matches


class InlineScriptRegExpSniffer(RegExpCodeSniffer):
    """
    Sniffer that matches on patterns inside inline scripts

    Keep in mind that currently this can't make use of context lines in
    diffs, so this will only match on <script> tags in the commit in which
    they're added.
    """
    EVENT_HANDLER_RE = re.compile(r"\son[a-z_\-]+=(['\"])([^\1]*?)\1",
                                  re.IGNORECASE)
    SCRIPT_TAG_RE = re.compile(r"<script(\s.*?)?>(.*?)</\s*script>",
                               re.MULTILINE | re.DOTALL | re.IGNORECASE)

    def _sniffImpl(self, d_file, chunk):
        matches = {}
        for match in re.finditer(self.EVENT_HANDLER_RE, chunk.contents):
            matches.update(
                self._sniffInsideScript(d_file, chunk, match, match.group(2))
            )
        # TODO: flag to ignore inline templates inside script tags?
        for match in re.finditer(self.SCRIPT_TAG_RE, chunk.contents):
            matches.update(
                self._sniffInsideScript(d_file, chunk, match, match.group(2))
            )
        return matches

    def _sniffInsideScript(self, d_file, chunk, script_match, script_text):
        matches = {}
        # To get the correct line numbers of the match, line numbers must be
        # offset by the number of lines between the script tag and the start
        # of the chunk.
        lineno_offset = script_match.string.count("\n", 0, script_match.start())
        for code_re in self._code_res:
            for match in re.finditer(code_re, script_text):
                coords = chunk.linenos_for_match(match, offset=lineno_offset)
                matches[coords] = match
        return matches


class JSRegExpSniffer(RegExpCodeSniffer):
    """Sniffs both inline and separate scripts for specific patterns"""

    def __init__(self, title, code_res, template_path_re, path_re=None,
                 op_types={LINE_TYPE_ADD}):
        super(JSRegExpSniffer, self).__init__(
            title,
            path_re,
            path_re=path_re,
            op_types=op_types
        )
        self._sniffers = (
            InlineScriptRegExpSniffer(
                title, code_res, path_re=template_path_re
            ),
            RegExpCodeSniffer(
                title, code_res, path_re=r".*\.jsx?"
            ),
        )

    def _sniffImpl(self, d_file, chunk):
        matches = {}
        for sniffer in self._sniffers:
            result = sniffer.sniff(d_file, (chunk,))
            matches.update(result.matches if result else {})
        return matches

