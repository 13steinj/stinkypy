import re

from collections import defaultdict, OrderedDict

from difftools import chunkify_diff, ChangeType


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
    def __init__(self, title, severity, matches):
        self.title = title
        self.severity = severity
        # Sort the matches by line number
        self.matches = OrderedDict(sorted(matches.items(), key=lambda x: x[0]))


class SmellSeverity(object):
    # This is a perfectly ok thing to do, but might need extra attention
    INFO = "Info"
    # This is normally the wrong thing to do, but there might be valid cases
    WARN = "Warning"
    # This is almost certainly incorrect and could lead to vulnerabilities
    ERROR = "Error"


class AbstractCodeSniffer(object):
    def __init__(self, title, severity=None, path_re=None, change_types=None):
        if change_types is None:
            change_types = {ChangeType.ADD}
        if severity is None:
            severity = SmellSeverity.INFO
        self.title = title
        self._severity = severity
        self._path_re = path_re
        self._change_types = change_types

    def sniff(self, d_file, chunks):
        if self._path_re:
            if not re.match(self._path_re, d_file.path, re.IGNORECASE):
                return
        # (start line, end line) -> result dict
        # indexed that way so we can ignore hits on the same line
        # by multiple regexes checking for the same issue.
        matches = {}
        for chunk in chunks:
            # We look at local context chunks to find possibly deleted lines,
            # added lines will be in remote context chunks.
            change_type = ChangeType.DELETE if chunk.local else ChangeType.ADD
            if change_type not in self._change_types:
                continue
            context_matches = self._sniffImpl(d_file, chunk)

            # Now figure out which issues actually occur on changed lines
            for line_range, match in context_matches.iteritems():
                smell_in_diff = d_file.range_is_modified(
                    line_range.start, line_range.end, line_range.local_linenos
                )
                if smell_in_diff:
                    matches[line_range] = match

        if not matches:
            return None
        return Smell(self.title, self._severity, matches)

    def _sniffImpl(self, d_file, chunk):
        raise NotImplementedError()


class RegExpCodeSniffer(AbstractCodeSniffer):
    def __init__(self, title, code_res, severity=None, path_re=None,
                 change_types=None):
        super(RegExpCodeSniffer, self).__init__(
            title,
            severity=severity,
            path_re=path_re,
            change_types=change_types
        )
        self._code_res = code_res

    def _sniffImpl(self, d_file, chunk):
        matches = {}
        for code_re in self._code_res:
            for match in re.finditer(code_re, chunk.contents):
                coords = chunk.lineRangeForMatch(match)
                matches[coords] = match
        return matches


class FilteredRegExpSniffer(RegExpCodeSniffer):
    """A RegExpCodeSniffer with a user-defined post-filter on the matches"""

    def _sniffImpl(self, d_file, chunk):
        matches = super(FilteredRegExpSniffer, self)._sniffImpl(d_file, chunk)
        if not matches:
            return {}

        new_matches = {}
        for line_range, match in matches.iteritems():
            if self._verifyStinks(d_file, line_range, match):
                new_matches[line_range] = match

        return new_matches

    def _verifyStinks(self, d_file, line_range, match):
        """Verify something found by our initial regexes actually stinks"""
        raise NotImplementedError()


class InlineScriptRegExpSniffer(RegExpCodeSniffer):
    """Sniffer that matches on patterns inside inline scripts"""

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
                coords = chunk.lineRangeForMatch(match, offset=lineno_offset)
                matches[coords] = match
        return matches


class JSRegExpSniffer(RegExpCodeSniffer):
    """Sniffs both inline and separate scripts for specific patterns"""

    def __init__(self, title, code_res, template_path_re, severity=None,
                 path_re=None, change_types=None):
        super(JSRegExpSniffer, self).__init__(
            title,
            code_res,
            severity=severity,
            path_re=path_re,
            change_types=change_types
        )
        self._sniffers = (
            InlineScriptRegExpSniffer(
                title,
                code_res,
                severity=severity,
                path_re=template_path_re,
                change_types=change_types,
            ),
            RegExpCodeSniffer(
                title,
                code_res,
                severity=severity,
                path_re=r".*\.jsx?",
                change_types=change_types,
            ),
        )

    def _sniffImpl(self, d_file, chunk):
        matches = {}
        for sniffer in self._sniffers:
            result = sniffer.sniff(d_file, (chunk,))
            matches.update(result.matches if result else {})
        return matches

