from cStringIO import StringIO

from .unidiff import parser


class ChangeType(object):
    DELETE = "Delete"
    ADD = "Add"


class ContextChunk(object):
    """Complete chunk of code for matching on"""

    def __init__(self, local, start, contents, whole_file=False):
        self.start = start
        self.contents = contents
        self.local = local
        # In the future might be used to allow AST-based checks when True
        self.whole_file = whole_file

    def __repr__(self):
        summary = self.contents.split('\n')[0] + "..."
        return "DiffChunk%s" % repr((self.local, self.start, summary))

    @classmethod
    def fromDiffHunk(cls, hunk):
        """Get ContextChunks for both the local and remote sides of a hunk"""
        local_joined = "".join(hunk.source_lines)
        remote_joined = "".join(hunk.target_lines)
        return (
            ContextChunk(True, hunk.source_start, local_joined),
            ContextChunk(False, hunk.target_start, remote_joined)
        )

    def lineRangeForMatch(self, match, offset=0):
        """Map a regex match to start and end line nos within the file"""
        text = match.string
        offset += self.start
        abs_lineno = lambda x: offset + text.count("\n", 0, x)
        abs_linenos = tuple(map(abs_lineno, (match.start(), match.end())))
        return DiffLineRange(self.local, *abs_linenos)


class DiffLineRange(object):
    def __init__(self, local, start, end):
        # NB: not factored into comparisons
        self.local_linenos = local
        self.start = start
        self.end = end

    def __cmp__(self, other):
        return cmp((self.start, self.end), (other.start, other.end))

    def __str__(self):
        return self.toString()

    def __iter__(self):
        return xrange(self.start, self.end + 1)

    def intersects(self, other):
        return max(self.start, other.start) >= min(self.end, other.end)

    def toString(self, start_only=False):
        start_only = start_only or self.start == self.end
        lines = (self.start,) if start_only else (self.start, self.end)
        prfx = "L" if self.local_linenos else "R"
        return "-".join(map(lambda x: prfx + str(x), lines))


def chunkify_diff(contents):
    parsed_diff = parser.parse_unidiff(StringIO(contents))

    for d_file in parsed_diff:
        chunks = []
        for hunk in d_file:
            # Create addition and deletion chunks
            chunks += ContextChunk.fromDiffHunk(hunk)

        yield d_file, chunks


def get_full_match_lines(match):
    text = match.string
    leading_nl = text.rfind("\n", 0, match.start())
    trailing_nl = text.find("\n", match.end())
    start = leading_nl + 1 if leading_nl != -1 else 0
    match_len = match.end() - match.start()
    end = trailing_nl if trailing_nl != -1 else len(text)
    return text[start:end]
