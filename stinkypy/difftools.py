from cStringIO import StringIO

from .unidiff import parser
from .unidiff.patch import LINE_TYPE_CONTEXT, LINE_TYPE_DELETE


class DiffChunk(object):
    def __init__(self, op_type, start, contents):
        # For deletions `start` is a local line number; for additions,
        # a remote line number.
        self.start = start
        self.contents = contents
        self.op_type = op_type

    def __repr__(self):
        summary = self.contents.split('\n')[0] + "..."
        return "DiffChunk%s" % repr((self.op_type, self.start, summary))

    def lineRangeForMatch(self, match, offset=0):
        """Map a regex match to start and end line nos within the file"""
        text = match.string
        offset += self.start
        abs_lineno = lambda x: offset + text.count("\n", 0, x)
        abs_linenos = tuple(map(abs_lineno, (match.start(), match.end())))
        local_linenos = self.op_type == LINE_TYPE_DELETE
        return DiffLineRange(local_linenos, *abs_linenos)


class DiffLineRange(object):
    def __init__(self, local, start, end):
        self.local_linenos = local
        self.start = start
        self.end = end

    def __cmp__(self, other):
        return cmp((self.start, self.end), (other.start, other.end))

    def __str__(self):
        return self.toString()

    def toString(self, start_only=False):
        start_only = start_only or self.start == self.end
        lines = (self.start,) if start_only else (self.start, self.end)
        prfx = "L" if self.local_linenos else "R"
        return "-".join(map(lambda x: prfx + str(x), lines))


def merge_chunks(start, types, lines):
    # Chunk together neighbouring operations of the same type so we can
    # do multi-line matches for things like:
    # ```
    # + html_sink(
    # +     get_untrusted("ack!")
    # + )
    # ```
    chunks = []
    chunk_start = start
    chunk_buf = ""
    last_type = None

    for i, line_type in enumerate(types):
        # Start of new chunk or last line
        if line_type != last_type:
            if chunk_buf:
                chunks.append(DiffChunk(last_type, chunk_start, chunk_buf))
            chunk_buf = ""
            chunk_start = start + i

        chunk_buf += lines[i]
        last_type = line_type
    if chunk_buf:
        chunks.append(DiffChunk(last_type, chunk_start, chunk_buf))
    return chunks


def chunkify_diff(contents):
    parsed_diff = parser.parse_unidiff(StringIO(contents))

    for d_file in parsed_diff:
        chunks = []
        for hunk in d_file:
            # Create addition and deletion chunks
            chunks += merge_chunks(
                hunk.target_start,
                hunk.target_types,
                hunk.target_lines
            )
            chunks += merge_chunks(
                hunk.source_start,
                hunk.source_types,
                hunk.source_lines
            )

        # Context lines are ignored for simplicity and can't be matched on,
        # consider yourself warned.
        useful_chunks = filter(lambda x: x.op_type != LINE_TYPE_CONTEXT, chunks)
        yield d_file, useful_chunks


def get_full_match_lines(match):
    text = match.string
    leading_nl = text.rfind("\n", 0, match.start())
    trailing_nl = text.find("\n", match.end())
    start = leading_nl + 1 if leading_nl != -1 else 0
    match_len = match.end() - match.start()
    end = trailing_nl if trailing_nl != -1 else len(text)
    return text[start:end]
