import hashlib
import requests
import stinkypy


def gen_diff_anchor(path, linerange):
    # GitHub only supports highlighting a single line in diff views
    str_lineno = linerange.toString(start_only=True)
    # Undocumented, that hash in the anchor is `md5(filename)`
    path_hash = hashlib.md5(path).hexdigest()
    return "diff-%s%s" % (path_hash, str_lineno)


def get_gh_session(access_token):
    sess = requests.session()
    sess.auth = (access_token, 'x-oauth-basic')
    version = stinkypy.__version__
    sess.headers['User-Agent'] = 'stinkypy diff sniffer/%s' % version
    return sess


class PullRequestEvent(dict):
    """Simple wrapper around the JSON returned by the PR webhook"""

    def getLineLink(self, file_path, line_range):
        base_url = self["pull_request"]["url"]
        return base_url + "#" + gen_diff_anchor(file_path, line_range)

    def getDiff(self, session):
        headers = {"Accept": "application/vnd.github.3.diff"}
        return session.get(self["pull_request"]["url"], headers=headers).text
