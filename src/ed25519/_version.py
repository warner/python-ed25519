
# This file helps to compute a version number in source trees obtained from
# git-archive tarball (such as those provided by githubs download-from-tag
# feature). Distribution tarballs (build by setup.py sdist) and build
# directories (produced by setup.py build) will contain a much shorter file
# that just contains the computed version number.

# this string will be replaced by git during git-archive
verstr = "$Format:%d$"


import subprocess

def run_command(args, verbose=False):
    try:
        p = subprocess.Popen(list(args), stdout=subprocess.PIPE)
    except EnvironmentError, e:
        if verbose:
            print "unable to run %s" % args[0]
            print e
        return None
    stdout = p.communicate()[0].strip()
    if p.returncode != 0:
        if verbose:
            print "unable to run %s (error)" % args[0]
        return None
    return stdout

import os.path

def version_from_vcs(tag_prefix, verbose=False):
    if not os.path.isdir(".git"):
        if verbose:
            print "This does not appear to be a Git repository."
        return None
    stdout = run_command(["git", "describe",
                          "--tags", "--dirty", "--always"])
    if stdout is None:
        return None
    if not stdout.startswith(tag_prefix):
        if verbose:
            print "tag '%s' doesn't start with prefix '%s'" %                   (stdout, tag_prefix)
        return None
    return stdout[len(tag_prefix):]

def version_from_expanded_variable(s, tag_prefix):
    s = s.strip()
    if "$Format" in s: # unexpanded
        return version_from_vcs(tag_prefix)
    refs = set([r.strip() for r in s.strip("()").split(",")])
    refs.discard("HEAD") ; refs.discard("master")
    for r in reversed(sorted(refs)):
        if r.startswith(tag_prefix):
            return r[len(tag_prefix):]
    return "unknown"

tag_prefix = ""
__version__ = version_from_expanded_variable(verstr.strip(), tag_prefix)
