import argparse
import collections
import configparser
from datetime import datetime
from fnmatch import fnmatch
import hashlib
from math import ceil
import os
import re
import sys
import zlib
import grp, pwd




def main(argv=sys.argv[1:]):
    argparser = argparse.ArgumentParser(description="git version mine")
    argsubparsers = argparser.add_subparsers(title="Commands", dest="command")
    argsubparsers.required = True
    argsp = argsubparsers.add_parser("init", help="Initialize a new, empty repository.")

    argsp.add_argument("path",
                   metavar="directory",
                   nargs="?",
                   default=".",
                   help="Where to create the repository.")



    argsp = argsubparsers.add_parser("cat-file",
                                 help="Provide content of repository objects")

    argsp.add_argument("type",
                   metavar="type",
                   choices=["blob", "commit", "tag", "tree"],
                   help="Specify the type")

    argsp.add_argument("object",
                   metavar="object",
                   help="The object to display")

    argsp = argsubparsers.add_parser(
    "hash-object",
    help="Compute object ID and optionally creates a blob from a file")

    argsp.add_argument("-t",
                   metavar="type",
                   dest="type",
                   choices=["blob", "commit", "tag", "tree"],
                   default="blob",
                   help="Specify the type")

    argsp.add_argument("-w",
                   dest="write",
                   action="store_true",
                   help="Actually write the object into the database")

    argsp.add_argument("path",
                   help="Read object from <file>")


    argsp = argsubparsers.add_parser("log", help="Display history of a given commit.")
    argsp.add_argument("commit",
                   default="HEAD",
                   nargs="?",
                   help="Commit to start at.")
    
    argsp = argsubparsers.add_parser("ls-tree", help="Pretty-print a tree object.")
    argsp.add_argument("-r",
                   dest="recursive",
                   action="store_true",
                   help="Recurse into sub-trees")

    argsp.add_argument("tree",
                   help="A tree-ish object.")
    

    argsp = argsubparsers.add_parser("checkout", help="Checkout a commit inside of a directory.")

    argsp.add_argument("commit",
                   help="The commit or tree to checkout.")

    argsp.add_argument("path",
                   help="The EMPTY directory to checkout on.")
    
    argsp = argsubparsers.add_parser("show-ref", help="List references.")

    argsp = argsubparsers.add_parser(
    "tag",
    help="List and create tags")

    argsp.add_argument("-a",
                   action="store_true",
                   dest="create_tag_object",
                   help="Whether to create a tag object")

    argsp.add_argument("name",
                   nargs="?",
                   help="The new tag's name")

    argsp.add_argument("object",
                   default="HEAD",
                   nargs="?",
                   help="The object the new tag will point to")
    
    argsp = argsubparsers.add_parser(
    "rev-parse",
    help="Parse revision (or other objects) identifiers")

    argsp.add_argument("--wyag-type",
                   metavar="type",
                   dest="type",
                   choices=["blob", "commit", "tag", "tree"],
                   default=None,
                   help="Specify the expected type")

    argsp.add_argument("name",
                   help="The name to parse")
            
    

    argsp = argsubparsers.add_parser("ls-files", help = "List all the stage files")
    argsp.add_argument("--verbose", action="store_true", help="Show everything.")

    argsp = argsubparsers.add_parser("check-ignore", help = "Check path(s) against ignore rules.")
    argsp.add_argument("path", nargs="+", help="Paths to check")

    argsp = argsubparsers.add_parser("status", help = "Show the working tree status.")

    argsp = argsubparsers.add_parser("rm", help="Remove files from the working tree and the index.")
    argsp.add_argument("path", nargs="+", help="Files to remove")

    argsp = argsubparsers.add_parser("add", help = "Add files contents to the index.")
    argsp.add_argument("path", nargs="+", help="Files to add")
    
    argsp = argsubparsers.add_parser("commit", help="Record changes to the repository.")

    argsp.add_argument("-m",
                   metavar="message",
                   dest="message",
                   help="Message to associate with this commit.")


    args = argparser.parse_args(argv)
    match args.command:
        case "init"         : cmd_init(args)
        case "cat-file"      : cmd_cat_file(args)
        case "hash-object": cmd_hash_object(args)
        case "log": cmd_log(args)
        case "ls-tree": cmd_ls_tree(args)
        case "checkout": cmd_checkout(args)
        case "show-ref": cmd_show_ref(args)
        case "tag": cmd_tag(args)
        case "rev-parse": cmd_rev_parse(args)
        case "ls-files": cmd_ls_files(args)
        case "check-ignore": cmd_check_ignore(args)
        case "status": cmd_status(args)
        case "rm": cmd_rm(args)
        case "add": cmd_add(args)
        case "commit": cmd_commit(args)
        case _              : print("Bad command.")


def cmd_commit(args):
    repo = repo_find()
    index = index_read(repo)
    # Create trees, grab back SHA for the root tree.
    tree = tree_from_index(repo, index)

    # Create the commit object itself
    commit = commit_create(repo,
                           tree,
                           object_find(repo, "HEAD"),
                           gitconfig_user_get(gitconfig_read()),
                           datetime.now(),
                           args.message)

    # Update HEAD so our commit is now the tip of the active branch.
    active_branch = branch_get_active(repo)
    if active_branch: # If we're on a branch, we update refs/heads/BRANCH
        with open(repo_file(repo, os.path.join("refs/heads", active_branch)), "w") as fd:
            fd.write(commit + "\n")
    else: # Otherwise, we update HEAD itself.
        with open(repo_file(repo, "HEAD"), "w") as fd:
            fd.write("\n")

def cmd_add(args):
  repo = repo_find()
  add(repo, args.path)

def cmd_rm(args):
    repo = repo_find()
    rm(repo, args.path)


#removes the existing index entry
# hash the file into glob objet 
# create the entry using stat and wirthe the modified index back
def add(repo, paths, delete=True, skip_missing=False):

  # First remove all paths from the index, if they exist.
  rm (repo, paths, delete=False, skip_missing=True)

  worktree = repo.worktree + os.sep

  # Convert the paths to pairs: (absolute, relative_to_worktree).
  # Also delete them from the index if they're present.
  clean_paths = list()
  for path in paths:
    abspath = os.path.abspath(path)
    if not (abspath.startswith(worktree) and os.path.isfile(abspath)):
      raise Exception("Not a file, or outside the worktree: {}".format(paths))
    relpath = os.path.relpath(abspath, repo.worktree)
    clean_paths.append((abspath,  relpath))

    index = index_read(repo)

    for (abspath, relpath) in clean_paths:
      with open(abspath, "rb") as fd:
        sha = object_hash(fd, b"blob", repo)

      stat = os.stat(abspath)

      ctime_s = int(stat.st_ctime)
      ctime_ns = stat.st_ctime_ns % 10**9
      mtime_s = int(stat.st_mtime)
      mtime_ns = stat.st_mtime_ns % 10**9

      entry = GitIndexEntry(ctime=(ctime_s, ctime_ns), mtime=(mtime_s, mtime_ns), dev=stat.st_dev, ino=stat.st_ino,
                            mode_type=0b1000, mode_perms=0o644, uid=stat.st_uid, gid=stat.st_gid,
                            fsize=stat.st_size, sha=sha, flag_assume_valid=False,
                            flag_stage=False, name=relpath)
      index.entries.append(entry)

    # Write the index back
    index_write(repo, index)
    

#takes a list of paths and removes them from the index_file
def rm(repo, paths, delete=True, skip_missing=False):
  # Find and read the index
  index = index_read(repo)

  worktree = repo.worktree + os.sep

  # Make paths absolute
  abspaths = list()
  for path in paths:
    abspath = os.path.abspath(path)
    if abspath.startswith(worktree):
      abspaths.append(abspath)
    else:
      raise Exception("Cannot remove paths outside of worktree: {}".format(paths))

  kept_entries = list()
  remove = list()

  for e in index.entries:
    full_path = os.path.join(repo.worktree, e.name)

    if full_path in abspaths:
      remove.append(full_path)
      abspaths.remove(full_path)
    else:
      kept_entries.append(e) # Preserve entry

  if len(abspaths) > 0 and not skip_missing:
    raise Exception("Cannot remove paths not in the index: {}".format(abspaths))

  if delete:
    for path in remove:
      os.unlink(path)

  index.entries = kept_entries
  index_write(repo, index)    


def cmd_status(_):
    repo = repo_find()
    index = index_read(repo)

    cmd_status_branch(repo)
    cmd_status_head_index(repo, index)
    print()
    cmd_status_index_worktree(repo, index)

def branch_get_active(repo):
    with open(repo_file(repo, "HEAD"), "r") as f:
        head = f.read()

    if head.startswith("ref: refs/heads/"):
        return(head[16:-1])
    else:
        return False


# takes the tree which is a list of leaf objects and converts to a dict of path -> sha
def tree_to_dict(repo, ref, prefix=""):
  ret = dict()
  tree_sha = object_find(repo, ref, fmt=b"tree")
  tree = object_read(repo, tree_sha)

  for leaf in tree.items:
      full_path = os.path.join(prefix, leaf.path)

      # We read the object to extract its type (this is uselessly
      # expensive: we could just open it as a file and read the
      # first few bytes)
      is_subtree = leaf.mode.startswith(b'04')

      # Depending on the type, we either store the path (if it's a
      # blob, so a regular file), or recurse (if it's another tree,
      # so a subdir)
      if is_subtree:
        ret.update(tree_to_dict(repo, leaf.sha, full_path))
      else:
        ret[full_path] = leaf.sha

  return ret

def cmd_status_head_index(repo, index):
    print("Changes to be committed:")

    head = tree_to_dict(repo, "HEAD")
    for entry in index.entries:
        if entry.name in head:
            if head[entry.name] != entry.sha:
                print("  modified:", entry.name)
            del head[entry.name] # Delete the key
        else:
            print("  added:   ", entry.name)

    # Keys still in HEAD are files that we haven't met in the index,
    # and thus have been deleted.
    for entry in head.keys():
        print("  deleted: ", entry)

def cmd_status_branch(repo):
    branch = branch_get_active(repo)
    if branch:
        print("On branch {}.".format(branch))
    else:
        print("HEAD detached at {}".format (object_find(repo, "HEAD")))


def cmd_check_ignore(args):
    repo = repo_find()
    rules = gitignore_read(repo)
    for path in args.path:
        if check_ignore(rules, path):
            print(path)

#compares the index file to the worktree
def cmd_status_index_worktree(repo, index):
    print("Changes not staged for commit:")

    ignore = gitignore_read(repo)

    gitdir_prefix = repo.git_directory + os.path.sep

    all_files = list()

    # We begin by walking the filesystem
    for (root, _, files) in os.walk(repo.worktree, True):
        if root==repo.git_directory or root.startswith(gitdir_prefix):
            continue
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, repo.worktree)
            all_files.append(rel_path)

    # We now traverse the index, and compare real files with the cached
    # versions.

    for entry in index.entries:
        full_path = os.path.join(repo.worktree, entry.name)

        # That file *name* is in the index

        if not os.path.exists(full_path):
            print("  deleted: ", entry.name)
        else:
            stat = os.stat(full_path)

            # Compare metadata
            ctime_ns = entry.ctime[0] * 10**9 + entry.ctime[1]
            mtime_ns = entry.mtime[0] * 10**9 + entry.mtime[1]
            if (stat.st_ctime_ns != ctime_ns) or (stat.st_mtime_ns != mtime_ns):
                # If different, deep compare.
                # @FIXME This *will* crash on symlinks to dir.
                with open(full_path, "rb") as fd:
                    new_sha = object_hash(fd, b"blob", None)
                    # If the hashes are the same, the files are actually the same.
                    same = entry.sha == new_sha

                    if not same:
                        print("  modified:", entry.name)

        if entry.name in all_files:
            all_files.remove(entry.name)

    print()
    print("Untracked files:")

    for f in all_files:
        # @TODO If a full directory is untracked, we should display
        # its name without its contents.
        if not check_ignore(ignore, f):
            print(" ", f)

def gitignore_parse_one_rule(raw):
    raw = raw.strip()

    if not raw or raw[0] == "#":
        return None
    
    elif raw[0] == "!":
        return (raw[1:], False)
    elif raw[0] == "\\":
        return (raw[1:], True)
    else:
        return (raw, True)

def gitignore_parse(lines):
    ret = list()

    for line in lines:
        parsed = gitignore_parse_one_rule(line)
        if parsed:
            ret.append(parsed)

    return ret

class GitIgnore(object):
    absolute = None
    scoped = None

    def __init__(self, absolute, scoped):
        self.absolute = absolute
        self.scoped = scoped


def gitignore_read(repo):
    ret = GitIgnore(absolute=list(), scoped=dict())

    # Read local configuration in .git/info/exclude
    repo_file = os.path.join(repo.git_directory, "info/exclude")
    if os.path.exists(repo_file):
        with open(repo_file, "r") as f:
            ret.absolute.append(gitignore_parse(f.readlines()))
    

    # Global configuration
    if "XDG_CONFIG_HOME" in os.environ:
        config_home = os.environ["XDG_CONFIG_HOME"]
    else:
        config_home = os.path.expanduser("~/.config")
    global_file = os.path.join(config_home, "git/ignore")


    if os.path.exists(global_file):
        with open(global_file, "r") as f:
            ret.absolute.append(gitignore_parse(f.readlines()))

    # .gitignore files in the index
    index = index_read(repo)

    for entry in index.entries:
        if entry.name == ".gitignore" or entry.name.endswith("/.gitignore"):
            dir_name = os.path.dirname(entry.name)
            contents = object_read(repo, entry.sha)
            lines = contents.blobdata.decode("utf8").splitlines()
            ret.scoped[dir_name] = gitignore_parse(lines)

    return ret

def check_ignore_one_path(rules, path):
    result = None
    for (pattern, value) in rules:
        if fnmatch(path, pattern):
            result = value
    return result

def check_ignore_scoped(rules, path):
    parent = os.path.dirname(path)
    while True:
        if parent in rules:
            result = check_ignore_one_path(rules[parent], path)
            if result != None:
                return result
        if parent == "":
            break
        parent = os.path.dirname(parent)
    return None

def check_ignore_absolute(rules, path):
    for ruleset in rules:
        result = check_ignore_one_path(ruleset, path)
        if result != None:
            return result
    return False # This is a reasonable default at this point.

def check_ignore(rules, path):
    if os.path.isabs(path):
        raise Exception("This function requires path to be relative to the repository's root")

    result = check_ignore_scoped(rules.scoped, path)
    if result != None:
        return result

    return check_ignore_absolute(rules.absolute, path)


def cmd_ls_files(args):
    repo=repo_find()
    index = index_read(repo) 
    if args.verbose:
        print("Index file format v{}, containing {} entries.".format(index.version, len(index.entries)))

    for e in index.entries:
        print(e.name)
        if args.verbose:
            print("  {} with perms: {:o}".format(
        { 0b1000: "regular file",
          0b1010: "symlink",
          0b1110: "git link" }[e.mode_type],
        e.mode_perms))
        print("  on blob: {}".format(e.sha))
        print("  created: {}.{}, modified: {}.{}".format(
        datetime.fromtimestamp(e.ctime[0])
        , e.ctime[1]
        , datetime.fromtimestamp(e.mtime[0])
        , e.mtime[1]))
        print("  device: {}, inode: {}".format(e.dev, e.ino))
        print("  user: {} ({})  group: {} ({})".format(
            pwd.getpwuid(e.uid).pw_name,
            e.uid,
        grp.getgrgid(e.gid).gr_name,
        e.gid))
        print("  flags: stage={} assume_valid={}".format(
        e.flag_stage,
        e.flag_assume_valid))

def cmd_rev_parse(args):
    if args.type:
        fmt = args.type.encode()
    else:
        fmt = None

    repo = repo_find()

    print (object_find(repo, args.name, fmt, follow=True))


def cmd_tag(args):
    repo = repo_find()

    if args.name:
        tag_create(repo,
                   args.name,
                   args.object,
                   type="object" if args.create_tag_object else "ref")
    else:
        refs = ref_list(repo)
        if len(refs["tags"].values()) == 0:
            print("no tags found") 
        show_ref(repo, refs["tags"], with_hash=True)


def tag_create(repo, name, ref, create_tag_object = False, type=""):
    sha = object_find(repo, ref)
    
    if create_tag_object:
        tag = GitTag()
        tag.kvlm = collections.OrderedDict()
        tag.kvlm[b'object'] = sha.encode()
        tag.kvlm[b'type'] = b'commit'
        tag.kvlm[b'tag'] = name.encode()
        tag.kvlm[b'tagger']= "me"
        tag.kvlm[None]  = b"Tag test"
        tag_sha = object_write(tag)
        ref_create(repo, "tags/"+name, tag_sha)
    else:
        ref_create(repo, "tags/"+name, sha)

def ref_create(repo, ref_name, sha):
    with open(repo_file(repo, "refs/" + ref_name), 'w') as fp:
        fp.write(sha + "\n")


def cmd_show_ref(args):
    repo = repo_find()
    refs = ref_list(repo)
    show_ref(repo, refs, prefix="refs")
    

def show_ref(repo, refs, with_hash=True, prefix=""):
    for k,v in refs.items():
        if type(v)==str:
            print ("{0}{1}{2}".format(
                v + " " if with_hash else "",
                prefix + "/" if prefix else "",
                k))

        else:
            show_ref(repo, v, with_hash=with_hash, prefix="{0}{1}{2}".format(prefix, "/" if prefix else "", k))

def cmd_checkout(args):
    repo = repo_find()
    obj = object_read(repo, object_find(repo, args.commit))

    if obj.fmt == b'commit':
        obj = object_read(repo, obj.kvlm[b'tree'][0].decode("ascii"))
    
    if os.path.exists(args.path):
        if not os.path.isdir(args.path):
            raise Exception(f"Not a directory {args.path}")
        if os.listdir(args.path):
            raise Exception(f"Not empty", args.path)
    
    else:
        os.makedirs(args.path)


    tree_checkout(repo, obj, os.path.realpath(args.path))

def tree_checkout(repo, tree, path):
    for elem in tree.items:
        obj = object_read(repo, elem.sha)
        dest = os.path.join(path, elem.path)

        if obj.fmt == b'tree':
            os.mkdir(dest)
            tree_checkout(repo,obj, dest)
        elif obj.fmt==b'blob':
            with open(dest, 'wb') as f:
                f.write(obj.blobdata)


def cmd_ls_tree(args):
    repo=repo_find()
    ls_tree(repo, args.tree, args.recursive)

def ls_tree(repo, ref, recursive=None, prefix=""):
    sha = object_find(repo, ref, fmt=b"tree")
    obj = object_read(repo, sha) #get the tree from the objects folder

    for item in obj.items:
        if len(item.mode)==5:
            type = item.mode[0:1]
        else:
            type = item.mode[0:2]
        
        match type: #this is per definition of the tree content https://wyag.thb.lt/#checkout
            case b'04': type = "tree"
            case b'10': type = "blob" # A regular file.
            case b'12': type = "blob" # A symlink. Blob contents is link target.
            case b'16': type = "commit" # A submodule
            case _: raise Exception("Weird tree leaf mode {}".format(item.mode))

        if type != 'tree' or not recursive: #this is a leaf, print it
            zero_padding = "0" * (6 - len(item.mode)) + item.mode.decode("ascii"),
            print("{0} {1} {2}\t{3}".format(
                zero_padding,
                type,
                item.sha,
                os.path.join(prefix, item.path)))
        else: 
            ls_tree(repo, item.sha, recursive, os.path.join(prefix, item.path))

def cmd_log(args):
    repo = repo_find()

    print("digraph wyaglog{")
    print("  node[shape=rect]")
    visualize_commits(repo, object_find(repo, args.commit), set())
    print("}")

def cmd_hash_object(args):
    if args.write:
        repo = repo_find()
    else:
        repo = None

    with open(args.path, "rb") as fd:
        sha = object_hash(fd, args.type.encode(), repo)
        print(sha)

def object_hash(fd, fmt, repo=None):
    data = fd.read()

    match fmt:
        case b'commit' : obj=GitCommit(data)
        case b'tree'   : obj=GitTree(data)
        case b'tag'    : obj=GitTag(data)
        case b'blob'   : obj=GitBlob(data)
        case _: raise Exception("Unknown type %s!" % fmt)

    return object_write(obj, repo)

def cmd_cat_file(args):
    repo = repo_find()
    cat_file(repo, args.object, fmt=args.type.encode())


def cat_file(repo, object, fmt=None):
    obj = object_read(repo, object_find(repo, object, fmt=fmt))
    sys.stdout.buffer.write(obj.serialize())

def object_find(repo, name, fmt=None, follow=True):
    sha = object_resolve(repo, name)
    if not sha:
        return Exception("no such references")

    if len(sha)>1:
        raise Exception("more than one candidates, ambitious reference")


    sha = sha[0]

    if not fmt:
        return sha

    
    while(True):
        object = object_read(repo, sha)
        if object.fmt == fmt:
            return sha
    
        if not follow:
            return None
    
        if object.fmt == b'tag':
            sha = object.kvlm[b'object'].decode("ascii")
        elif object.fmt == b'commit' and fmt == b'tree':
            sha = object.kvlm[b'tree'][0].decode("ascii")
        else:
            return None

def cmd_init(args):
    repo_create(args.path)


def visualize_commits(repo, commit_sha, seen):
    if commit_sha in seen:
        return
    seen.add(commit_sha)

    commit = object_read(repo, commit_sha)
    message = commit.kvlm[None].decode("utf8").strip()
    message = message.replace("\\", "\\\\")
    message = message.replace("\"", "\\\"")

    if "\n" in message: # Keep only the first line
        message = message[:message.index("\n")]

    print("  c_{0} [label=\"{1}: {2}\"]".format(commit_sha, commit_sha[0:7], message))
    assert commit.fmt==b'commit'

    if not b'parent' in commit.kvlm.keys():
        # Base case: the initial commit.
        return

    parents = commit.kvlm[b'parent']

    if type(parents) != list:
        parents = [ parents ]

    for p in parents:
        p = p.decode("ascii")
        print ("  c_{0} -> c_{1};".format(commit_sha, p))
        visualize_commits(repo, p, seen)

def repo_create(path):
    git_repo = GitRepository(path, True)

    if not os.path.exists(git_repo.git_directory):
        os.makedirs(git_repo.git_directory)


    if not os.path.isdir(git_repo.worktree):
        raise Exception ("%s is not a directory!" % path)
    if os.path.exists(git_repo.git_directory) and os.listdir(git_repo.git_directory):
        raise Exception("%s is not empty!" % path)

    
    assert repo_dir(git_repo, "branches", mkdir=True)
    assert repo_dir(git_repo, "objects", mkdir=True)
    assert repo_dir(git_repo, "refs", "tags", mkdir=True)
    assert repo_dir(git_repo, "refs", "heads", mkdir=True)


    with open(repo_file(git_repo, "description"), "w") as f:
        f.write("edit this file to name the repository")

    with open(repo_file(git_repo, "HEAD") ,"w") as f:
        f.write("ref: refs/heads/master\n")

    with open(repo_file(git_repo, "config"), "w") as f:
        config = repo_default_config()
        config.write(f)

    return git_repo


def repo_default_config():
    cf = configparser.ConfigParser()
    
    cf.add_section("core")
    cf.set("core", "repositoryformatversion", "0")
    cf.set("core", "filemode", "false")
    cf.set("core", "bare", "false")

    return cf



class GitRepository (object):
    worktree = None
    git_directory = None
    conf = None

    # finds the .git directory
    # and checks it is valid
    # checks the repository version
    # sets both the work tree ( current path) and the git directory 
    # which is a /.git folder within the worktree
    # conf is then a config file within the .git folder
    def __init__(self, path, force=False):
        self.worktree = path
        self.git_directory = os.path.join(path, ".git")


        if not force and not os.path.isdir(self.git_directory):
            return Exception("Not a git repository %s" % path)

        

        self.conf = configparser.ConfigParser()
        cf = repo_file(self, "config")

        if not force and (cf and os.path.exists(cf)):
            self.conf.read([cf])

        if not force:
            repoFormatVersion = self.conf.get("core", "repositoryformatversion")
            if repoFormatVersion != 0:
                raise Exception("unsupported opreration")
    

def repo_path(repo, *path):
    return os.path.join(repo.git_directory, *path)

def repo_file(repo, *path, mkdir=False):
    if repo_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_path(repo, *path)



def repo_dir(repo, *path, mkdir=False):

    repository_path = repo_path(repo, *path)

    if os.path.exists(repository_path):
        if os.path.isdir(repository_path):
            return repository_path
        else:
            raise Exception("not a directory")
    

    if mkdir:
        os.makedirs(repository_path)
        return repository_path
    else:
        return None



def repo_find(path=".", required=True):
    path = os.path.realpath(path)


    gitpath = os.path.join(path, ".git")
    if os.path.isdir(gitpath):
        return GitRepository(path, True)
    
    
    parent = os.path.realpath(os.path.join(path, ".."))
    if parent == path:
        if required:
            raise Exception("no repo found")

        else:
            return None

    return repo_find(parent, required)


class GitObject(object):
    def __init__(self, data=None):
        if data != None:
            self.deserialize(data)
        else:
            self.init() 
    
    def serialize(self, repo):
        raise Exception("unimplemented")

    def deserialize(self, data):
        raise Exception("unimplemented")
    
    def init(self):
        pass


def object_read(repo, sha):
    path = repo_file(repo, "objects", sha[0:2], sha[2:])

    if not os.path.isfile(path):
        return None

    with open (path, "rb") as f:
        decompressed = zlib.decompress(f.read())

        #An object starts with a header that specifies its type:
            #1. blob, commit, tag or tree. 
            #2. This header is followed by an ASCII space (0x20), 
            #3. then the size of the object in bytes as an ASCII number, 
            #4. then null (0x00) (the null byte), then the contents of the object

        x = decompressed.find(b' ')  #find the ASCII space and read everything before that as the type
        object_type = decompressed[0:x]

        
        #find the ASCII null and everyhting before that and after the space is the size of the object in bytes as an ASCII number
        y = decompressed.find(b'\x00', x) 
        size = int(decompressed[x:y].decode("ascii"))
        if size != len(decompressed)-y-1: #y-1 is the size of the header, so we subtract that from the total = left with object size
            raise Exception("Malformed object {0}: bad length".format(sha))


        match object_type:
            case b'commit': c=GitCommit
            case b'tree': c=GitTree
            case b'tag': c=GitTag
            case b'blob': c=GitBlob
            case _:
                raise Exception("unknown type")
        
    
        #[y+1:] is the object data, as [y+1] is the header. I might be off by 1
        return c(decompressed[y+1:])


def object_write(obj, repo=None):
    data = obj.serialize()
#add header
    result = obj.fmt + b' ' + str(len(data)).encode() + b'\x00' + data

    sha = hashlib.sha1(result).hexdigest()

    if repo:
        path=repo_file(repo, "objects", sha[0:2], sha[2:], mkdir=True)

        if not os.path.exists(path):
            with open(path, 'wb') as f:
                f.write(zlib.compress(result))

    return sha




class GitBlob(GitObject):
    fmt=b'blob'

    def serialize(self):
        return self.blobdata

    def deserialize(self, data):
        self.blobdata=data



class GitCommit(GitObject):
    fmt=b'commit'
    
    def serialize(self):
        return kvlm_serialize(self.kvlm)
    
    def deserialize(self, data):
        self.kvlm = kvlm_parse(data)
    
    def init(self):
        self.kvlm = dict()



class GitTag(GitCommit):
    fmt = b'tag'       
         

def kvlm_parse(raw, start=0, dct=None):
    if not dct:
        dct= collections.OrderedDict()
    
   
    space = raw.find(b' ', start)
    newline = raw[start:].find(b'\n', start)

    noSpace = space == -1
    if noSpace or newline < space:
        dct[None] = raw[start+1:]  #the message
        return dct

    key = raw[start:space]

    #the value may stretch over multiple lines
    end = start
    while True:
        end = raw.find(b'\n', end+1)
        if raw[end+1] != ord(' '): break


    val = raw[space+1:end].replace(b'\n ', b'\n')
    if key in dct:
        if type(dct[key]) == list:
            dct[key].append(val)
        else:
            dct[key] = [ dct[key], val ]
    else:
        dct[key]=val

    return kvlm_parse(raw, start=end+1, dct=dct)


def kvlm_serialize(kvlm):
    msg = b''

    for k in kvlm.keys():
        if k==None: continue
        val = kvlm[k]
        if type(val) != list:
            val = [ val ]

        for v in val:
            msg+= k + b' ' + (v.replace(b'\n', 'b\n ')) + b'\n'


    msg += b'\n' + kvlm[None] + b'\n' 
        
    return msg


class GitTreeLeaf(object):
    
    def __init__(self, mode, path, sha):
        self.mode=mode
        self.path= path 
        self.sha = sha


class GitTree(GitObject):
    fmt = b'tree'

    def deserialize(self,data):
        self.items = tree_parse(data)
    
    def serialize(self):
        return tree_serialize(self)
    
    def init(self):
        self.items = list()


def tree_parse_one(raw, start=0):
    mode_end = raw.find(b' ', start)

    mode=raw[start:mode_end]
    if len(mode) == 5:
        # Normalize to six bytes.
        mode = b" " + mode

    path_end = raw.find(b'\x00', mode_end)

    path=raw[mode_end+1:path_end]

    #SHA-1 in binary encoding, on 20 bytes. converts to hexadeicmal
    sha = format(int.from_bytes(raw[path_end+1:path_end+21], "big"), "040x")
    print(path)
    return path_end+21, GitTreeLeaf(mode, path.decode("utf8"), sha) 



def tree_parse(raw):
    i = 0
    out = list()
    while(i<len(raw)):
        end, leaf = tree_parse_one(raw, i) 
        i=end
        out.append(leaf)

    return out


def tree_serialize(obj):
    obj.items.sort(key=tree_leaf_sort_key)
    ret = b''
    for i in obj.items:
        ret += i.mode
        ret += b' '
        ret += i.path.encode("utf8")
        ret += b'\x00'
        sha = int(i.sha, 16)
        ret += sha.to_bytes(20, byteorder="big")
    return ret

        

def tree_leaf_sort_key(leaf):
    if leaf.mode.startswith(b"10"):
        return leaf.path
    else:
        return leaf.path + "/"

def ref_resolve(repo, ref):
    path=repo_file(repo, ref)

    if not os.path.isfile(path):
        return None


    with open(path, 'r') as fp:
        data = fp.read()[:-1]
    if data.startswith("ref: "):
        return ref_resolve(repo, data[5:])
    else:
        return data

def ref_list(repo, path=None):
    if not path:
        path = repo_dir(repo, "refs")
    

    ret = collections.OrderedDict()

    for f in sorted(os.listdir(path)):
        ref_path = os.path.join(path, f)
        if os.path.isdir(ref_path):
            ret[f] = ref_list(repo, ref_path)
        else:
            ret[f] = ref_resolve(repo, ref_path)

    return ret


def object_resolve(repo, name):
    candidates = list()
    hashRE = re.compile(r"^[0-9A-Fa-f]{4,40}$")
    if not name.strip():
        return None
 
    if name == "HEAD":
        return [ref_resolve(repo, "HEAD")]

    if hashRE.match(name):
        name = name.lower()
        prefix = name[0:2]
        path = repo_dir(repo, "objects", prefix, mkdir=False)
        if path:
            rem = name[2:]
            for f in os.listdir(path):
                if f.startswith(rem):
                    candidates.append(prefix+f)



    as_tag = ref_resolve(repo, "refs/tags/"+name)
    if as_tag:
        candidates.append(as_tag)

    as_branch = ref_resolve(repo, "refs/heads/"+name)
    if as_branch:
        candidates.append(as_branch)



    # search for branches and tags (with or without "refs" and "heads" or "tags" prefixes)
    for path in [f'refs/heads/{name}', f'refs/tags/{name}', f'refs/{name}', name]:
        if os.path.exists(repo_file(repo, path)):
            candidates.append(ref_resolve(repo, path))
    
    return candidates


class GitIndexEntry (object):
    def __init__(self, ctime=None, mtime=None, dev=None, ino=None,
                 mode_type=None, mode_perms=None, uid=None, gid=None,
                 fsize=None, sha=None, flag_assume_valid=None,
                 flag_stage=None, name=None):
        
        self.ctime= ctime
        self.mtime = mtime
        self.dev = dev
        self.ino = ino
        self.mode_type = mode_type
        self.mode_perms = mode_perms
        self.uid = uid
        self.gid = gid
        self.fsize = fsize
        self.sha = sha
        self.flag_assume_valid =  flag_assume_valid
        self.flag_stage = flag_stage
        self.name = name




class GitIndex(object):

    version = None

    entries = []

    def __init__(self, version=2, entries=None):
        if not entries:
            entries=list()

        self.version = version
        self.entries = entries


def index_read(repo):
    index_file = repo_file(repo, "index")

    if not os.path.exists(index_file):
        return GitIndex()
    
    with open(index_file, 'rb') as f:
        raw = f.read()

    
    header = raw[:12]
    signature = header[:4]
    assert signature== b"DIRC"
    version = int.from_bytes(header[4:8], "big")

    assert version == 2
    count = int.from_bytes(header[8:12], "big")

    entries = list()

    content = raw[12:]
    idx = 0
    for i in range(0, count):
        # Read creation time, as a unix timestamp (seconds since
        # 1970-01-01 00:00:00, the "epoch")
        ctime_s =  int.from_bytes(content[idx: idx+4], "big")
        # Read creation time, as nanoseconds after that timestamps,
        # for extra precision.
        ctime_ns = int.from_bytes(content[idx+4: idx+8], "big")
        # Same for modification time: first seconds from epoch.
        mtime_s = int.from_bytes(content[idx+8: idx+12], "big")
        # Then extra nanoseconds
        mtime_ns = int.from_bytes(content[idx+12: idx+16], "big")
        # Device ID
        dev = int.from_bytes(content[idx+16: idx+20], "big")
        # Inode
        ino = int.from_bytes(content[idx+20: idx+24], "big")
        # Ignored.
        unused = int.from_bytes(content[idx+24: idx+26], "big")
        assert 0 == unused
        mode = int.from_bytes(content[idx+26: idx+28], "big")
        mode_type = mode >> 12
        assert mode_type in [0b1000, 0b1010, 0b1110]
        mode_perms = mode & 0b0000000111111111
        # User ID
        uid = int.from_bytes(content[idx+28: idx+32], "big")
        # Group ID
        gid = int.from_bytes(content[idx+32: idx+36], "big")
        # Size
        fsize = int.from_bytes(content[idx+36: idx+40], "big")
        # SHA (object ID).  We'll store it as a lowercase hex string
        # for consistency.
        sha = format(int.from_bytes(content[idx+40: idx+60], "big"), "040x")
        # Flags we're going to ignore
        flags = int.from_bytes(content[idx+60: idx+62], "big")
        # Parse flags
        flag_assume_valid = (flags & 0b1000000000000000) != 0
        flag_extended = (flags & 0b0100000000000000) != 0
        assert not flag_extended
        flag_stage =  flags & 0b0011000000000000
        # Length of the name.  This is stored on 12 bits, some max
        # value is 0xFFF, 4095.  Since names can occasionally go
        # beyond that length, git treats 0xFFF as meaning at least
        # 0xFFF, and looks for the final 0x00 to find the end of the
        # name --- at a small, and probably very rare, performance
        # cost.
        name_length = flags & 0b0000111111111111

        # We've read 62 bytes so far.
        idx += 62

        if name_length < 0xFFF:
            assert content[idx + name_length] == 0x00
            raw_name = content[idx:idx+name_length]
            idx += name_length + 1
        else:
            print("Notice: Name is 0x{:X} bytes long.".format(name_length))
            null_idx = content.find(b'\x00', idx + 0xFFF)
            raw_name = content[idx: null_idx]
            idx = null_idx + 1

        # Just parse the name as utf8.
        name = raw_name.decode("utf8")

        # Data is padded on multiples of eight bytes for pointer
        # alignment, so we skip as many bytes as we need for the next
        # read to start at the right position.

        idx = 8 * ceil(idx / 8)

        # And we add this entry to our list.
        entries.append(GitIndexEntry(ctime=(ctime_s, ctime_ns),
                                     mtime=(mtime_s,  mtime_ns),
                                     dev=dev,
                                     ino=ino,
                                     mode_type=mode_type,
                                     mode_perms=mode_perms,
                                     uid=uid,
                                     gid=gid,
                                     fsize=fsize,
                                     sha=sha,
                                     flag_assume_valid=flag_assume_valid,
                                     flag_stage=flag_stage,
                                     name=name))

    return GitIndex(version=version, entries=entries)

def index_write(repo, index):
    with open(repo_file(repo, "index"), "wb") as f:

        # HEADER

        # Write the magic bytes.
        f.write(b"DIRC")
        # Write version number.
        f.write(index.version.to_bytes(4, "big"))
        # Write the number of entries.
        f.write(len(index.entries).to_bytes(4, "big"))

        # ENTRIES

        idx = 0
        for e in index.entries:
            f.write(e.ctime[0].to_bytes(4, "big"))
            f.write(e.ctime[1].to_bytes(4, "big"))
            f.write(e.mtime[0].to_bytes(4, "big"))
            f.write(e.mtime[1].to_bytes(4, "big"))
            f.write(e.dev.to_bytes(4, "big"))
            f.write(e.ino.to_bytes(4, "big"))

            # Mode
            mode = (e.mode_type << 12) | e.mode_perms
            f.write(mode.to_bytes(4, "big"))

            f.write(e.uid.to_bytes(4, "big"))
            f.write(e.gid.to_bytes(4, "big"))

            f.write(e.fsize.to_bytes(4, "big"))
            # @FIXME Convert back to int.
            f.write(int(e.sha, 16).to_bytes(20, "big"))

            flag_assume_valid = 0x1 << 15 if e.flag_assume_valid else 0

            name_bytes = e.name.encode("utf8")
            bytes_len = len(name_bytes)
            if bytes_len >= 0xFFF:
                name_length = 0xFFF
            else:
                name_length = bytes_len

            # We merge back three pieces of data (two flags and the
            # length of the name) on the same two bytes.
            f.write((flag_assume_valid | e.flag_stage | name_length).to_bytes(2, "big"))

            # Write back the name, and a final 0x00.
            f.write(name_bytes)
            f.write((0).to_bytes(1, "big"))

            idx += 62 + len(name_bytes) + 1

            # Add padding if necessary.
            if idx % 8 != 0:
                pad = 8 - (idx % 8)
                f.write((0).to_bytes(pad, "big"))
                idx += pad
def gitconfig_read():
    xdg_config_home = os.environ["XDG_CONFIG_HOME"] if "XDG_CONFIG_HOME" in os.environ else "~/.config"
    configfiles = [
        os.path.expanduser(os.path.join(xdg_config_home, "git/config")),
        os.path.expanduser("~/.gitconfig")
    ]

    config = configparser.ConfigParser()
    config.read(configfiles)
    return config


def gitconfig_user_get(config):
    if "user" in config:
        if "name" in config["user"] and "email" in config["user"]:
            return "{} <{}>".format(config["user"]["name"], config["user"]["email"])
    return None

def tree_from_index(repo, index):
    contents = dict()
    contents[""] = list()

    # Enumerate entries, and turn them into a dictionary where keys
    # are directories, and values are lists of directory contents.
    for entry in index.entries:
        dirname = os.path.dirname(entry.name)

        # We create all dictonary entries up to root ("").  We need
        # them *all*, because even if a directory holds no files it
        # will contain at least a tree.
        key = dirname
        while key != "":
            if not key in contents:
                contents[key] = list()
            key = os.path.dirname(key)

        # For now, simply store the entry in the list.
        contents[dirname].append(entry)

    # Get keys (= directories) and sort them by length, descending.
    # This means that we'll always encounter a given path before its
    # parent, which is all we need, since for each directory D we'll
    # need to modify its parent P to add D's tree.
    sorted_paths = sorted(contents.keys(), key=len, reverse=True)

    # This variable will store the current tree's SHA-1.  After we're
    # done iterating over our dict, it will contain the hash for the
    # root tree.
    sha = None

    # We ge through the sorted list of paths (dict keys)
    for path in sorted_paths:
        # Prepare a new, empty tree object
        tree = GitTree()

        # Add each entry to our new tree, in turn
        for entry in contents[path]:
            # An entry can be a normal GitIndexEntry read from the
            # index, or a tree we've created.
            if isinstance(entry, GitIndexEntry): # Regular entry (a file)

                # We transcode the mode: the entry stores it as integers,
                # we need an octal ASCII representation for the tree.
                leaf_mode = "{:02o}{:04o}".format(entry.mode_type, entry.mode_perms).encode("ascii")
                leaf = GitTreeLeaf(mode = leaf_mode, path=os.path.basename(entry.name), sha=entry.sha)
            else: # Tree.  We've stored it as a pair: (basename, SHA)
                leaf = GitTreeLeaf(mode = b"040000", path=entry[0], sha=entry[1])

            tree.items.append(leaf)

        # Write the new tree object to the store.
        sha = object_write(tree, repo)

        # Add the new tree hash to the current dictionary's parent, as
        # a pair (basename, SHA)
        parent = os.path.dirname(path)
        base = os.path.basename(path) # The name without the path, eg main.go for src/main.go
        contents[parent].append((base, sha))

    return sha


def commit_create(repo, tree, parent, author, timestamp, message):
    commit = GitCommit() # Create the new commit object.
    commit.kvlm[b"tree"] = tree.encode("ascii")
    if parent:
        commit.kvlm[b"parent"] = parent.encode("ascii")

    # Format timezone
    offset = int(timestamp.astimezone().utcoffset().total_seconds())
    hours = offset // 3600
    minutes = (offset % 3600) // 60
    tz = "{}{:02}{:02}".format("+" if offset > 0 else "-", hours, minutes)

    author = author + timestamp.strftime(" %s ") + tz

    commit.kvlm[b"author"] = author.encode("utf8")
    commit.kvlm[b"committer"] = author.encode("utf8")
    commit.kvlm[None] = message.encode("utf8")

    return object_write(commit, repo)
