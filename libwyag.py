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
        case _              : print("Bad command.")


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


def cat_file(repo, object, fmt):
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
            sha = object.kvlm[b'tree'].decode("ascii")
        else:
            return None

def cmd_init(args):
    repo_create(args.path)


def visualize_commits(repo, commit_sha, seen):
    if commit_sha in seen:
        return
    seen.add(commit_sha)

    commit = object_read(repo, commit_sha)
    message = commit.kvlm["message"].decode("utf8").strip()
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


def calculate_path_from_hash(repo, hash):
    return repo_file(repo, "objects", hash[0:2], hash[2:], mkdir=True)


def object_read(repo, sha):
    path = calculate_path_from_hash(repo, sha)

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
        path = calculate_path_from_hash(repo, sha)
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
        dct["message"] = raw[start+1:]  #the message
        return dct

    key = raw[start:space]

    #the value may stretch over multiple lines
    end = start
    while True:
        end = raw.find(b'\n', end+1)
        char_after_nl_is_not_space = raw[end+1] != ord(' ')
        if char_after_nl_is_not_space: break

    val = raw[space+1:end].replace(b'\n ', b'\n')
    if key in dct:
        if type(dct[key]) == list:
            dct[key].append(val)
        else:
            dct[key] = [ dct[key], val ]
    else:
        dct[key]=[val]

    return kvlm_parse(raw, start=end+1, dct=dct)


def kvlm_serialize(kvlm):
    msg = b''

    for k in kvlm.keys():
        if k==None: continue
        val = kvlm[k]


        for v in val:
            msg+= k + b' ' + (v.replace(b'\n', 'b\n ')) + b'\n'


    msg += b'\n' + kvlm["message"] + b'\n' 
        
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
        tree_serialize(self)
    
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


def tree_serialize(tree):
    sorted = tree.items.sort(key=tree_leaf_sort_key)

    out = b''
    for elem in sorted.items:
        out+=elem.mode+b' '+elem.path.encode("utf8")+b'\x00'
        sha = int(elem.sha, 16)
        out+=sha.to_bytes(20,byteorder="big")

    return out

        

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
            rem = name[0:2]
            for f in os.listdir(path):
                if f.startswith(rem):
                    candidates.append(prefix+f)



    as_tag = ref_resolve(repo, "refs/tags/"+name)
    if as_tag:
        candidates.append(as_tag)

    as_branch = ref_resolve(repo, "refs/heads/"+name)
    if as_branch:
        candidates.append(as_branch)


    return candidates
