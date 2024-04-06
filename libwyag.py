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


    args = argparser.parse_args(argv)
    match args.command:
        case "init"         : cmd_init(args)
        case "cat-file"      : cmd_cat_file(args)
        case "hash-object": cmd_hash_object(args)
        case _              : print("Bad command.")

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
        # case b'commit' : obj=GitCommit(data)
        # case b'tree'   : obj=GitTree(data)
        # case b'tag'    : obj=GitTag(data)
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
    return name

def cmd_init(args):

    repo_create(args.path)

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
            # case b'commit': c=GitCommit
            # case b'tree':
            # case b'tag':
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


