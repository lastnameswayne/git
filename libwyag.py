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



    args = argparser.parse_args(argv)
    match args.command:
        case "init"         : cmd_init(args)
        case _              : print("Bad command.")


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

