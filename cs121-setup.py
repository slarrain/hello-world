#!/usr/bin/python

# CMSC 12100 - Computer Science with Application I
#
# Repository setup script
# 
# Command-line options (all optional):
#
#  --cnetid CNETID
#
#      By default, the script will assume the current $USER
#      is the CNetID of the student. If that is not the case,
#      use this option to override.
#
#  --repo-name REPO  
#
#      The default behaviour of this script is to clone the
#      student's individual repository (the name of a student's 
#      repository is their CNetID). To specify an alternate
#      repository name (e.g., for repositories created for
#      pairs of students), use this option.
#
#  --local-repo-path LOCALPATH
#
#      By default, the local repository is created in
#      ~/cs121-aut-14-REPO. Use this option to override.
#
#  --gitlab-hostname HOST
#
#      Use to specify an alternate GitLab server
#
#  --gitlab-token TOKEN
#
#      Use to specify a GitLab token. If not specified, the script
#      will ask for your CNetID password to log into GitLab.
#
#  --skip-ssl-verify
#
#      The CS department's certificate is not universally trusted.
#      Use this option to skip SSL certificate verification when
#      connecting to GitLab. Note: this does not disable encryption,
#      it just tells the script to trust the CS certificate.
#
#  --skip-push
#
#      Skip the final push to the repository. This means that all the
#      work done by the script will not affect any remote repositories,
#      which can be useful for testing purposes.
#
#  --verbose
#
#      Produce verbose output
#      
#
# TODO
#
# - Do the equivalent of these commands:
#
#     git config --global user.name "..."
#     git config --global user.email "CNETID@uchicago.edu"
#
# - Currently creates a passwordless SSH key. Is this prudent?
#
# - When git connects to the server for the first time, it will not trust the host:
#
#     The authenticity of host 'git-dev.cs.uchicago.edu (128.135.164.46)' can't be established.
#     ECDSA key fingerprint is de:f1:32:f8:71:10:6e:d1:70:69:fe:1e:4a:07:ee:ac.
#
#   Ideally the script should make this message disappear somehow. We can include it in the
#   instructions to the students, but better to keep stuff like this to a minimum to avoid
#   potential confusion.
#
# - If a git repository already exists in the student's home directory,
#   the script doesn't check whether it is a correct CS121 repository.
#
# - Write more meaningful log messages
#

from argparse import ArgumentParser
from pprint import pprint as pp
import getpass
import json
import os
import os.path
import stat
import subprocess

try:
    import requests
    import git
except ImportError, ie:
    print "Your system is missing a required software library to run this script."
    print "Try running the following:"
    print 
    print "    pip install --user requests GitPython"
    print 
    exit(1)


# COURSE-SPECIFIC DEFAULTS
# Update these for each new edition of CS121
COURSE_ID = "cs121-aut-14"
GITLAB_GROUP = COURSE_ID
UPSTREAM_REPO = COURSE_ID
DEFAULT_CNETID = getpass.getuser()


# GENERAL DEFAULTS
# These should not change from year to year
def get_default_repo_path(reponame):
    return os.path.expanduser("~/%s-%s" % (COURSE_ID, reponame))
GITLAB_SERVER = "git-dev.cs.uchicago.edu"
SSH_DIR = os.path.expanduser("~/.ssh")
SSH_PRV_KEY = SSH_DIR + "/id_rsa"
SSH_PUB_KEY = SSH_DIR + "/id_rsa.pub"
BASH_RC = os.path.expanduser("~/.bashrc")
VERBOSE = False


def log(msg):
    if VERBOSE:
        print msg


def print_http_response(response):
    print "HTTP Status Code: %i" % response.status_code
    print
    print "HTTP Response"
    print "-------------"
    pp(response.headers.items())
    print
    pp(response.text)


def get_gitlab_token(username, gitlab_hostname, ssl_verify):
    log("Fetching Gitlab token")
    
    password = getpass.getpass("Please enter the password for CNetID '%s': " % username)

    data = {"login": username, "password": password}

    try:
        response = requests.post("https://" + gitlab_hostname + "/api/v3/session", data=data, 
                                    verify=ssl_verify,
                                    headers={"connection": "close"})
    except requests.exceptions.SSLError, ssle:
        print "Your computer is not set up to trust the CS department's SSL certificate."
        print "Try running the setup script with the --skip-ssl-verify option."
        exit(1)

    if response.status_code == 201:
        gitlab_token = json.loads(response.content.decode("utf-8"))['private_token']
        return gitlab_token
    elif response.status_code == 401:
        print "Wrong username/password."
        exit(1)
    else:
        print "Encountered an unexpected error when fetching your Gitlab access token."
        print
        print_http_response(response)
        exit(1)
        
    
def generate_ssh_keys(username):
    assert not os.path.exists(SSH_PRV_KEY) and not os.path.exists(SSH_PUB_KEY)

    label = username + "@uchicago.edu"

    try:
        from Crypto import version_info
        from Crypto.PublicKey import RSA
    except ImportError, ie:
        print "Your computer does not have the 'pycrypto' library necessary to"
        print "run this script. Try generating your SSH keys manually by running this:"
        print
        print "    ssh-keygen -t rsa -C \"%s\" -f ~/.ssh/id_rsa" % label
        print
        exit(1)

    if version_info[0] < 2 or (version_info[0] == 2 and version_info[1] < 6):
        print "Your computer has an old version of the 'pycrypto' library necessary to"
        print "run this script (version 2.6 or higher is required). Try generating your"
        print "SSH keys manually by running this:"
        print
        print "    ssh-keygen -t rsa -C \"%s\" -f ~/.ssh/id_rsa" % label
        print
        exit(1)

    new_key = RSA.generate(2048)
    public_key = new_key.publickey().exportKey("OpenSSH")
    private_key = new_key.exportKey("PEM")

    if not os.path.exists(SSH_DIR):
        try:
            os.makedirs(SSH_DIR)
        except os.error, ose:
            print "Could not create your SSH directory (%s)" % SSH_DIR
            print "Reason: %s" % ose.message
            exit(1)
    elif not os.path.isdir(SSH_DIR):
            print "ERROR: %s is not a directory" % SSH_DIR
            exit(1)

    try:
        f = open(SSH_PRV_KEY, "w")
        f.write(private_key)
        f.close()
        os.chmod(SSH_PRV_KEY, 0 | stat.S_IRUSR)

        f = open(SSH_PUB_KEY, "w")
        f.write("%s %s" % (public_key, label))
        f.close()
    except IOError, ioe:
        print "Error saving your SSH keys: " + ioe.message
        exit(1)


def add_ssh_key_to_gitlab(ssh_pubkey, gitlab_token, gitlab_hostname, ssl_verify):
    
    actual_key = ssh_pubkey.split()[1]

    headers = {"PRIVATE-TOKEN": gitlab_token}

    try:
        response = requests.get("https://" + gitlab_hostname + "/api/v3/user/keys",
                                    verify=ssl_verify,
                                    headers=headers)
    except requests.exceptions.SSLError, ssle:
        print "Your computer is not set up to trust the CS department's SSL certificate."
        print "Try running the setup script with the --skip-ssl-verify option."
        exit(1)

    if response.status_code == 200:
        keys = json.loads(response.content.decode("utf-8"))
        titles = set()
        for key in keys:
            titles.add(key["title"])
            if actual_key == key["key"].split()[1]:
                log("User's SSH key is already in GitLab. Not adding it again.")
                return

    elif response.status_code == 401:
        print "Invalid GitLab access token."
        exit(1)
    else:
        print "Encountered an unexpected error when fetching your SSH keys from GitLab."
        print
        print_http_response(response)
        exit(1)

    key_title_prefix = "Added by CS121 Setup Script"
    key_index = 1

    key_title = key_title_prefix
    while key_title in titles:
        key_index += 1
        key_title = "%s (%i)" % (key_title_prefix, key_index)

    data = {"title": key_title, "key": ssh_pubkey}

    try:
        response = requests.post("https://" + gitlab_hostname + "/api/v3/user/keys", data=data,
                                    verify=ssl_verify,
                                    headers=headers)
    except requests.exceptions.SSLError, ssle:
        print "Your computer is not set up to trust the CS department's SSL certificate."
        print "Try running the setup script with the --skip-ssl-verify option."
        exit(1)

    if response.status_code == 201:
        log("SSH key successfully added to GitLab.")
        return
    elif response.status_code == 401:
        print "Invalid GitLab access token."
        exit(1)
    else:
        print "Encountered an unexpected error when adding your SSH key to GitLab."
        print
        print_http_response(response)
        exit(1)


def get_local_repo_path(repo_name, local_repo_path):
    if local_repo_path is not None:
        if not os.path.exists(local_repo_path):
            print "ERROR: %s does not exist" % local_repo_path
            exit(1)
        elif not os.path.isdir(local_repo_path):
            print "ERROR: %s is not a directory" % local_repo_path
            exit(1)
        repo_path = local_repo_path
    else:
        repo_path = get_default_repo_path(repo_name)

    if os.path.exists(repo_path):
        try:
            repo = git.Repo(repo_path)
            # TODO: Check whether repository in this path is correctly configured
            print "A valid CS121 repository already exists in %s" % repo_path
            exit(0)
        except git.exc.InvalidGitRepositoryError, igre:
            print "ERROR: Directory %s already exists" % repo_path
            print "       but it is not a Git repository"
            exit(1)
    else:
        try:
            os.makedirs(repo_path)
        except os.error, ose:
            print "Could not create directory %s" % repo_path
            print "Reason: %s" % ose.message
            exit(1)

    return repo_path

def print_git_error(gce):
    print    
    print "Git command: " + " ".join(gce.command)
    print
    print "Git error message"
    print "-----------------"
    print gce.stderr

def create_local_repo(repo_path, repo_url, upstream_repo_url, skip_push):
    try:
        repo = git.Repo.clone_from(repo_url, repo_path)
    except git.exc.GitCommandError, gce:
        print "ERROR: Could not clone from remote repository %s into %s" % (repo_url, repo_path)
        print_git_error(gce)
        exit(1)

    origin = repo.remotes[0]

    try:
        upstream = repo.create_remote("upstream", upstream_repo_url)
    except git.exc.GitCommandError, gce:
        print "ERROR: Could not add upstream repository %s" % (upstream_repo_url)
        print_git_error(gce)
        exit(1)

    try:
        upstream.pull("master")
    except AssertionError, ae:
        # We ignore this because the stable version of GitPython will throw AssertionErrors
        # at the drop of a hat starting in Git 1.8. This is fixed in their dev branch
        # but hasn't made it into a stable release yet.
        log("Warning: AssertionError thrown when pulling from upstream.")
        log("         This can usually be ignored if you're using Git 1.8 or higher.")
        log("")
        log(ae.message)
    except git.exc.GitCommandError, gce:
        print "ERROR: Could not pull from upstream repository" 
        print_git_error(gce)
        exit(1)
  
    try:
        if not skip_push:
            origin.push("master", u=True)
    except git.exc.GitCommandError, gce:
        print "ERROR: Could not pull from upstream repository" 
        print_git_error(gce)
        exit(1)
    

def add_bash_rc(repo_path):
    BASH_RC_LINES = [
                     "export CS121_REPO=%s" % repo_path,
                     "export CLASSPATH=$CS121_REPO/lib:$CLASSPATH"
                    ]    

    if os.path.exists(BASH_RC):
        bashrcf = open(BASH_RC)
        lines = bashrcf.readlines()
        bashrcf.close()

        # If the lines we're looking for exist, they're likely at the
        # end of the file, so let's search from the end.
        lines.reverse()
        
        lines_to_add = []

        for line_to_add in BASH_RC_LINES:
            found = False
            for line in lines:
                if line_to_add in line:
                    found = True
                    break
            if not found:
                lines_to_add.append(line_to_add)            

        if len(lines_to_add) > 0:
            bashrcf = open(BASH_RC, "a")
            bashrcf.write("\n")
            for line_to_add in lines_to_add:
                bashrcf.write(line_to_add + "\n")
            bashrcf.close()
    else:
        log("~/.bashrc does not exist. Creating one.")
        bashrcf = open(BASH_RC, "w")
        for line_to_add in lines_to_add:
            bashrcf.write(line_to_add + "\n")
        bashrcf.close()
        

def compile_java_libs(repo_path):
    lib_path = repo_path + "/lib/"
    java_files = []
    for path, dirs, files in os.walk(lib_path):
        rel_path = path.replace(lib_path, "")
        for f in files:
            if f.endswith(".java"):
                java_files.append(rel_path + "/" + f)

    for java_file in java_files:
        rc = subprocess.call(["javac", java_file], cwd=lib_path)
        if rc != 0:
            log("Unable to compile %s" % java_file)
        
                

### MAIN PROGRAM ###

if __name__ == "__main__":
    # Setup argument parser
    parser = ArgumentParser(description="cs121-setup")
    parser.add_argument('--cnetid', type=str, default=DEFAULT_CNETID)
    parser.add_argument('--repo-name', type=str, default=None)
    parser.add_argument('--local-repo-path', type=str, default=None)
    parser.add_argument('--gitlab-hostname', type=str, default=GITLAB_SERVER)
    parser.add_argument('--gitlab-token', type=str, default=None)
    parser.add_argument('--skip-ssl-verify', action="store_true")
    parser.add_argument('--skip-push', action="store_true")
    parser.add_argument('--verbose', action="store_true")

    args = parser.parse_args()

    if args.repo_name is None:
        repo_name = args.cnetid
    else:
        repo_name = args.repo_name

    if args.verbose:
        VERBOSE = True

    # This will only work on the CS machines, where the InCommon CA certificate
    # is included in the system CA bundle.
    # For other systems, the user should just use the --skip-ssl-verify option.
    ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
    if args.skip_ssl_verify:
        verify = False
    elif os.path.exists(ca_bundle):
        verify = ca_bundle
    else:
        verify = True

    repo_url = "git@%s:%s/%s.git" % (args.gitlab_hostname, GITLAB_GROUP, repo_name)
    upstream_repo_url = "git@%s:%s/%s.git" % (args.gitlab_hostname, GITLAB_GROUP, UPSTREAM_REPO)

    if args.gitlab_token is None:
        gitlab_token = get_gitlab_token(args.cnetid, args.gitlab_hostname, verify)
    else:
        gitlab_token = args.gitlab_token

    if not os.path.exists(SSH_PRV_KEY) and not os.path.exists(SSH_PUB_KEY):
        generate_ssh_keys(args.cnetid)

    try:
        f = open(SSH_PUB_KEY)
        ssh_pubkey = f.read().strip()
        f.close()
    except IOError, ioe:
        print "Error reading your SSH public key: " + ioe.message
        exit(1)

    add_ssh_key_to_gitlab(ssh_pubkey, gitlab_token, args.gitlab_hostname, verify)

    repo_path = get_local_repo_path(repo_name, args.local_repo_path)

    create_local_repo(repo_path, repo_url, upstream_repo_url, args.skip_push)      

    print "Your CS121 git repository has been created in %s" % repo_path

    add_bash_rc(repo_path)

    compile_java_libs(repo_path)


