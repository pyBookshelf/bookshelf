# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

from fabric.api import sudo, run
from fabric.context_managers import cd
from fabric.contrib.files import exists


def install_recent_git_from_source(version='2.4.6',
                                   prefix='/usr/local',
                                   log=False):
    # update git
    sudo("wget -c https://www.kernel.org/pub/software/scm/git/git-%s.tar.gz" %
         version)
    sudo("test -e git-%s || tar -zxf git-%s.tar.gz" % (version, version))
    with cd('git-%s' % version):
        sudo('test -e %s/bin/git || ./configure --prefix=%s' % (prefix, prefix))
        sudo('test -e %s/bin/git || make' % prefix)
        sudo('test -e %s/bin/git || make install' % prefix)


def git_clone(repo_url, repo_name):
    """ clones a git repository """
    if not exists(repo_name):
        run("git clone %s" % repo_url)
