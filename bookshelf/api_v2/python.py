# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0

from fabric.api import sudo, settings, run, hide


def update_system_pip_to_latest_pip():
    """ install the latest pip """
    sudo("pip install --quiet --upgrade pip")


def update_to_latest_pip():
    """ install the latest pip """
    run("pip install --quiet --upgrade pip")
