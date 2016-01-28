# vim: ai ts=4 sts=4 et sw=4 ft=python fdm=indent et foldlevel=0
import uuid
import os
import re

from fabric.operations import (get as get_file,
                               put as upload_file)


def insert_line_in_file_after_regex(path, line, after_regex, use_sudo=False):
    """ inserts a line in the middle of a file """

    tmpfile = str(uuid.uuid4())
    get_file(path, tmpfile, use_sudo=use_sudo)
    with open(tmpfile) as f:
        original = f.read()

    has_it_changed = False
    if line not in original:
        has_it_changed = True
        outfile = str(uuid.uuid4())
        with open(outfile, 'w') as output:
            for l in original.split('\n'):
                output.write(l + '\n')
                if re.match(after_regex, l) is not None:
                    output.write(line + '\n')

        upload_file(local_path=outfile,
                    remote_path=path,
                    use_sudo=use_sudo)
        os.unlink(outfile)
    os.unlink(tmpfile)

    return has_it_changed
