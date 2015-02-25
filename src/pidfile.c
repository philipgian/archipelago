/*
Copyright (C) 2010-2014 GRNET S.A.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pidfile.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

int pidfile_remove(char *path, int fd)
{
    close(fd);
    return (unlink(path));
}

int pidfile_write(int pid_fd)
{
    int ret;
    char buf[16];
    snprintf(buf, sizeof(buf), "%ld", syscall(SYS_gettid));
    buf[15] = 0;

    lseek(pid_fd, 0, SEEK_SET);
    ret = write(pid_fd, buf, strnlen(buf, 15));
    if (ret < 0) {
        return -errno;
    }

    return 0;
}

int pidfile_read(char *path, pid_t *pid)
{
    int fd, ret;
    char buf[16], *endptr;
    *pid = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    ret = read(fd, buf, 15);
    buf[15] = '\0';
    if (ret < 0) {
        ret = -errno;
        close(fd);
        return ret;
    } else {
        *pid = strtol(buf, &endptr, 10);
        if (endptr != &buf[ret]) {
            *pid = 0;
            return -EIO;
        }
    }

    return 0;
}

int pidfile_open(char *path, pid_t *old_pid)
{
    //nfs version > 3
    int fd = open(path, O_CREAT|O_EXCL|O_WRONLY,
                  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd < 0) {
        if (errno == EEXIST) {
            return pidfile_read(path, old_pid);
        }
    }

    return fd;
}
