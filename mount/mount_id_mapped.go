//go:build linux
// +build linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package mount

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// TODO: Support multiple mappings in future
func parseIDMapping(mapping string) ([]syscall.SysProcIDMap, error) {
	parts := strings.Split(mapping, ":")
	if len(parts) != 3 {
		return []syscall.SysProcIDMap{}, errors.New("user namespace mappings require the format `container-id:host-id:size`")
	}
	cID, err := strconv.ParseUint(parts[0], 0, 32)
	if err != nil {
		return []syscall.SysProcIDMap{}, errors.Wrapf(err, "invalid container id for user namespace remapping")
	}
	hID, err := strconv.ParseUint(parts[1], 0, 32)
	if err != nil {
		return []syscall.SysProcIDMap{}, errors.Wrapf(err, "invalid host id for user namespace remapping")
	}
	size, err := strconv.ParseUint(parts[2], 0, 32)
	if err != nil {
		return []syscall.SysProcIDMap{}, errors.Wrapf(err, "invalid size for user namespace remapping")
	}

	return []syscall.SysProcIDMap{
		{
			ContainerID: int(cID),
			HostID:      int(hID),
			Size:        int(size),
		},
	}, nil
}

func mountIDMapped(target string, pid int) (err error) {
	var (
		path       string
		attr       unix.MountAttr
		userNsFile *os.File
		targetDir  *os.File
	)

	path = fmt.Sprintf("/proc/%d/ns/user", pid)
	if userNsFile, err = os.Open(path); err != nil {
		return errors.Wrapf(err, "Unable to get user ns file descriptor for - %s", path)
	}

	attr.Attr_set = unix.MOUNT_ATTR_IDMAP
	attr.Attr_clr = 0
	attr.Propagation = 0
	attr.Userns_fd = uint64(userNsFile.Fd())

	defer userNsFile.Close()
	if targetDir, err = os.Open(target); err != nil {
		return errors.Wrapf(err, "Unable to get mount point target file descriptor - %s", target)
	}

	defer targetDir.Close()
	return unix.MountSetattr(int(targetDir.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_RECURSIVE, &attr)
}

// MapMount applies GID/UID shift according to gidmap/uidmap for target path
func MapMount(uidmap string, gidmap string, target string) (err error) {
	const (
		userNsHelperBinary = "/bin/true"
	)
	// TODO: Avoid dependency on /bin/true or do in a completely different way
	// Currently there is no way to pass idmapping directly to mount_setattr,
	// this is not very convenient from the container runtime point of view.
	// The id remapping procedure should be done in containerd, due to we have
	// old approach that use recursive chown.
	// Maybe it is necessary to think about moving of container rootfs ownership
	// adjustment to runc due to runc has information about container user namespace.
	// But personally I think that it would be better to add possibility to call
	// mount_setattr with explicit id mappings and leave container runtime components
	// responsibilities unchanged.
	cmd := exec.Command(userNsHelperBinary)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
	}

	if cmd.SysProcAttr.UidMappings, err = parseIDMapping(uidmap); err != nil {
		return err
	}
	if cmd.SysProcAttr.GidMappings, err = parseIDMapping(gidmap); err != nil {
		return err
	}

	if err = cmd.Start(); err != nil {
		return errors.Wrapf(err, "Failed to run the %s helper binary", userNsHelperBinary)
	}

	defer func() {
		if waitErr := cmd.Wait(); waitErr != nil {
			err = errors.Wrapf(waitErr, "Failed to run the %s helper binary", userNsHelperBinary)
		}
	}()
	if err = mountIDMapped(target, cmd.Process.Pid); err != nil {
		return errors.Wrapf(err, "Failed to create idmapped mount for target - %s", target)
	}

	return nil
}
