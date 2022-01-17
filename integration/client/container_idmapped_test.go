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

package client

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/oci"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func getVersion(release [65]int8) (major int, middle int, err error) {
	buf := make([]byte, 0, len(release))

	for _, v := range release {
		if v == 0x00 {
			break
		}

		if major == 0 && v == '.' {
			major, err = strconv.Atoi(string(buf))
			if err != nil {
				return 0, 0, err
			}
			buf = make([]byte, 0, len(release))
			continue
		}
		if major != 0 && v == '.' {
			middle, err = strconv.Atoi(string(buf))
			if err != nil {
				return 0, 0, err
			}
			return major, middle, nil
		}
		buf = append(buf, byte(v))
	}
	return 0, 0, fmt.Errorf("Can't parse uname")

}

func TestIDMapped(t *testing.T) {
	t.Log("Start IDMapped test")
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		t.Fatal(err)
	}

	major, middle, err := getVersion(uname.Release)

	if err != nil {
		t.Fatal(err)
	}

	// check whether idmapped mount supported
	// it's preliminary now to check, since overlayfs support for id mapped mounts still
	// not yet merged
	if !(major >= 5 && middle >= 17) {
		t.Log("Would be skipped")
		t.Skip("Skipped due to linux kernel version")
	}

	client, err := newClient(t, address)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var (
		ctx, cancel = testContext(t)
		id          = t.Name()
	)
	defer cancel()

	t.Log("Getting image")
	image, err := client.GetImage(ctx, testImage)
	if err != nil {
		t.Fatal(err)
	}

	hostID := uint32(33)
	contID := uint32(0)

	uidMap := specs.LinuxIDMapping{
		ContainerID: contID,
		HostID:      hostID,
		Size:        uint32(1000),
	}
	gidMap := specs.LinuxIDMapping{
		ContainerID: contID,
		HostID:      hostID,
		Size:        uint32(1000),
	}
	snapshotter := "overlayfs"

	// this one for idmap mount, for test purpose lets create w/o remapperLables
	container, err := client.NewContainer(ctx, id,
		containerd.WithImage(image),
		containerd.WithImageConfigLabels(image),
		containerd.WithSnapshotter(snapshotter),
		containerd.WithNewSnapshot(id, image, containerd.WithRemapperLabels(uidMap.ContainerID, uidMap.HostID, gidMap.ContainerID, gidMap.HostID, 1)),
		containerd.WithNewSpec(oci.WithImageConfig(image),
			oci.WithUserID(hostID),
			oci.WithUserNamespace([]specs.LinuxIDMapping{uidMap}, []specs.LinuxIDMapping{gidMap}),
			longCommand))

	if err != nil {
		t.Fatal(err)
	}
	defer container.Delete(ctx, containerd.WithSnapshotCleanup)

	t.Log("creating new task")

	task, err := container.NewTask(ctx, empty())
	if err != nil {
		t.Fatal(err)
	}
	defer task.Delete(ctx)

	finishedC, err := task.Wait(ctx)
	if err != nil {
		t.Error(err)
	}

	if err := task.Start(ctx); err != nil {
		t.Fatal(err)
	}

	spec, err := container.Spec(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// start an exec process without running the original container process info
	processSpec := spec.Process
	withExecArgs(processSpec, "ls", "-aln", "/bin/true")

	execID := t.Name() + "_exec"

	stdout := bytes.NewBuffer(nil)
	process, err := task.Exec(ctx, execID, processSpec, cio.NewCreator(withByteBuffers(stdout)))
	if err != nil {
		t.Fatal(err)
	}
	processStatusC, err := process.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if err := process.Start(ctx); err != nil {
		t.Fatal(err)
	}

	status := <-processStatusC
	code, _, err := status.Result()
	if err != nil {
		t.Fatal(err)
	}

	if code != 0 {
		t.Errorf("expected exec exit code 0 but received %d", code)
	}
	if _, err := process.Delete(ctx); err != nil {
		t.Fatal(err)
	}

	if err := task.Kill(ctx, syscall.SIGKILL); err != nil {
		t.Error(err)
	}

	status = <-finishedC

	code, _, err = status.Result()
	if err != nil {
		t.Fatal(err)
	}

	lsOutput := strings.Split(stdout.String(), " ")

	if len(lsOutput) < 3 {
		t.Errorf("expected owner of the file is %d", contID)
	}
	if len(lsOutput) >= 3 {
		parsedUID, err := strconv.ParseUint(lsOutput[3], 10, 64)
		// we're checking here the file owner if fs for contID
		if err != nil || parsedUID != uint64(contID) {
			t.Errorf("expected owner of the file is %d, %v", contID, err)
		}
	}
}
