//go:build integration

package integration

import (
	"os/exec"
	"testing"
)

func TestPodmanAvailable(t *testing.T) {
	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not installed")
	}
}
