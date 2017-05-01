// +build selinux,linux

package label

import (
	"os"
	"strings"
	"testing"

	"github.com/opencontainers/runc/libcontainer/selinux"
)

func TestInit(t *testing.T) {
	if selinux.SelinuxEnabled() {
		var testNull []string
		plabel, mlabel, err := InitLabels(testNull)
		if err != nil {
			t.Log("InitLabels Failed")
			t.Fatal(err)
		}
		testDisabled := []string{"label=disable"}
		roMountLabel := GetROMountLabel()
		if roMountLabel == "" {
			t.Errorf("GetROMountLabel Failed")
		}
		plabel, mlabel, err = InitLabels(testDisabled)
		if err != nil {
			t.Log("InitLabels Disabled Failed")
			t.Fatal(err)
		}
		if plabel != "" {
			t.Log("InitLabels Disabled Failed")
			t.FailNow()
		}
		testUser := []string{"label=user:user_u", "label=role:user_r", "label=type:user_t", "label=level:s0:c1,c15"}
		plabel, mlabel, err = InitLabels(testUser)
		if err != nil {
			t.Log("InitLabels User Failed")
			t.Fatal(err)
		}
		if plabel != "user_u:user_r:user_t:s0:c1,c15" || mlabel != "user_u:object_r:svirt_sandbox_file_t:s0:c1,c15" {
			t.Log("InitLabels User Match Failed")
			t.Log(plabel, mlabel)
			t.Fatal(err)
		}

		testBadData := []string{"label=user", "label=role:user_r", "label=type:user_t", "label=level:s0:c1,c15"}
		if _, _, err = InitLabels(testBadData); err == nil {
			t.Log("InitLabels Bad Failed")
			t.Fatal(err)
		}
	}
}
func TestDuplicateLabel(t *testing.T) {
	secopt := DupSecOpt("system_u:system_r:svirt_lxc_net_t:s0:c1,c2")
	t.Log(secopt)
	for _, opt := range secopt {
		parts := strings.SplitN(opt, "=", 2)
		if len(parts) != 2 || parts[0] != "label" {
			t.Errorf("Invalid DupSecOpt return value")
			continue
		}
		con := strings.SplitN(parts[1], ":", 2)
		if con[0] == "user" {
			if con[1] != "system_u" {
				t.Errorf("DupSecOpt Failed user incorrect")
			}
			continue
		}
		if con[0] == "role" {
			if con[1] != "system_r" {
				t.Errorf("DupSecOpt Failed role incorrect")
			}
			continue
		}
		if con[0] == "type" {
			if con[1] != "svirt_lxc_net_t" {
				t.Errorf("DupSecOpt Failed type incorrect")
			}
			continue
		}
		if con[0] == "level" {
			if con[1] != "s0:c1,c2" {
				t.Errorf("DupSecOpt Failed level incorrect")
			}
			continue
		}
		t.Errorf("DupSecOpt Failed invalid field %q", con[0])
	}
	secopt = DisableSecOpt()
	if secopt[0] != "label=disable" {
		t.Errorf("DisableSecOpt Failed level incorrect")
	}
}
func TestRelabel(t *testing.T) {
	testdir := "/tmp/test"
	if err := os.Mkdir(testdir, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(testdir)
	label := "system_u:object_r:svirt_sandbox_file_t:s0:c1,c2"
	if err := Relabel(testdir, "", true); err != nil {
		t.Fatalf("Relabel with no label failed: %v", err)
	}
	if err := Relabel(testdir, label, true); err != nil {
		t.Fatalf("Relabel shared failed: %v", err)
	}
	if err := Relabel(testdir, label, false); err != nil {
		t.Fatalf("Relabel unshared failed: %v", err)
	}
	if err := Relabel("/etc", label, false); err == nil {
		t.Fatalf("Relabel /etc succeeded")
	}
	if err := Relabel("/", label, false); err == nil {
		t.Fatalf("Relabel / succeeded")
	}
	if err := Relabel("/usr", label, false); err == nil {
		t.Fatalf("Relabel /usr succeeded")
	}
}

func TestValidate(t *testing.T) {
	if err := Validate("zZ"); err != ErrIncompatibleLabel {
		t.Fatalf("Expected incompatible error, got %v", err)
	}
	if err := Validate("Z"); err != nil {
		t.Fatal(err)
	}
	if err := Validate("z"); err != nil {
		t.Fatal(err)
	}
	if err := Validate(""); err != nil {
		t.Fatal(err)
	}
}

func TestIsShared(t *testing.T) {
	if shared := IsShared("Z"); shared {
		t.Fatalf("Expected label `Z` to not be shared, got %v", shared)
	}
	if shared := IsShared("z"); !shared {
		t.Fatalf("Expected label `z` to be shared, got %v", shared)
	}
	if shared := IsShared("Zz"); !shared {
		t.Fatalf("Expected label `Zz` to be shared, got %v", shared)
	}

}
