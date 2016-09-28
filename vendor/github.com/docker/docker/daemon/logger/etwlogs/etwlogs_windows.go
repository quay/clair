// Package etwlogs provides a log driver for forwarding container logs
// as ETW events.(ETW stands for Event Tracing for Windows)
// A client can then create an ETW listener to listen for events that are sent
// by the ETW provider that we register, using the provider's GUID "a3693192-9ed6-46d2-a981-f8226c8363bd".
// Here is an example of how to do this using the logman utility:
// 1. logman start -ets DockerContainerLogs -p {a3693192-9ed6-46d2-a981-f8226c8363bd} 0 0 -o trace.etl
// 2. Run container(s) and generate log messages
// 3. logman stop -ets DockerContainerLogs
// 4. You can then convert the etl log file to XML using: tracerpt -y trace.etl
//
// Each container log message generates a ETW event that also contains:
// the container name and ID, the timestamp, and the stream type.
package etwlogs

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/daemon/logger"
)

type etwLogs struct {
	containerName string
	imageName     string
	containerID   string
	imageID       string
}

const (
	name             = "etwlogs"
	win32CallSuccess = 0
)

var win32Lib *syscall.DLL
var providerHandle syscall.Handle
var refCount int
var mu sync.Mutex

func init() {
	providerHandle = syscall.InvalidHandle
	if err := logger.RegisterLogDriver(name, New); err != nil {
		logrus.Fatal(err)
	}
}

// New creates a new etwLogs logger for the given container and registers the EWT provider.
func New(ctx logger.Context) (logger.Logger, error) {
	if err := registerETWProvider(); err != nil {
		return nil, err
	}
	logrus.Debugf("logging driver etwLogs configured for container: %s.", ctx.ContainerID)

	return &etwLogs{
		containerName: fixContainerName(ctx.ContainerName),
		imageName:     ctx.ContainerImageName,
		containerID:   ctx.ContainerID,
		imageID:       ctx.ContainerImageID,
	}, nil
}

// Log logs the message to the ETW stream.
func (etwLogger *etwLogs) Log(msg *logger.Message) error {
	if providerHandle == syscall.InvalidHandle {
		// This should never be hit, if it is, it indicates a programming error.
		errorMessage := "ETWLogs cannot log the message, because the event provider has not been registered."
		logrus.Error(errorMessage)
		return errors.New(errorMessage)
	}
	return callEventWriteString(createLogMessage(etwLogger, msg))
}

// Close closes the logger by unregistering the ETW provider.
func (etwLogger *etwLogs) Close() error {
	unregisterETWProvider()
	return nil
}

func (etwLogger *etwLogs) Name() string {
	return name
}

func createLogMessage(etwLogger *etwLogs, msg *logger.Message) string {
	return fmt.Sprintf("container_name: %s, image_name: %s, container_id: %s, image_id: %s, source: %s, log: %s",
		etwLogger.containerName,
		etwLogger.imageName,
		etwLogger.containerID,
		etwLogger.imageID,
		msg.Source,
		msg.Line)
}

// fixContainerName removes the initial '/' from the container name.
func fixContainerName(cntName string) string {
	if len(cntName) > 0 && cntName[0] == '/' {
		cntName = cntName[1:]
	}
	return cntName
}

func registerETWProvider() error {
	mu.Lock()
	defer mu.Unlock()
	if refCount == 0 {
		var err error
		if win32Lib, err = syscall.LoadDLL("Advapi32.dll"); err != nil {
			return err
		}
		if err = callEventRegister(); err != nil {
			win32Lib.Release()
			win32Lib = nil
			return err
		}
	}

	refCount++
	return nil
}

func unregisterETWProvider() {
	mu.Lock()
	defer mu.Unlock()
	if refCount == 1 {
		if callEventUnregister() {
			refCount--
			providerHandle = syscall.InvalidHandle
			win32Lib.Release()
			win32Lib = nil
		}
		// Not returning an error if EventUnregister fails, because etwLogs will continue to work
	} else {
		refCount--
	}
}

func callEventRegister() error {
	proc, err := win32Lib.FindProc("EventRegister")
	if err != nil {
		return err
	}
	// The provider's GUID is {a3693192-9ed6-46d2-a981-f8226c8363bd}
	guid := syscall.GUID{
		0xa3693192, 0x9ed6, 0x46d2,
		[8]byte{0xa9, 0x81, 0xf8, 0x22, 0x6c, 0x83, 0x63, 0xbd},
	}

	ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&guid)), 0, 0, uintptr(unsafe.Pointer(&providerHandle)))
	if ret != win32CallSuccess {
		errorMessage := fmt.Sprintf("Failed to register ETW provider. Error: %d", ret)
		logrus.Error(errorMessage)
		return errors.New(errorMessage)
	}
	return nil
}

func callEventWriteString(message string) error {
	proc, err := win32Lib.FindProc("EventWriteString")
	if err != nil {
		return err
	}
	ret, _, _ := proc.Call(uintptr(providerHandle), 0, 0, uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(message))))
	if ret != win32CallSuccess {
		errorMessage := fmt.Sprintf("ETWLogs provider failed to log message. Error: %d", ret)
		logrus.Error(errorMessage)
		return errors.New(errorMessage)
	}
	return nil
}

func callEventUnregister() bool {
	proc, err := win32Lib.FindProc("EventUnregister")
	if err != nil {
		return false
	}
	ret, _, _ := proc.Call(uintptr(providerHandle))
	if ret != win32CallSuccess {
		return false
	}
	return true
}
