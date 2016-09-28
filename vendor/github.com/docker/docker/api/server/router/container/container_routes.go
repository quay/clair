package container

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/server/httputils"
	"github.com/docker/docker/api/types/backend"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/docker/pkg/signal"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/docker/runconfig"
	"github.com/docker/engine-api/types"
	"github.com/docker/engine-api/types/container"
	"github.com/docker/engine-api/types/filters"
	"golang.org/x/net/context"
	"golang.org/x/net/websocket"
)

func (s *containerRouter) getContainersJSON(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}
	filter, err := filters.FromParam(r.Form.Get("filters"))
	if err != nil {
		return err
	}

	config := &types.ContainerListOptions{
		All:    httputils.BoolValue(r, "all"),
		Size:   httputils.BoolValue(r, "size"),
		Since:  r.Form.Get("since"),
		Before: r.Form.Get("before"),
		Filter: filter,
	}

	if tmpLimit := r.Form.Get("limit"); tmpLimit != "" {
		limit, err := strconv.Atoi(tmpLimit)
		if err != nil {
			return err
		}
		config.Limit = limit
	}

	containers, err := s.backend.Containers(config)
	if err != nil {
		return err
	}

	return httputils.WriteJSON(w, http.StatusOK, containers)
}

func (s *containerRouter) getContainersStats(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	stream := httputils.BoolValueOrDefault(r, "stream", true)
	if !stream {
		w.Header().Set("Content-Type", "application/json")
	}

	var closeNotifier <-chan bool
	if notifier, ok := w.(http.CloseNotifier); ok {
		closeNotifier = notifier.CloseNotify()
	}

	config := &backend.ContainerStatsConfig{
		Stream:    stream,
		OutStream: w,
		Stop:      closeNotifier,
		Version:   string(httputils.VersionFromContext(ctx)),
	}

	return s.backend.ContainerStats(vars["name"], config)
}

func (s *containerRouter) getContainersLogs(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	// Args are validated before the stream starts because when it starts we're
	// sending HTTP 200 by writing an empty chunk of data to tell the client that
	// daemon is going to stream. By sending this initial HTTP 200 we can't report
	// any error after the stream starts (i.e. container not found, wrong parameters)
	// with the appropriate status code.
	stdout, stderr := httputils.BoolValue(r, "stdout"), httputils.BoolValue(r, "stderr")
	if !(stdout || stderr) {
		return fmt.Errorf("Bad parameters: you must choose at least one stream")
	}

	var closeNotifier <-chan bool
	if notifier, ok := w.(http.CloseNotifier); ok {
		closeNotifier = notifier.CloseNotify()
	}

	containerName := vars["name"]
	logsConfig := &backend.ContainerLogsConfig{
		ContainerLogsOptions: types.ContainerLogsOptions{
			Follow:     httputils.BoolValue(r, "follow"),
			Timestamps: httputils.BoolValue(r, "timestamps"),
			Since:      r.Form.Get("since"),
			Tail:       r.Form.Get("tail"),
			ShowStdout: stdout,
			ShowStderr: stderr,
		},
		OutStream: w,
		Stop:      closeNotifier,
	}

	chStarted := make(chan struct{})
	if err := s.backend.ContainerLogs(containerName, logsConfig, chStarted); err != nil {
		select {
		case <-chStarted:
			// The client may be expecting all of the data we're sending to
			// be multiplexed, so send it through OutStream, which will
			// have been set up to handle that if needed.
			fmt.Fprintf(logsConfig.OutStream, "Error running logs job: %v\n", err)
		default:
			return err
		}
	}

	return nil
}

func (s *containerRouter) getContainersExport(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	return s.backend.ContainerExport(vars["name"], w)
}

func (s *containerRouter) postContainersStart(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	// If contentLength is -1, we can assumed chunked encoding
	// or more technically that the length is unknown
	// https://golang.org/src/pkg/net/http/request.go#L139
	// net/http otherwise seems to swallow any headers related to chunked encoding
	// including r.TransferEncoding
	// allow a nil body for backwards compatibility
	var hostConfig *container.HostConfig
	if r.Body != nil && (r.ContentLength > 0 || r.ContentLength == -1) {
		if err := httputils.CheckForJSON(r); err != nil {
			return err
		}

		c, err := runconfig.DecodeHostConfig(r.Body)
		if err != nil {
			return err
		}

		hostConfig = c
	}

	if err := s.backend.ContainerStart(vars["name"], hostConfig); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *containerRouter) postContainersStop(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	seconds, _ := strconv.Atoi(r.Form.Get("t"))

	if err := s.backend.ContainerStop(vars["name"], seconds); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)

	return nil
}

type errContainerIsRunning interface {
	ContainerIsRunning() bool
}

func (s *containerRouter) postContainersKill(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	var sig syscall.Signal
	name := vars["name"]

	// If we have a signal, look at it. Otherwise, do nothing
	if sigStr := r.Form.Get("signal"); sigStr != "" {
		var err error
		if sig, err = signal.ParseSignal(sigStr); err != nil {
			return err
		}
	}

	if err := s.backend.ContainerKill(name, uint64(sig)); err != nil {
		var isStopped bool
		if e, ok := err.(errContainerIsRunning); ok {
			isStopped = !e.ContainerIsRunning()
		}

		// Return error that's not caused because the container is stopped.
		// Return error if the container is not running and the api is >= 1.20
		// to keep backwards compatibility.
		version := httputils.VersionFromContext(ctx)
		if version.GreaterThanOrEqualTo("1.20") || !isStopped {
			return fmt.Errorf("Cannot kill container %s: %v", name, err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *containerRouter) postContainersRestart(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	timeout, _ := strconv.Atoi(r.Form.Get("t"))

	if err := s.backend.ContainerRestart(vars["name"], timeout); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)

	return nil
}

func (s *containerRouter) postContainersPause(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	if err := s.backend.ContainerPause(vars["name"]); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)

	return nil
}

func (s *containerRouter) postContainersUnpause(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	if err := s.backend.ContainerUnpause(vars["name"]); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)

	return nil
}

func (s *containerRouter) postContainersWait(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	status, err := s.backend.ContainerWait(vars["name"], -1*time.Second)
	if err != nil {
		return err
	}

	return httputils.WriteJSON(w, http.StatusOK, &types.ContainerWaitResponse{
		StatusCode: status,
	})
}

func (s *containerRouter) getContainersChanges(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	changes, err := s.backend.ContainerChanges(vars["name"])
	if err != nil {
		return err
	}

	return httputils.WriteJSON(w, http.StatusOK, changes)
}

func (s *containerRouter) getContainersTop(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	procList, err := s.backend.ContainerTop(vars["name"], r.Form.Get("ps_args"))
	if err != nil {
		return err
	}

	return httputils.WriteJSON(w, http.StatusOK, procList)
}

func (s *containerRouter) postContainerRename(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	name := vars["name"]
	newName := r.Form.Get("name")
	if err := s.backend.ContainerRename(name, newName); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (s *containerRouter) postContainerUpdate(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}
	if err := httputils.CheckForJSON(r); err != nil {
		return err
	}

	var updateConfig container.UpdateConfig

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&updateConfig); err != nil {
		return err
	}

	hostConfig := &container.HostConfig{
		Resources:     updateConfig.Resources,
		RestartPolicy: updateConfig.RestartPolicy,
	}

	name := vars["name"]
	warnings, err := s.backend.ContainerUpdate(name, hostConfig)
	if err != nil {
		return err
	}

	return httputils.WriteJSON(w, http.StatusOK, &types.ContainerUpdateResponse{
		Warnings: warnings,
	})
}

func (s *containerRouter) postContainersCreate(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}
	if err := httputils.CheckForJSON(r); err != nil {
		return err
	}

	name := r.Form.Get("name")

	config, hostConfig, networkingConfig, err := runconfig.DecodeContainerConfig(r.Body)
	if err != nil {
		return err
	}
	version := httputils.VersionFromContext(ctx)
	adjustCPUShares := version.LessThan("1.19")

	ccr, err := s.backend.ContainerCreate(types.ContainerCreateConfig{
		Name:             name,
		Config:           config,
		HostConfig:       hostConfig,
		NetworkingConfig: networkingConfig,
		AdjustCPUShares:  adjustCPUShares,
	})
	if err != nil {
		return err
	}

	return httputils.WriteJSON(w, http.StatusCreated, ccr)
}

func (s *containerRouter) deleteContainers(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	name := vars["name"]
	config := &types.ContainerRmConfig{
		ForceRemove:  httputils.BoolValue(r, "force"),
		RemoveVolume: httputils.BoolValue(r, "v"),
		RemoveLink:   httputils.BoolValue(r, "link"),
	}

	if err := s.backend.ContainerRm(name, config); err != nil {
		// Force a 404 for the empty string
		if strings.Contains(strings.ToLower(err.Error()), "prefix can't be empty") {
			return fmt.Errorf("no such container: \"\"")
		}
		return err
	}

	w.WriteHeader(http.StatusNoContent)

	return nil
}

func (s *containerRouter) postContainersResize(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	height, err := strconv.Atoi(r.Form.Get("h"))
	if err != nil {
		return err
	}
	width, err := strconv.Atoi(r.Form.Get("w"))
	if err != nil {
		return err
	}

	return s.backend.ContainerResize(vars["name"], height, width)
}

func (s *containerRouter) postContainersAttach(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	err := httputils.ParseForm(r)
	if err != nil {
		return err
	}
	containerName := vars["name"]

	_, upgrade := r.Header["Upgrade"]

	keys := []byte{}
	detachKeys := r.FormValue("detachKeys")
	if detachKeys != "" {
		keys, err = term.ToBytes(detachKeys)
		if err != nil {
			logrus.Warnf("Invalid escape keys provided (%s) using default : ctrl-p ctrl-q", detachKeys)
		}
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return fmt.Errorf("error attaching to container %s, hijack connection missing", containerName)
	}

	setupStreams := func() (io.ReadCloser, io.Writer, io.Writer, error) {
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return nil, nil, nil, err
		}

		// set raw mode
		conn.Write([]byte{})

		if upgrade {
			fmt.Fprintf(conn, "HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
		} else {
			fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
		}

		closer := func() error {
			httputils.CloseStreams(conn)
			return nil
		}
		return ioutils.NewReadCloserWrapper(conn, closer), conn, conn, nil
	}

	attachConfig := &backend.ContainerAttachConfig{
		GetStreams: setupStreams,
		UseStdin:   httputils.BoolValue(r, "stdin"),
		UseStdout:  httputils.BoolValue(r, "stdout"),
		UseStderr:  httputils.BoolValue(r, "stderr"),
		Logs:       httputils.BoolValue(r, "logs"),
		Stream:     httputils.BoolValue(r, "stream"),
		DetachKeys: keys,
		MuxStreams: true,
	}

	return s.backend.ContainerAttach(containerName, attachConfig)
}

func (s *containerRouter) wsContainersAttach(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}
	containerName := vars["name"]

	var keys []byte
	var err error
	detachKeys := r.FormValue("detachKeys")
	if detachKeys != "" {
		keys, err = term.ToBytes(detachKeys)
		if err != nil {
			logrus.Warnf("Invalid escape keys provided (%s) using default : ctrl-p ctrl-q", detachKeys)
		}
	}

	done := make(chan struct{})
	started := make(chan struct{})

	setupStreams := func() (io.ReadCloser, io.Writer, io.Writer, error) {
		wsChan := make(chan *websocket.Conn)
		h := func(conn *websocket.Conn) {
			wsChan <- conn
			<-done
		}

		srv := websocket.Server{Handler: h, Handshake: nil}
		go func() {
			close(started)
			srv.ServeHTTP(w, r)
		}()

		conn := <-wsChan
		return conn, conn, conn, nil
	}

	attachConfig := &backend.ContainerAttachConfig{
		GetStreams: setupStreams,
		Logs:       httputils.BoolValue(r, "logs"),
		Stream:     httputils.BoolValue(r, "stream"),
		DetachKeys: keys,
		UseStdin:   true,
		UseStdout:  true,
		UseStderr:  true,
		MuxStreams: false, // TODO: this should be true since it's a single stream for both stdout and stderr
	}

	err = s.backend.ContainerAttach(containerName, attachConfig)
	close(done)
	select {
	case <-started:
		logrus.Errorf("Error attaching websocket: %s", err)
		return nil
	default:
	}
	return err
}
