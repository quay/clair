package plugin

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	distreference "github.com/docker/distribution/reference"
	"github.com/docker/docker/api/server/httputils"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/docker/pkg/streamformatter"
	"github.com/docker/docker/reference"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

func parseHeaders(headers http.Header) (map[string][]string, *types.AuthConfig) {

	metaHeaders := map[string][]string{}
	for k, v := range headers {
		if strings.HasPrefix(k, "X-Meta-") {
			metaHeaders[k] = v
		}
	}

	// Get X-Registry-Auth
	authEncoded := headers.Get("X-Registry-Auth")
	authConfig := &types.AuthConfig{}
	if authEncoded != "" {
		authJSON := base64.NewDecoder(base64.URLEncoding, strings.NewReader(authEncoded))
		if err := json.NewDecoder(authJSON).Decode(authConfig); err != nil {
			authConfig = &types.AuthConfig{}
		}
	}

	return metaHeaders, authConfig
}

// parseRemoteRef parses the remote reference into a reference.Named
// returning the tag associated with the reference. In the case the
// given reference string includes both digest and tag, the returned
// reference will have the digest without the tag, but the tag will
// be returned.
func parseRemoteRef(remote string) (reference.Named, string, error) {
	// Parse remote reference, supporting remotes with name and tag
	// NOTE: Using distribution reference to handle references
	// containing both a name and digest
	remoteRef, err := distreference.ParseNamed(remote)
	if err != nil {
		return nil, "", err
	}

	var tag string
	if t, ok := remoteRef.(distreference.Tagged); ok {
		tag = t.Tag()
	}

	// Convert distribution reference to docker reference
	// TODO: remove when docker reference changes reconciled upstream
	ref, err := reference.WithName(remoteRef.Name())
	if err != nil {
		return nil, "", err
	}
	if d, ok := remoteRef.(distreference.Digested); ok {
		ref, err = reference.WithDigest(ref, d.Digest())
		if err != nil {
			return nil, "", err
		}
	} else if tag != "" {
		ref, err = reference.WithTag(ref, tag)
		if err != nil {
			return nil, "", err
		}
	} else {
		ref = reference.WithDefaultTag(ref)
	}

	return ref, tag, nil
}

func (pr *pluginRouter) getPrivileges(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	metaHeaders, authConfig := parseHeaders(r.Header)

	ref, _, err := parseRemoteRef(r.FormValue("remote"))
	if err != nil {
		return err
	}

	privileges, err := pr.backend.Privileges(ctx, ref, metaHeaders, authConfig)
	if err != nil {
		return err
	}
	return httputils.WriteJSON(w, http.StatusOK, privileges)
}

func (pr *pluginRouter) pullPlugin(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return errors.Wrap(err, "failed to parse form")
	}

	var privileges types.PluginPrivileges
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&privileges); err != nil {
		return errors.Wrap(err, "failed to parse privileges")
	}
	if dec.More() {
		return errors.New("invalid privileges")
	}

	metaHeaders, authConfig := parseHeaders(r.Header)

	ref, tag, err := parseRemoteRef(r.FormValue("remote"))
	if err != nil {
		return err
	}

	name := r.FormValue("name")
	if name == "" {
		if _, ok := ref.(reference.Canonical); ok {
			trimmed := reference.TrimNamed(ref)
			if tag != "" {
				nt, err := reference.WithTag(trimmed, tag)
				if err != nil {
					return err
				}
				name = nt.String()
			} else {
				name = reference.WithDefaultTag(trimmed).String()
			}
		} else {
			name = ref.String()
		}
	} else {
		localRef, err := reference.ParseNamed(name)
		if err != nil {
			return err
		}
		if _, ok := localRef.(reference.Canonical); ok {
			return errors.New("cannot use digest in plugin tag")
		}
		if distreference.IsNameOnly(localRef) {
			// TODO: log change in name to out stream
			name = reference.WithDefaultTag(localRef).String()
		}
	}
	w.Header().Set("Docker-Plugin-Name", name)

	w.Header().Set("Content-Type", "application/json")
	output := ioutils.NewWriteFlusher(w)

	if err := pr.backend.Pull(ctx, ref, name, metaHeaders, authConfig, privileges, output); err != nil {
		if !output.Flushed() {
			return err
		}
		output.Write(streamformatter.NewJSONStreamFormatter().FormatError(err))
	}

	return nil
}

func (pr *pluginRouter) createPlugin(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	options := &types.PluginCreateOptions{
		RepoName: r.FormValue("name")}

	if err := pr.backend.CreateFromContext(ctx, r.Body, options); err != nil {
		return err
	}
	//TODO: send progress bar
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (pr *pluginRouter) enablePlugin(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	name := vars["name"]
	timeout, err := strconv.Atoi(r.Form.Get("timeout"))
	if err != nil {
		return err
	}
	config := &types.PluginEnableConfig{Timeout: timeout}

	return pr.backend.Enable(name, config)
}

func (pr *pluginRouter) disablePlugin(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	name := vars["name"]
	config := &types.PluginDisableConfig{
		ForceDisable: httputils.BoolValue(r, "force"),
	}

	return pr.backend.Disable(name, config)
}

func (pr *pluginRouter) removePlugin(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return err
	}

	name := vars["name"]
	config := &types.PluginRmConfig{
		ForceRemove: httputils.BoolValue(r, "force"),
	}
	return pr.backend.Remove(name, config)
}

func (pr *pluginRouter) pushPlugin(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	if err := httputils.ParseForm(r); err != nil {
		return errors.Wrap(err, "failed to parse form")
	}

	metaHeaders, authConfig := parseHeaders(r.Header)

	w.Header().Set("Content-Type", "application/json")
	output := ioutils.NewWriteFlusher(w)

	if err := pr.backend.Push(ctx, vars["name"], metaHeaders, authConfig, output); err != nil {
		if !output.Flushed() {
			return err
		}
		output.Write(streamformatter.NewJSONStreamFormatter().FormatError(err))
	}
	return nil
}

func (pr *pluginRouter) setPlugin(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	var args []string
	if err := json.NewDecoder(r.Body).Decode(&args); err != nil {
		return err
	}
	if err := pr.backend.Set(vars["name"], args); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (pr *pluginRouter) listPlugins(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	l, err := pr.backend.List()
	if err != nil {
		return err
	}
	return httputils.WriteJSON(w, http.StatusOK, l)
}

func (pr *pluginRouter) inspectPlugin(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
	result, err := pr.backend.Inspect(vars["name"])
	if err != nil {
		return err
	}
	return httputils.WriteJSON(w, http.StatusOK, result)
}
