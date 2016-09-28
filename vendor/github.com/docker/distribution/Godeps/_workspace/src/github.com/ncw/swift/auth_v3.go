package swift

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
)

const (
	v3AuthMethodToken        = "token"
	v3AuthMethodPassword     = "password"
	v3InterfacePublic        = "public"
	v3InterfaceInternal      = "internal"
	v3InterfaceAdmin         = "admin"
	v3CatalogTypeObjectStore = "object-store"
)

// V3 Authentication request
// http://docs.openstack.org/developer/keystone/api_curl_examples.html
// http://developer.openstack.org/api-ref-identity-v3.html
type v3AuthRequest struct {
	Auth struct {
		Identity struct {
			Methods  []string        `json:"methods"`
			Password *v3AuthPassword `json:"password,omitempty"`
			Token    *v3AuthToken    `json:"token,omitempty"`
		} `json:"identity"`
		Scope *v3Scope `json:"scope,omitempty"`
	} `json:"auth"`
}

type v3Scope struct {
	Project *v3Project `json:"project,omitempty"`
	Domain  *v3Domain  `json:"domain,omitempty"`
	Trust   *v3Trust   `json:"OS-TRUST:trust,omitempty"`
}

type v3Domain struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type v3Project struct {
	Name   string    `json:"name,omitempty"`
	Id     string    `json:"id,omitempty"`
	Domain *v3Domain `json:"domain,omitempty"`
}

type v3Trust struct {
	Id string `json:"id"`
}

type v3User struct {
	Domain   *v3Domain `json:"domain,omitempty"`
	Id       string    `json:"id,omitempty"`
	Name     string    `json:"name,omitempty"`
	Password string    `json:"password,omitempty"`
}

type v3AuthToken struct {
	Id string `json:"id"`
}

type v3AuthPassword struct {
	User v3User `json:"user"`
}

// V3 Authentication response
type v3AuthResponse struct {
	Token struct {
		Expires_At, Issued_At string
		Methods               []string
		Roles                 []struct {
			Id, Name string
			Links    struct {
				Self string
			}
		}

		Project struct {
			Domain struct {
				Id, Name string
			}
			Id, Name string
		}

		Catalog []struct {
			Id, Namem, Type string
			Endpoints       []struct {
				Id, Region_Id, Url, Region, Interface string
			}
		}

		User struct {
			Id, Name string
			Domain   struct {
				Id, Name string
				Links    struct {
					Self string
				}
			}
		}

		Audit_Ids []string
	}
}

type v3Auth struct {
	Auth    *v3AuthResponse
	Headers http.Header
}

func (auth *v3Auth) Request(c *Connection) (*http.Request, error) {

	var v3i interface{}

	v3 := v3AuthRequest{}

	if c.UserName == "" {
		v3.Auth.Identity.Methods = []string{v3AuthMethodToken}
		v3.Auth.Identity.Token = &v3AuthToken{Id: c.ApiKey}
	} else {
		v3.Auth.Identity.Methods = []string{v3AuthMethodPassword}
		v3.Auth.Identity.Password = &v3AuthPassword{
			User: v3User{
				Name:     c.UserName,
				Password: c.ApiKey,
			},
		}

		var domain *v3Domain

		if c.Domain != "" {
			domain = &v3Domain{Name: c.Domain}
		} else if c.DomainId != "" {
			domain = &v3Domain{Id: c.DomainId}
		}
		v3.Auth.Identity.Password.User.Domain = domain
	}

	if c.TrustId != "" {
		v3.Auth.Scope = &v3Scope{Trust: &v3Trust{Id: c.TrustId}}
	} else if c.TenantId != "" || c.Tenant != "" {

		v3.Auth.Scope = &v3Scope{Project: &v3Project{}}

		if c.TenantId != "" {
			v3.Auth.Scope.Project.Id = c.TenantId
		} else if c.Tenant != "" {
			v3.Auth.Scope.Project.Name = c.Tenant
			var defaultDomain v3Domain
			if c.Domain != "" {
				defaultDomain = v3Domain{Name: "Default"}
			} else if c.DomainId != "" {
				defaultDomain = v3Domain{Id: "Default"}
			}
			v3.Auth.Scope.Project.Domain = &defaultDomain
		}
	}

	v3i = v3

	body, err := json.Marshal(v3i)

	if err != nil {
		return nil, err
	}

	url := c.AuthUrl
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	url += "auth/tokens"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)
	return req, nil
}

func (auth *v3Auth) Response(resp *http.Response) error {
	auth.Auth = &v3AuthResponse{}
	auth.Headers = resp.Header
	err := readJson(resp, auth.Auth)
	return err
}

func (auth *v3Auth) endpointUrl(Type string, Internal bool) string {
	for _, catalog := range auth.Auth.Token.Catalog {
		if catalog.Type == Type {
			for _, endpoint := range catalog.Endpoints {
				if Internal {
					if endpoint.Interface == v3InterfaceInternal {
						return endpoint.Url
					}
				} else {
					if endpoint.Interface == v3InterfacePublic {
						return endpoint.Url
					}
				}
			}
		}
	}
	return ""
}

func (auth *v3Auth) StorageUrl(Internal bool) string {
	return auth.endpointUrl(v3CatalogTypeObjectStore, Internal)
}

func (auth *v3Auth) Token() string {
	return auth.Headers.Get("X-Subject-Token")
}

func (auth *v3Auth) CdnUrl() string {
	return ""
}
