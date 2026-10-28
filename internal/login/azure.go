package login

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

const (
	defaultAzureResource = "https://management.azure.com/"
	imdsBase             = "http://169.254.169.254/metadata"
)

// imdsClient talks to the link-local Azure Instance Metadata Service; it must
// never go through a proxy and should fail fast off Azure.
var imdsClient = &http.Client{
	Timeout:   2 * time.Second,
	Transport: &http.Transport{Proxy: nil},
}

// azureLogin logs in with the azure auth method. Unless a jwt param is set,
// the token comes from the managed identity (IMDS) when running on Azure, or
// otherwise from the Azure CLI (`az login`).
func azureLogin(ctx context.Context, client *api.Client, mount, role, resource string, data map[string]any) (*api.Secret, error) {
	if resource == "" {
		resource = defaultAzureResource
	}
	data["role"] = role
	if jwt, _ := data["jwt"].(string); jwt == "" {
		jwt, imdsErr := imdsToken(ctx, resource)
		if imdsErr == nil {
			addIMDSMetadata(ctx, data)
		} else {
			var cliErr error
			if jwt, cliErr = azCLIToken(ctx, resource); cliErr != nil {
				return nil, fmt.Errorf("get Azure token: managed identity: %v; Azure CLI: %v", imdsErr, cliErr)
			}
		}
		data["jwt"] = jwt
	}
	return client.Logical().WriteWithContext(ctx, "auth/"+mount+"/login", data)
}

func imdsGet(ctx context.Context, path string, query url.Values, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, imdsBase+path+"?"+query.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Metadata", "true")
	resp, err := imdsClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("IMDS %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func imdsToken(ctx context.Context, resource string) (string, error) {
	var out struct {
		AccessToken string `json:"access_token"`
	}
	q := url.Values{"api-version": {"2018-02-01"}, "resource": {resource}}
	if err := imdsGet(ctx, "/identity/oauth2/token", q, &out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

// addIMDSMetadata fills VM identity fields the azure auth method may bind
// roles to, without overriding configured params.
func addIMDSMetadata(ctx context.Context, data map[string]any) {
	var md struct {
		SubscriptionID    string `json:"subscriptionId"`
		ResourceGroupName string `json:"resourceGroupName"`
		Name              string `json:"name"`
		VMScaleSetName    string `json:"vmScaleSetName"`
	}
	if err := imdsGet(ctx, "/instance/compute", url.Values{"api-version": {"2021-02-01"}}, &md); err != nil {
		return
	}
	setDefault := func(k, v string) {
		if _, ok := data[k]; !ok && v != "" {
			data[k] = v
		}
	}
	setDefault("subscription_id", md.SubscriptionID)
	setDefault("resource_group_name", md.ResourceGroupName)
	if md.VMScaleSetName != "" {
		setDefault("vmss_name", md.VMScaleSetName)
	} else {
		setDefault("vm_name", md.Name)
	}
}

func azCLIToken(ctx context.Context, resource string) (string, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "az", "account", "get-access-token", "--resource", resource, "--query", "accessToken", "-o", "tsv")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}
