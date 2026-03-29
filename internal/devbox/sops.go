// Copyright 2024 Jetify Inc. and contributors. All rights reserved.
// Use of this source code is governed by the license in the LICENSE file.

package devbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-envparse"
	"go.jetify.com/devbox/internal/boxcli/usererr"
	"go.jetify.com/devbox/internal/nix"
	"gopkg.in/yaml.v3"
)

func findSopsBinary(projectDir string) (string, error) {
	if path, err := exec.LookPath("sops"); err == nil {
		return path, nil
	}
	// Check in the devbox nix profile bin directory.
	nixBinPath := filepath.Join(nix.ProfileBinPath(projectDir), "sops")
	if _, err := os.Stat(nixBinPath); err == nil {
		return nixBinPath, nil
	}
	return "", usererr.New(
		"sops binary not found. Install sops or add it to your devbox packages.",
	)
}

func (d *Devbox) sopsDecrypt(ctx context.Context) (map[string]string, error) {
	filePath := d.cfg.Root.SopsFilePath()
	if _, err := os.Stat(filePath); err != nil {
		return nil, usererr.New("SOPS file not found: %s", filePath)
	}

	sopsBin, err := findSopsBinary(d.projectDir)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".yaml", ".yml":
		return sopsDecryptYAML(ctx, sopsBin, filePath)
	case ".json":
		return sopsDecryptJSON(ctx, sopsBin, filePath)
	case ".env":
		return sopsDecryptDotenv(ctx, sopsBin, filePath)
	default:
		return nil, usererr.New(
			"unsupported SOPS file extension %q. Supported extensions: .yaml, .yml, .json, .env",
			ext,
		)
	}
}

func sopsDecryptYAML(ctx context.Context, sopsBin, filePath string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, sopsBin, "decrypt", filePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, usererr.New(
			"failed to decrypt SOPS file %s: %s",
			filePath, strings.TrimSpace(stderr.String()),
		)
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(stdout.Bytes(), &raw); err != nil {
		return nil, usererr.New(
			"failed to parse decrypted SOPS output as YAML: %v", err,
		)
	}

	return flattenToStringMap(raw, filePath)
}

func sopsDecryptJSON(ctx context.Context, sopsBin, filePath string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, sopsBin, "decrypt", filePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, usererr.New(
			"failed to decrypt SOPS file %s: %s",
			filePath, strings.TrimSpace(stderr.String()),
		)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &raw); err != nil {
		return nil, usererr.New(
			"failed to parse decrypted SOPS output as JSON: %v", err,
		)
	}

	return flattenToStringMap(raw, filePath)
}

// flattenToStringMap converts a map[string]interface{} with flat scalar values
// to a map[string]string. Nested objects or arrays are rejected.
func flattenToStringMap(raw map[string]interface{}, filePath string) (map[string]string, error) {
	result := make(map[string]string, len(raw))
	for key, v := range raw {
		switch val := v.(type) {
		case string:
			result[key] = val
		case int:
			result[key] = fmt.Sprintf("%d", val)
		case int64:
			result[key] = fmt.Sprintf("%d", val)
		case float64:
			if val == float64(int64(val)) {
				result[key] = fmt.Sprintf("%d", int64(val))
			} else {
				result[key] = fmt.Sprintf("%g", val)
			}
		case bool:
			result[key] = fmt.Sprintf("%t", val)
		case nil:
			result[key] = ""
		default:
			return nil, usererr.New(
				"SOPS file %s contains a nested value for key %q. "+
					"Only flat key-value pairs are supported for env_from.",
				filePath, key,
			)
		}
	}
	return result, nil
}

func sopsDecryptDotenv(ctx context.Context, sopsBin, filePath string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, sopsBin, "decrypt", filePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, usererr.New(
			"failed to decrypt SOPS file %s: %s",
			filePath, strings.TrimSpace(stderr.String()),
		)
	}

	envMap, err := envparse.Parse(&stdout)
	if err != nil {
		return nil, usererr.New(
			"failed to parse decrypted SOPS .env output: %v", err,
		)
	}
	return envMap, nil
}
