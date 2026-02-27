package gitops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
)

// StateWriter is called to persist state and errors during apply.
type StateWriter interface {
	SaveState(ctx context.Context, state *State) error
}

// Apply runs vault-gitops apply: resolve templates, POST create/update, DELETE removed, update state.
func Apply(ctx context.Context, resources []Resource, client *api.Client, state *State, writer StateWriter) error {
	if client == nil {
		return fmt.Errorf("vault client is required")
	}
	if state == nil || state.Resources == nil {
		state = &State{Resources: make(map[string]StateResource)}
	}

	order, err := topologicalOrder(resources)
	if err != nil {
		return err
	}

	currentKeys := make(map[string]bool)
	for _, r := range resources {
		currentKeys[r.Key()] = true
	}

	// Create or update
	for _, idx := range order {
		r := &resources[idx]
		key := r.Key()
		resolvedData, err := ResolveTemplates(r.Data, state)
		if err != nil {
			msg := fmt.Sprintf("resource %s%s: %v", r.Namespace, r.Path, err)
			if !r.IgnoreFailures {
				return fmt.Errorf("%s", msg)
			}
			continue
		}
		rev := revisionForDigest(r.Revision)
		if prev, inState := state.Resources[key]; inState && prev.DataDigest == dataDigestWithRevision(resolvedData, rev) {
			continue
		}
		// Maybe state exists under old key (hash) after user added name to resource.
		if _, inState := state.Resources[key]; !inState {
			if oldKey, prev, found := state.FindByNsPath(r.NamespaceOrDefault(), r.Path); found && prev.DataDigest == dataDigestWithRevision(resolvedData, rev) {
				state.Resources[key] = StateResource{
					DataDigest:     prev.DataDigest,
					Dependencies:   prev.Dependencies,
					IgnoreFailures: prev.IgnoreFailures,
					ResponseData:   prev.ResponseData,
					Namespace:      r.NamespaceOrDefault(),
					Path:           r.Path,
				}
				delete(state.Resources, oldKey)
				if writer != nil {
					if err := writer.SaveState(ctx, state); err != nil {
						msg := fmt.Sprintf("resource %s%s: save state (migrate key): %v", r.Namespace, r.Path, err)
						if !r.IgnoreFailures {
							return fmt.Errorf("%s", msg)
						}
						continue
					}
				}
				continue
			}
		}
		path := strings.TrimPrefix(r.Path, "/")
		reqClient := client
		if r.Namespace != "" {
			reqClient = client.WithNamespace(strings.TrimSuffix(r.Namespace, "/"))
		}
		method := normalizeMethod(r.Method)

		var responseData interface{}
		var applyErr error
		switch method {
		case "GET":
			secret, err := reqClient.Logical().ReadWithContext(ctx, path)
			if err != nil {
				applyErr = err
				break
			}
			if secret != nil && secret.Data != nil {
				responseData = normalizeValue(secret.Data)
			}
		default:
			dataMap, err := dataToDataMap(resolvedData)
			if err != nil {
				msg := fmt.Sprintf("resource %s%s: json encode: %v", r.Namespace, r.Path, err)
				if !r.IgnoreFailures {
					return fmt.Errorf("%s", msg)
				}
				continue
			}
			secret, err := reqClient.Logical().WriteWithContext(ctx, path, dataMap)
			if err != nil {
				applyErr = err
				break
			}
			if secret != nil && secret.Data != nil {
				responseData = normalizeValue(secret.Data)
			}
		}

		if applyErr != nil {
			msg := formatVaultErr(r.Namespace, r.Path, applyErr)
			if !r.IgnoreFailures {
				return fmt.Errorf("%s", msg)
			}
			continue
		}
		state.Resources[key] = StateResource{
			DataDigest:     dataDigestWithRevision(resolvedData, rev),
			Dependencies:   r.Dependencies,
			IgnoreFailures: r.IgnoreFailures,
			ResponseData:   responseData,
			Namespace:      r.NamespaceOrDefault(),
			Path:           r.Path,
		}
		if writer != nil {
			if err := writer.SaveState(ctx, state); err != nil {
				msg := fmt.Sprintf("resource %s%s: save state: %v", r.Namespace, r.Path, err)
				if !r.IgnoreFailures {
					return fmt.Errorf("%s", msg)
				}
				continue
			}
		}
	}

	// Delete
	var toDelete []string
	for key := range state.Resources {
		if !currentKeys[key] {
			toDelete = append(toDelete, key)
		}
	}
	deleteOrder := deleteOrderFromState(state, toDelete)
	for _, key := range deleteOrder {
		res := state.Resources[key]
		ns, path := res.Namespace, strings.TrimPrefix(res.Path, "/")
		ignoreFailures := res.IgnoreFailures
		reqClient := client
		if ns != "" {
			reqClient = client.WithNamespace(strings.TrimSuffix(ns, "/"))
		}
		_, err := reqClient.Logical().DeleteWithContext(ctx, path)
		if err == nil {
			delete(state.Resources, key)
			if writer != nil {
				if err := writer.SaveState(ctx, state); err != nil {
					msg := fmt.Sprintf("delete %s%s: save state: %v", ns, res.Path, err)
					if !ignoreFailures {
						return fmt.Errorf("%s", msg)
					}
					continue
				}
			}
			continue
		}
		respErr, ok := err.(*api.ResponseError)
		if ok && (respErr.StatusCode == 404 || respErr.StatusCode == 405) {
			delete(state.Resources, key)
			if writer != nil {
				if err := writer.SaveState(ctx, state); err != nil {
					msg := fmt.Sprintf("delete %s%s: save state after %d: %v", ns, res.Path, respErr.StatusCode, err)
					if !ignoreFailures {
						return fmt.Errorf("%s", msg)
					}
					continue
				}
			}
			continue
		}
		msg := formatVaultErr(ns, res.Path, err)
		if !ignoreFailures {
			return fmt.Errorf("%s", msg)
		}
	}

	return nil
}

func formatVaultErr(namespace, path string, err error) string {
	if respErr, ok := err.(*api.ResponseError); ok {
		return fmt.Sprintf("resource %s%s: %d %s", namespace, path, respErr.StatusCode, strings.TrimSpace(respErr.Error()))
	}
	return fmt.Sprintf("resource %s%s: %v", namespace, path, err)
}

// dataToDataMap converts resource data to map[string]interface{} for Vault API.
func dataToDataMap(data interface{}) (map[string]interface{}, error) {
	norm := normalizeValue(data)
	m, ok := norm.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("data must be an object (map)")
	}
	return m, nil
}

func revisionForDigest(revision int) uint64 {
	if revision < 0 {
		return 0
	}
	return uint64(revision)
}

func normalizeMethod(m string) string {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "GET":
		return "GET"
	default:
		return "POST"
	}
}

func dataDigestWithRevision(data interface{}, revision uint64) string {
	norm := normalizeValue(data)
	input := map[string]interface{}{"data": norm, "revision": revision}
	b, err := json.Marshal(input)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func deleteOrderFromState(state *State, keys []string) []string {
	keySet := make(map[string]bool)
	for _, k := range keys {
		keySet[k] = true
	}
	inDegree := make(map[string]int)
	adj := make(map[string][]string)
	for _, k := range keys {
		inDegree[k] = 0
		adj[k] = nil
	}
	for _, k := range keys {
		res := state.Resources[k]
		for _, depName := range res.Dependencies {
			if keySet[depName] {
				adj[depName] = append(adj[depName], k)
				inDegree[k]++
			}
		}
	}
	var queue []string
	for k := range inDegree {
		if inDegree[k] == 0 {
			queue = append(queue, k)
		}
	}
	var order []string
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		order = append(order, u)
		for _, v := range adj[u] {
			inDegree[v]--
			if inDegree[v] == 0 {
				queue = append(queue, v)
			}
		}
	}
	return order
}

func topologicalOrder(resources []Resource) ([]int, error) {
	byName := make(map[string]int)
	for i := range resources {
		byName[resources[i].EffectiveName()] = i
	}
	inDegree := make([]int, len(resources))
	adj := make([][]int, len(resources))
	for i := range resources {
		r := &resources[i]
		for _, depName := range r.Dependencies {
			depIdx, ok := byName[depName]
			if !ok {
				continue
			}
			adj[depIdx] = append(adj[depIdx], i)
			inDegree[i]++
		}
	}
	var queue []int
	for i := range inDegree {
		if inDegree[i] == 0 {
			queue = append(queue, i)
		}
	}
	var order []int
	for len(queue) > 0 {
		u := queue[0]
		queue = queue[1:]
		order = append(order, u)
		for _, v := range adj[u] {
			inDegree[v]--
			if inDegree[v] == 0 {
				queue = append(queue, v)
			}
		}
	}
	if len(order) != len(resources) {
		return nil, fmt.Errorf("cycle in dependencies")
	}
	return order, nil
}
