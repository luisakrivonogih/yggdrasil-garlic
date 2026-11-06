package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hjson/hjson-go/v4"

	"github.com/yggdrasil-network/yggdrasil-go/src/admin"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/garlic"
)

// marshalConfig renders cfg the way -normaliseconf does. The admin socket
// address is left out only when it is the platform default, so a custom
// AdminListen survives normalisation (package upgrades normalise the
// config on every install).
func marshalConfig(cfg *config.NodeConfig, asJSON bool) ([]byte, error) {
	out := *cfg
	if out.AdminListen == config.GetDefaults().DefaultAdminListen {
		out.AdminListen = ""
	}
	if out.PrivateKeyPath != "" {
		out.PrivateKey = nil
	}
	if asJSON {
		return json.MarshalIndent(&out, "", "  ")
	}
	return hjson.Marshal(&out)
}

// configPersister writes peers added or removed at runtime (addPeer,
// removePeer, addGarlicPeer, removeGarlicPeer) back to the config file the
// daemon was started with, so they survive restarts and reinstalls.
type configPersister struct {
	path       string
	privateKey ed25519.PrivateKey // the key the node is running with
	signingKey []byte             // the Garlic signing seed it is running with
	mu         sync.Mutex
}

// update re-reads the config file, applies edit and, if edit reports a
// change, atomically replaces the file (same format, mode and owner).
func (p *configPersister) update(edit func(cfg *config.NodeConfig) bool) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := os.ReadFile(p.path)
	if err != nil {
		return err
	}
	cfg := config.GenerateConfig()
	if _, err := cfg.ReadFrom(bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("the config file no longer parses: %w", err)
	}
	// A file without a private key would get a fresh random one here; keep
	// the identity the node is actually running with instead.
	if cfg.PrivateKeyPath == "" {
		cfg.PrivateKey = config.KeyBytes(p.privateKey)
	}
	// Likewise a file without a Garlic signing key would get a random one
	// (and new site domains); write the one the node is using.
	if cfg.GeneratedSigningKey && len(p.signingKey) > 0 {
		cfg.Garlic.SigningPrivateKey = config.KeyBytes(p.signingKey)
	}
	if !edit(cfg) {
		return nil
	}
	out, err := marshalConfig(cfg, json.Valid(bytes.TrimSpace(raw)))
	if err != nil {
		return err
	}
	out = append(out, '\n')
	info, err := os.Stat(p.path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p.path), "."+filepath.Base(p.path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	chownLike(tmp.Name(), info)
	return os.Rename(tmp.Name(), p.path)
}

// backup copies the config file next to itself (same mode and owner) and
// returns the copy's path.
func (p *configPersister) backup(suffix string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, err := os.ReadFile(p.path)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(p.path)
	if err != nil {
		return "", err
	}
	base := p.path + "." + suffix + "-" + time.Now().UTC().Format("20060102-150405")
	// Never overwrite an earlier backup (two changes within one second).
	for i := 1; ; i++ {
		path := base
		if i > 1 {
			path = fmt.Sprintf("%s-%d", base, i)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm())
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(raw); err != nil {
			f.Close()
			os.Remove(path)
			return "", err
		}
		if err := f.Close(); err != nil {
			os.Remove(path)
			return "", err
		}
		chownLike(path, info)
		return path, nil
	}
}

// setupDomainCommands adds newGarlicDomains: a new signing key, and so new
// domains for every site, only when explicitly asked for.
func setupDomainCommands(a *admin.AdminSocket, p *configPersister, services []config.GarlicServiceConfig) {
	_ = a.AddHandler("newGarlicDomains", "Give every site a new .yggg domain by replacing Garlic.SigningPrivateKey (the old domains stop working). Saved to the config, with a backup of the old one; takes effect after a restart. Needs confirm=yes", []string{"confirm"},
		func(in json.RawMessage) (interface{}, error) {
			var req struct {
				Confirm string `json:"confirm"`
			}
			if err := json.Unmarshal(in, &req); err != nil {
				return nil, err
			}
			if req.Confirm != "yes" {
				return nil, fmt.Errorf("this replaces all of this node's .yggg domains for good - run it as: newGarlicDomains confirm=yes")
			}
			seed := make([]byte, ed25519.SeedSize)
			if _, err := rand.Read(seed); err != nil {
				return nil, err
			}
			backup, err := p.backup("before-new-domains")
			if err != nil {
				return nil, fmt.Errorf("could not back up %s, nothing changed: %w", p.path, err)
			}
			if err := p.update(func(cfg *config.NodeConfig) bool {
				cfg.Garlic.SigningPrivateKey = seed
				// New domains use the blinded format (blind.go).
				cfg.Garlic.BlindedDomains = true
				return true
			}); err != nil {
				return nil, fmt.Errorf("could not save the new key to %s, nothing changed: %w", p.path, err)
			}
			key := ed25519.NewKeyFromSeed(seed)
			domains := map[string]string{"(default)": garlic.ComputeGIDv2(key.Public().(ed25519.PublicKey)).Domain()}
			for _, s := range services {
				serviceID, err := hex.DecodeString(s.ServiceID)
				if err != nil {
					continue
				}
				siteKey, err := garlic.SiteSigningKey(key, s.Name, serviceID)
				if err != nil {
					continue
				}
				label := s.Name
				if label == "" {
					label = "(default)"
				}
				if s.ServiceID != "" {
					label += " serviceId=" + s.ServiceID
				}
				domains[label] = garlic.ComputeGIDv2(siteKey.Public().(ed25519.PublicKey)).Domain()
			}
			return map[string]interface{}{
				"saved":      true,
				"config":     p.path,
				"backup":     backup,
				"newDomains": domains,
				"note":       "restart yggdrasil to switch to the new domains; to undo before that, copy the backup back over the config",
			}, nil
		})
}

// addPeerArgs is the request of the addPeer and removePeer handlers.
type addPeerArgs struct {
	URI       string `json:"uri"`
	Interface string `json:"interface,omitempty"`
}

func addUnique(list []string, item string, equal func(a, b string) bool) ([]string, bool) {
	if slices.ContainsFunc(list, func(s string) bool { return equal(s, item) }) {
		return list, false
	}
	return append(list, item), true
}

func removeAll(list []string, item string, equal func(a, b string) bool) ([]string, bool) {
	out := slices.DeleteFunc(slices.Clone(list), func(s string) bool { return equal(s, item) })
	return out, len(out) != len(list)
}

func sameURI(a, b string) bool { return strings.TrimSpace(a) == strings.TrimSpace(b) }

func sameKey(a, b string) bool { return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b)) }

// peerArgs parses the addPeer/removePeer request.
func peerArgs(in json.RawMessage) (addPeerArgs, bool) {
	var req addPeerArgs
	if json.Unmarshal(in, &req) != nil || req.URI == "" {
		return req, false
	}
	if _, err := url.Parse(req.URI); err != nil {
		return req, false
	}
	return req, true
}

// garlicKeyArg parses the key of the addGarlicPeer/removeGarlicPeer request.
func garlicKeyArg(in json.RawMessage) (string, bool) {
	var req struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(in, &req) != nil {
		return "", false
	}
	key := strings.ToLower(strings.TrimSpace(req.Key))
	if b, err := hex.DecodeString(key); err != nil || len(b) != ed25519.PublicKeySize {
		return "", false
	}
	return key, true
}

// configEdits maps each persisted admin command to the change it makes to
// the config; each returns whether the config changed.
var configEdits = map[string]func(in json.RawMessage, cfg *config.NodeConfig) bool{
	"addPeer": func(in json.RawMessage, cfg *config.NodeConfig) bool {
		req, ok := peerArgs(in)
		if !ok {
			return false
		}
		var changed bool
		if req.Interface == "" {
			cfg.Peers, changed = addUnique(cfg.Peers, req.URI, sameURI)
		} else {
			if cfg.InterfacePeers == nil {
				cfg.InterfacePeers = map[string][]string{}
			}
			cfg.InterfacePeers[req.Interface], changed = addUnique(cfg.InterfacePeers[req.Interface], req.URI, sameURI)
		}
		return changed
	},
	"removePeer": func(in json.RawMessage, cfg *config.NodeConfig) bool {
		req, ok := peerArgs(in)
		if !ok {
			return false
		}
		var changed bool
		if req.Interface == "" {
			cfg.Peers, changed = removeAll(cfg.Peers, req.URI, sameURI)
		} else if list, ok := cfg.InterfacePeers[req.Interface]; ok {
			cfg.InterfacePeers[req.Interface], changed = removeAll(list, req.URI, sameURI)
			if len(cfg.InterfacePeers[req.Interface]) == 0 {
				delete(cfg.InterfacePeers, req.Interface)
			}
		}
		return changed
	},
	"addGarlicPeer": func(in json.RawMessage, cfg *config.NodeConfig) bool {
		key, ok := garlicKeyArg(in)
		if !ok {
			return false
		}
		var changed bool
		cfg.Garlic.TrustedPeers, changed = addUnique(cfg.Garlic.TrustedPeers, key, sameKey)
		return changed
	},
	"removeGarlicPeer": func(in json.RawMessage, cfg *config.NodeConfig) bool {
		key, ok := garlicKeyArg(in)
		if !ok {
			return false
		}
		var a, b bool
		cfg.Garlic.TrustedPeers, a = removeAll(cfg.Garlic.TrustedPeers, key, sameKey)
		cfg.Garlic.BootstrapPeers, b = removeAll(cfg.Garlic.BootstrapPeers, key, sameKey)
		return a || b
	},
}

// setupConfigPersistence makes runtime peer changes permanent. A failure to
// save never fails the admin request itself: the peer is still added or
// removed for the running node, and the response says it was not saved.
// Commands of modules that are not running (Garlic disabled) are skipped.
func setupConfigPersistence(a *admin.AdminSocket, p *configPersister, logger core.Logger) {
	for name, edit := range configEdits {
		_ = a.WrapHandler(name, func(next core.AddHandlerFunc) core.AddHandlerFunc {
			return func(in json.RawMessage) (interface{}, error) {
				res, err := next(in)
				if err != nil {
					return res, err
				}
				saveErr := p.update(func(cfg *config.NodeConfig) bool { return edit(in, cfg) })
				status := map[string]interface{}{"saved": saveErr == nil, "config": p.path}
				if saveErr != nil {
					status["saveError"] = saveErr.Error()
					logger.Warnf("%s: applied, but not saved to %s (it lasts until restart): %v", name, p.path, saveErr)
				} else {
					logger.Infof("%s: saved to %s", name, p.path)
				}
				if m, ok := res.(map[string]interface{}); ok {
					for k, v := range status {
						m[k] = v
					}
					return m, nil
				}
				return status, nil
			}
		})
	}
}
